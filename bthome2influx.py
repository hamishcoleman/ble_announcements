#!/usr/bin/env python3
"""
Listen for BTHome structured BLE advertisements and send them to influx
"""
#
# :dotsctl:
#   dpkg:
#     - python3-bluez
#     - python3-influxdb
# ...
#

import argparse
import bluetooth._bluetooth as bluez
import ctypes
import influxdb
import struct
import sys
import time


EVT_LE_META_EVENT = 0x3e


class MACAddr:
    def __init__(self, buf):
        self.addr = buf

    def __str__(self):
        a = []
        for b in self.addr:
            a.append(f"{b:02x}")
        return ":".join(a)


class BTHome:
    @classmethod
    def from_buf(cls, buf):
        return cls(buf)

    def __init__(self, buf):
        self.info = buf[0]
        self.measurements = {}
        self._parse_measurements(buf[1:])

    def __str__(self):
        s = ["BTHome"]
        for k, v in self.measurements.items():
            s += [k, str(v)]

        return " ".join(s)

    def _parse_measurements(self, buf):
        pos = 0
        while pos < len(buf):
            obj_id = buf[pos]
            pos += 1

            # TODO:
            # - this could return objects
            # - the size could be calculated from the struct type string

            data_types = {
                0: {
                    "name": "sequence",
                    "size": 1,
                    "type": "B",
                },
                1: {
                    "name": "battery",
                    "size": 1,
                    "type": "B",
                    "unit": "%",
                },
                2: {
                    "name": "temperature",
                    "size": 2,
                    "type": "<h",
                    "factor": 0.01,
                    "unit": "°C",
                },
                3: {
                    "name": "humidity",
                    "size": 2,
                    "type": "<H",
                    "factor": 0.01,
                    "unit": "%",
                },
                0x0c: {
                    "name": "voltage",
                    "size": 2,
                    "type": "<H",
                    "factor": 0.001,
                    "unit": "V",
                },
                0x10: {
                    "name": "power",
                    "size": 1,
                    "type": "?",
                },
            }

            if obj_id not in data_types:
                # TODO: be more resilient in the face of unknown
                raise ValueError(f"Unknown BTHome measurement {obj_id}")

            type = data_types[obj_id]
            size = type["size"]
            rawdata = buf[pos:pos + size]
            pos += size

            raw, = struct.unpack(type["type"], rawdata)

            if "factor" in type:
                value = raw * type["factor"]
            else:
                value = raw

            self.measurements[type["name"]] = value


class BLE_Tag_Base:
    def __init__(self, buf):
        self.id = buf[0]
        self.rawdata = buf[1:]
        self.short = str(self.id)
        self.desc = "Unknown"

    def _str_data(self):
        return self.rawdata.hex()

    def __str__(self):
        return f"{self.short}={self._str_data()}"

    @classmethod
    def from_buf(cls, buf):
        return cls(buf)


class BLE_Tag_Name(BLE_Tag_Base):
    def __init__(self, buf):
        super().__init__(buf)
        self.short = "N"
        self.desc = "Complete Local Name"

    def _str_data(self):
        return self.rawdata.decode("utf8")


class BLE_Tag_Service_Data(BLE_Tag_Base):
    def __init__(self, buf):
        super().__init__(buf)
        self.short = "S"
        self.desc = "Service"
        self.uuid = int.from_bytes(self.rawdata[0:2], byteorder="big")
        self.rawdata = self.rawdata[2:]

    def _str_data(self):
        return f"{self.uuid:04x}:{self.rawdata.hex()}"

    @classmethod
    def from_buf(cls, buf):
        # id = buf[0]
        uuid = int.from_bytes(buf[1:3], byteorder="big")
        id2cls = {
            0xd2fc: BTHome,
        }
        if uuid in id2cls:
            return id2cls[uuid].from_buf(buf[3:])
        return cls(buf)


class BLE_Tag:
    @classmethod
    def from_buf(cls, buf):
        """Extract the id and create an object of the correct class"""
        if len(buf) < 1:
            return None
        id = buf[0]

        id2cls = {
            0x09: BLE_Tag_Name,
            0x16: BLE_Tag_Service_Data,
        }
        cls = id2cls.get(id, BLE_Tag_Base)

        return cls.from_buf(buf)


class Message:
    def __init__(self):
        self.tags = []
        self.timestamp = None
        self.bthome = None
        self.rssi = None

    def __str__(self):
        s = []
        s += [f"{self.timestamp}"]
        s += [f"{self.addr}"]
        s += [f"{self.bthome}"]

        for tag in self.tags:
            s += [f"{tag}"]

        return " ".join(s)

    def to_influxline(self):
        if self.bthome is None:
            return None

        keys = f"node={self.addr}"
        # TODO: if there was a Name tag, could add it to keys

        values = {}
        values['rssi'] = str(self.rssi)
        for k, v in self.bthome.measurements.items():
            values[k] = str(v)
        values = ",".join(["=".join(i) for i in values.items()])

        return f"bthome,{keys} {values} {self.timestamp}"

    def add_tag(self, tag):
        if isinstance(tag, BTHome):
            self.bthome = tag
        else:
            self.tags.append(tag)


def handle_buf_inner1(msg, buf):
    """second layer wrapped message"""
    # TODO: It probably has a type name
    pos = 0

    while pos < len(buf):
        obj_len = buf[pos]
        pos += 1
        obj_buf = buf[pos:pos + obj_len]
        pos += obj_len

        tag = BLE_Tag.from_buf(obj_buf)
        msg.add_tag(tag)


def handle_buf(buf):
    """Handle a message from the bluetooth socket"""
    # TODO:
    # - accumulate metrics for unexpected events

    (
        event1,
        event_code,
        len1,
        subevent_code,
        num_reports,
        event_type,
        address_type,
        addr,
        len2
    ) = struct.unpack("BBBB3B6sB", buf[0:14])
    buf1 = buf[14:14 + len2]
    rssi = struct.unpack("b", buf[14 + len2:14 + len2 + 1])[0]

    if event1 != bluez.HCI_EVENT_PKT:
        return None
    if event_code != EVT_LE_META_EVENT:
        return None
    # if len1 != len(buf1) + size of decoded fields:
    #     return None

    if subevent_code != 2:
        return None
    # if num_reports != 1:
    #    report error, unhandled case
    #    return None

    msg = Message()
    msg.addr = MACAddr(addr[::-1])
    msg.rssi = rssi
    handle_buf_inner1(msg, buf1)
    return msg


def ble_open(name):
    devid = bluez.hci_devid(name)
    assert devid >= 0

    dev = bluez.hci_open_dev(devid)
    return dev


def ble_scan_enable(dev):
    dll = ctypes.CDLL("libbluetooth.so.3")

    r = dll.hci_le_set_scan_enable(
        dev.fileno(),
        1,            # enable = True
        0,            # filter_dup
        10000
    )
    if r != 0:
        # probably eperm
        # might be "alreacy scanning"
        # TODO:
        # - get scane enable and check before set
        print(f"WARNING: le set scan enable returned {r}")


def argparser():
    args = argparse.ArgumentParser(
        description=__doc__,
    )

    args.add_argument(
        "--config",
        action="append",
        help="File(s) or dir(s) to load config settings from",
    )

    args.add_argument(
        "--interface",
        help="Bluetooth interface name",
    )

    args.add_argument(
        "--influxdsn",
        help="Influxdb connection string",
    )

    args.add_argument(
        "--db",
        help="Influxdb database name",
    )

    args.add_argument(
        "--verbose",
        action="store_true",
        help="Set verbose output",
    )

    # authentication

    r = args.parse_args()
    return r


def config_load(args):
    config = {}

    # First, load the defaults
    config["influx"] = {
        "dsn": None,
        "db": None,
    }
    config["interface"] = "hci0"
    config["verbose"] = False

    if args.config:
        # TODO: merge the config
        raise NotImplementedError

    # Finally, overwrite with any CLI settings
    # TODO: if any more CLI args arrive, this will get unwieldy
    if args.influxdsn:
        config["influx"]["dsn"] = args.influxdsn
    if args.db:
        config["influx"]["db"] = args.db
    if args.interface:
        config["interface"] = args.interface
    if args.verbose:
        config["verbose"] = args.verbose

    return config


def main():
    args = argparser()
    config = config_load(args)

    dev = ble_open(config["interface"])
    ble_scan_enable(dev)

    if config["influx"]["dsn"] is None:
        db = None
    else:
        db = influxdb.InfluxDBClient.from_dsn(config["influx"]["dsn"])

    # Maybe save old filter?
    # filter_saved = dev.getsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, 14)

    filter = bluez.hci_filter_new()
    bluez.hci_filter_set_ptype(filter, bluez.HCI_EVENT_PKT)
    bluez.hci_filter_set_event(filter, EVT_LE_META_EVENT)
    dev.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, filter)

    # FIXME:
    # - how do we know we have permissions to listen?
    # - running this with user perms simply ends up never getting data
    #   (No errors registered)

    prev_seq = {}

    try:
        while True:
            buf = dev.recv(64)
            now = int(time.time())

            try:
                msg = handle_buf(buf)
            except ValueError as e:
                print(e)
                print(buf.hex())
                continue

            msg.timestamp = now

            if msg is None:
                continue
            if msg.bthome is None:
                continue

            try:
                sequence = msg.bthome.measurements["sequence"]
                prev = prev_seq.get(msg.addr.addr, None)
                if sequence == prev:
                    continue
                prev_seq[msg.addr.addr] = sequence
            except KeyError:
                pass

            # send to influx ...
            line = msg.to_influxline()
            if line is None:
                continue

            if config["verbose"]:
                print(line)
                sys.stdout.flush()

            if db is not None:
                db.write(
                    line,
                    params={
                        # FIXME:
                        # - why does the DSN database name not work?
                        # - also why not switch_database?
                        "db": config["influx"]["db"],
                        "precision": "s",
                    },
                    protocol="line"
                )

    except KeyboardInterrupt:
        # If saved, restore
        # dev.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, filter_saved)
        pass


if __name__ == "__main__":
    main()
