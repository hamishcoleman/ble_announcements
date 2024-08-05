#!/usr/bin/env python3
"""
Listen for BLE advertisements and dump
"""
#
# :dotsctl:
#   dpkg:
#     - python3-bluez
# ...
#

import argparse
import bluetooth._bluetooth as bluez
import ctypes
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

            # TODO: this could return objects

            data_types = {
                0: {
                    "name": "sequence",
                    "size": 1,
                    "type": "u8",
                },
                1: {
                    "name": "battery",
                    "size": 1,
                    "type": "u8",
                    "unit": "%",
                },
                2: {
                    "name": "temperature",
                    "size": 2,
                    "type": "s16",
                    "factor": 0.01,
                    "unit": "°C",
                },
                3: {
                    "name": "humidity",
                    "size": 2,
                    "type": "u16",
                    "factor": 0.01,
                    "unit": "%",
                },
                0x0c: {
                    "name": "voltage",
                    "size": 2,
                    "type": "u16",
                    "factor": 0.001,
                    "unit": "V",
                },
                0x10: {
                    "name": "power",
                    "size": 1,
                    "type": "bool",
                },
            }

            if obj_id not in data_types:
                # TODO: be more resilient in the face of unknown
                raise ValueError(f"Unknown BTHome measurement {obj_id}")

            type = data_types[obj_id]

            if type["type"] == "u8":
                raw = buf[pos]
            elif type["type"] == "s16":
                raw = int.from_bytes(buf[pos:pos+2], "little", signed=True)
            elif type["type"] == "u16":
                raw = int.from_bytes(buf[pos:pos+2], "little")
            elif type["type"] == "bool":
                raw = buf[pos] != 0

            pos += type["size"]

            if "factor" in type:
                value = raw * type["factor"]
            else:
                value = raw

            self.measurements[type["name"]] = value


class MiBeacon:
    # Theoretically, this packet format could include useful sensor data,
    # but the device I had to test with did not send anything useful, so
    # There ended up being nothing further to decode
    #

    @classmethod
    def from_buf(cls, buf):
        return cls(buf)

    def __init__(self, buf):
        self.buf = buf

    def __str__(self):
        s = ["MiBeacon"]
        s += [self.buf.hex()]

        return " ".join(s)


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


class BLE_Tag_Flags(BLE_Tag_Base):
    # Supplement to Core spec, Part A, 1.3
    def __init__(self, buf):
        super().__init__(buf)
        self.short = "F"
        self.desc = "Flags"
        # rawdata is n bytes bitmapped flags


class BLE_Tag_UUID(BLE_Tag_Base):
    def __init__(self, buf):
        super().__init__(buf)
        self.short = "U"
        self.desc = "UUID"
        # rawdata is u16


class BLE_Tag_Name(BLE_Tag_Base):
    def __init__(self, buf):
        super().__init__(buf)
        self.short = "N"
        self.desc = "Complete Local Name"

    def _str_data(self):
        return self.rawdata.decode("utf8")


class BLE_Tag_TXpower(BLE_Tag_Base):
    def __init__(self, buf):
        super().__init__(buf)
        self.short = "Tx"
        self.desc = "Tx Power Level"

    def _str_data(self):
        b = int.from_bytes(self.rawdata[0:1], byteorder="little", signed=True)
        return f"{b}dBm"


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
            0x95fe: MiBeacon,
            0xd2fc: BTHome,
        }
        if uuid in id2cls:
            return id2cls[uuid].from_buf(buf[3:])
        return cls(buf)


class BLE_Tag_Appearance(BLE_Tag_Base):
    def __init__(self, buf):
        super().__init__(buf)
        self.short = "Icon"
        self.desc = "Appearance"
        self.icon_id = int.from_bytes(self.rawdata[0:2], byteorder="little")

    def icon(self):
        names = {
            0x00c0: "Watch",
        }
        return names.get(self.icon_id, f"0x{self.icon_id:x}")

    def _str_data(self):
        return self.icon()


class BLE_Tag_Manufacturer(BLE_Tag_Base):
    def __init__(self, buf):
        super().__init__(buf)
        self.short = "M"
        self.desc = "Manufacturer Specific"
        self.manuf_id = int.from_bytes(self.rawdata[0:2], byteorder="little")
        self.rawdata = self.rawdata[2:]

    def manuf(self):
        names = {
            0x4c: "Apple",
            0x75: "Samsung",
            0x611: "Beurer",
            0x6a8: "GD_Midea",
        }
        return names.get(self.manuf_id, f"0x{self.manuf_id:x}")

    def _str_data(self):
        return f"{self.manuf()}:{self.rawdata.hex()}"


class BLE_Tag:
    @classmethod
    def from_buf(cls, buf):
        """Extract the id and create an object of the correct class"""
        if len(buf) < 1:
            return None

        # ad_type
        id = buf[0]

        # Assigned Numbers, 2.3: Common Data Types
        id2cls = {
            0x01: BLE_Tag_Flags,
            0x02: BLE_Tag_UUID,
            0x09: BLE_Tag_Name,
            0x0a: BLE_Tag_TXpower,
            0x16: BLE_Tag_Service_Data,
            0x19: BLE_Tag_Appearance,
            0xff: BLE_Tag_Manufacturer,
        }
        cls = id2cls.get(id, BLE_Tag_Base)

        return cls.from_buf(buf)


class Message:
    def __init__(self):
        self.tags = []
        self.rssi = None

    def __str__(self):
        s = []
        s += [f"{self.addr}"]
        s += [f"rssi={self.rssi}"]

        if hasattr(self, "buf"):
            s += [f"{self.buf}"]

        for tag in self.tags:
            s += [f"{tag}"]

        return " ".join(s)

    def add_tag(self, tag):
        self.tags.append(tag)


def handle_buf_inner2(msg, buf):
    """second layer wrapped message"""
    # Bluetooth spec, Vol 3, Part C, Section 11
    pos = 0

    while pos < len(buf):
        # ad struct length
        obj_len = buf[pos]
        pos += 1
        obj_buf = buf[pos:pos + obj_len]
        pos += obj_len

        tag = BLE_Tag.from_buf(obj_buf)
        msg.add_tag(tag)


def handle_buf_inner1(buf):
    """first layer wrapped message"""
    # TODO: It probably has a type name
    pos = 0

    msg = Message()

    # TODO:
    # flags:
    #   subevent_code == 2
    #   num_reports (1 through 0x19)
    #   event_type[num_reports]

    flags = buf[pos:pos+3]
    pos += 3
    if flags not in [b'\x02\x01\x00', b'\x02\x01\x02',  b'\x02\x01\x03']:
        # TODO: be more resilient
        raise ValueError(f"unexpected {flags} {pos} {buf}")
    # TODO: msg.flags0 = flags

    # address_type[num_reports]
    if buf[pos] not in [0, 1]:
        # TODO: be more resilient
        raise ValueError(f"unexpected {buf[pos]} {pos} {buf}")
    pos += 1
    # TODO: msg.?? =

    # address[num_reports]
    msg.addr = MACAddr(buf[pos:pos+6][::-1])
    pos += 6

    # data_length[num_reports]
    len2 = buf[pos]
    pos += 1

    # data - repeated num_reports times, each one sized by data_length[]
    handle_buf_inner2(msg, buf[pos:pos + len2])
    pos += len2

    # TODO:
    # final byte
    # RSSI[num_reports] (-127 thru +20, or 0x7f for None)
    msg.rssi = struct.unpack("b", buf[pos:pos + 1])[0]

    return msg


def handle_buf(buf):
    """Handle a message from the bluetooth socket"""
    pos = 0

    # messages are prefixed with a two byte struct, check it looks right
    # TODO: it probably has a type name
    event = buf[pos]
    pos += 1
    if event != bluez.HCI_EVENT_PKT:
        raise ValueError("expected HCI_EVENT_PKT")

    # Bluetooth Core Vol 4, Part E, 7.7.65.2 LE Advertising Report event
    event_code = buf[pos]
    pos += 1

    if event_code != EVT_LE_META_EVENT:
        raise ValueError("expected EVT_LE_META_EVENT")

    # consistancy check.
    # TODO: is which struct is this length part of?
    len1 = buf[pos]
    pos += 1

    if len1 != len(buf) - pos:
        raise ValueError("expected correct length")

    return handle_buf_inner1(buf[pos:])


def argparser():
    args = argparse.ArgumentParser(
        description=__doc__,
    )

    args.add_argument(
        "--interface",
        default="hci0",
        help="Bluetooth interface name",
    )

    r = args.parse_args()
    return r


def main():
    args = argparser()

    devid = bluez.hci_devid(args.interface)
    if devid < 0:
        raise ValueError(f"devid error {devid}")

    dev = bluez.hci_open_dev(devid)

    dll = ctypes.CDLL("libbluetooth.so.3")

    if False:
        # These are often the default values, maybe we can skip setting it?
        dll.hci_le_set_scan_parameters(
            dev.fileno(),
            0,            # scan_type = passive
            16,           # interval
            16,           # window
            0,            # own_type (unused if passive?)
            0,            # filter_policy = unfiltered
            10000         # to
        )

    # TODO:
    # - find a way to get scan enable
    # - dont set it if it is already set
    # - restore the state on exit

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
        # - get errno and react differently depending on reason
        print(f"WARNING: le set scan enable returned {r}")

    # Maybe:
    # systemctl stop bluetooth
    # hciconfig hci0 up

    # Maybe save old filter?
    # filter_saved = dev.getsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, 14)

    filter = bluez.hci_filter_new()
    bluez.hci_filter_set_ptype(filter, bluez.HCI_EVENT_PKT)
    bluez.hci_filter_set_event(filter, EVT_LE_META_EVENT)
    dev.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, filter)

    try:
        while True:
            buf = dev.recv(64)
            now = int(time.time())
            print(now, handle_buf(buf))
            sys.stdout.flush()
    except KeyboardInterrupt:
        pass

        # If saved, restore
        # dev.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, filter_saved)

        # This will affect any other scanning tool, so dont do it
        # Stop scanning when we exit
        # (some devices will return "busy" errors if scanning is enabled
        # when we ask them to enable scanning)
        # r = dll.hci_le_set_scan_enable(
        #     dev.fileno(),
        #     0,            # enable = False
        #     0,            # filter_dup
        #     10000
        # )


if __name__ == "__main__":
    main()
