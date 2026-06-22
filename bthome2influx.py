#!/usr/bin/env python3
"""
Listen for BTHome structured BLE advertisements and send them to influx
"""
#
# :dotsctl:
#   dpkg:
#     - python3-bluez
#     - python3-influxdb
#     - python3-yaml
# ...
#

import argparse
import influxdb
import os
import requests
import sys
import time
import yaml

# Ensure that we look for any modules in our local lib dir.  This allows
# simple testing and development use.  It also does not break the case where
# the lib # has been installed properly on the normal sys.path
sys.path.insert(
    0,
    os.path.join(os.path.dirname(os.path.realpath(__file__)), 'python3')
)
# I would use site.addsitedir, but it does an append, not insert

import hc.ble  # noqa: E402
import hc.config  # noqa: E402


class MACAddr:
    def __init__(self, buf):
        self.addr = buf

    def __str__(self):
        a = []
        for b in self.addr:
            a.append(f"{b:02x}")
        return ":".join(a)


class Message:
    def __init__(self):
        self.timestamp = None
        self.bthome = None
        self.rssi = None
        self.tags = {}

    def __str__(self):
        s = []
        s += [f"{self.timestamp}"]
        s += [f"{self.addr}"]
        s += [f"{self.bthome}"]

        return " ".join(s)

    def to_influxline(self):
        if self.bthome is None:
            return None

        # TODO: if there was a Name tag, could add it to tags
        tag_set = ",".join(["=".join(i) for i in self.tags.items()])

        values = {}
        values['rssi'] = str(self.rssi)
        for k, v in self.bthome.measurements.items():
            values[k] = str(v)
        values = ",".join(["=".join(i) for i in values.items()])

        return f"bthome,{tag_set} {values} {self.timestamp}"

    def add_tag(self, tag):
        if isinstance(tag, hc.ble.BTHome):
            self.bthome = tag
        # TODO: could record name if it occurs


def handle_buf_inner1(msg, buf):
    """second layer wrapped message"""
    # TODO: It probably has a type name
    pos = 0

    while pos < len(buf):
        obj_len = buf[pos]
        pos += 1
        obj_buf = buf[pos:pos + obj_len]
        pos += obj_len

        tag = hc.ble.BLE_Tag.from_buf(obj_buf)
        msg.add_tag(tag)


def handle_buf(buf):
    """Handle a message from the bluetooth socket"""
    # TODO:
    # - accumulate metrics for unexpected events

    hci = hc.ble.HCI_Packet.from_bytes(buf)

    msg = Message()
    msg.addr = MACAddr(hci.addr[::-1])
    msg.rssi = hci.rssi
    handle_buf_inner1(msg, hci.remainder)
    return msg


def argparser():
    args = argparse.ArgumentParser(
        description=__doc__,
    )

    args.add_argument(
        "--interface",
        help="Bluetooth interface name",
    )

    args.add_argument(
        "--influxdsn",
        help="Influxdb connection string (Note: not a URL)",
    )

    args.add_argument(
        "--db",
        help="Influxdb database name",
    )

    args.add_argument(
        "--verbose",
        action="store_true",
        default=None,
        help="Set verbose output",
    )

    args.add_argument(
        "--debug",
        action="store_true",
        default=None,
        help="Dump some interal information",
    )

    # authentication

    hc.config.add_standard_args(args)
    r = args.parse_args()
    return r


def config_init(args):
    """Set the config defaults, load any conf files and merge the CLI args"""

    # First, load the defaults
    config = {
        "influx": {
            "options": {
                "verify_ssl": True,     # Why is this not the default?
            },
            "db": None,
        },
        "interface": "hci0",
        "ble": {},
        "tags": {},
    }

    # This is set early here to let the loader use the verbose flag and
    # again later to allow CLI to override any config file loaded
    config["debug"] = args.debug

    config = hc.config.config_init(args, config)

    # Finally, overwrite with any CLI settings
    # TODO: if any more CLI args arrive, this will get unwieldy
    if args.debug is not None:
        config["debug"] = args.debug
    if args.influxdsn:
        config["influx"]["dsn"] = args.influxdsn
    if args.db:
        config["influx"]["db"] = args.db
    if args.interface:
        config["interface"] = args.interface
    if args.verbose is not None:
        config["verbose"] = args.verbose
    else:
        config["verbose"] = False

    # Backwards support
    if "ble" not in config and "nodes" in config:
        print("Warning: old config for BLE nodes detected")
        config["ble"] = config["nodes"]

    return config


def main():
    args = argparser()
    config = config_init(args)

    if config["debug"]:
        print(yaml.safe_dump(config, default_flow_style=False))
        hc.ble.BTHome.debug = True
    # TODO: It would be great to apply a schema to config

    dev = hc.ble.open(config["interface"])
    hc.ble.scan_enable(dev)

    connection_options = config["influx"]["options"]

    if "dsn" in config["influx"]:
        db = influxdb.InfluxDBClient.from_dsn(
            config["influx"]["dsn"],
            **connection_options
        )
    elif "host" in connection_options:
        db = influxdb.InfluxDBClient(**connection_options)
    else:
        # If --verbose is set, stdout gets the line data, even when the
        # db is None
        db = None

    hc.ble.set_filter(dev)

    prev_seq = {}

    try:
        while True:
            buf = dev.recv(64)
            now = int(time.time())

            try:
                msg = handle_buf(buf)
            except ValueError as e:
                print(e)
                print("Buffer:", buf.hex())
                continue

            if msg is None:
                continue

            msg.timestamp = now
            msg.tags.update(config["tags"])
            addr = str(msg.addr)
            if addr in config["ble"]:
                if config["ble"][addr].get("skip_node", False):
                    continue
                msg.tags.update(config["ble"][addr])

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

            # The data schema for influx needs a per-node tag to show
            # different sources
            msg.tags["node"] = str(msg.addr)

            # send to influx ...
            line = msg.to_influxline()
            if line is None:
                continue

            if config["verbose"]:
                print(line)
                sys.stdout.flush()

            if db is None:
                continue

            try:
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
            except (
                        requests.exceptions.ConnectionError,
                        influxdb.exceptions.InfluxDBServerError,
                    ) as e:
                print(e)
                continue

    except KeyboardInterrupt:
        # If saved, restore
        # dev.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, filter_saved)
        pass


if __name__ == "__main__":
    main()
