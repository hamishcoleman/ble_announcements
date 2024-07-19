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


class MACAddr:
    def __init__(self, buf):
        self.addr = buf

    def __str__(self):
        a = []
        for b in self.addr:
            a.append(f"{b:02x}")
        return ":".join(a)


def _manuf(buf):
    names = {
        0x4c: "Apple",
        0x75: "Samsung",
        0x611: "Beurer",
        0x6a8: "GD_Midea",
    }
    manuf = int.from_bytes(buf[0:2], byteorder="little")
    if manuf in names:
        manuf = names[manuf]
    else:
        manuf = f"0x{manuf:x}"
    data = buf[2:]
    return f"{manuf}:{data.hex()}"


def _s8dBm(buf):
    b = int.from_bytes(buf[0:1], byteorder="little", signed=True)
    return f"{b}dBm"


def _str(buf):
    return buf.decode("utf8")


def _u8hex(buf):
    b = buf[0]
    return f"0x{b:02x}"


def _u16hex_nox(buf):
    b = int.from_bytes(buf[0:2], byteorder="little")
    return f"{b:04x}"


class BLE_Tag:

    tag_ids = {
        0x01: {
            "desc": "Flags",
            "short": "F",
            "str": _u8hex,
        },
        0x02: {
            "desc": "UUID",
            "short": "U",
            "str": _u16hex_nox,
        },
        0x09: {
            "desc": "Complete Local Name",
            "short": "N",
            "str": _str,
        },
        0x0a: {
            "desc": "TX Power Level",
            "short": "Tx",
            "str": _s8dBm,
        },
        0x19: {
            "desc": "Appearance",
            "short": "Icon",
            "str": _u16hex_nox,
        },
        0xff: {
            "desc": "Manufacturer Specific",
            "short": "M",
            "str": _manuf,
        },
    }

    def __init__(self, buf):
        self.buf = buf

    def __str__(self):
        id = self.id()
        if id in self.tag_ids:
            tag_info = self.tag_ids[id]
            return tag_info["short"] + ":" + tag_info["str"](self.data())
        return str(self.buf)

    def id(self):
        return self.buf[0]

    def data(self):
        return self.buf[1:]


class Message:
    def __init__(self):
        self.tags = []

    def __str__(self):
        s = []
        s += [f"{self.addr}"]

        if hasattr(self, "buf"):
            s += [f"{self.buf}"]

        for tag in self.tags:
            s += [f"{tag}"]

        return " ".join(s)

    def add_tag(self, tag):
        self.tags.append(tag)


EVT_LE_META_EVENT = 0x3e


def handle_buf_inner2(msg, buf):
    """second layer wrapped message"""
    # TODO: It probably has a type name
    pos = 0

    while pos < len(buf):
        obj_len = buf[pos]
        pos += 1
        obj_buf = buf[pos:pos + obj_len]
        pos += obj_len

        tag = BLE_Tag(obj_buf)
        msg.add_tag(tag)


def handle_buf_inner1(buf):
    """first layer wrapped message"""
    # TODO: It probably has a type name
    pos = 0

    msg = Message()

    # TODO:
    # - this is a LTV
    # - how do we know it ends?
    flags = buf[pos:pos+3]
    pos += 3
    if flags not in [b'\x02\x01\x00', b'\x02\x01\x03']:
        raise ValueError(f"unexpected {flags} {pos} {buf}")
    # TODO: msg.flags0 = flags

    # unknown
    if buf[pos] not in [0, 1]:
        raise ValueError(f"unexpected {buf[pos]} {pos} {buf}")
    pos += 1
    # TODO: msg.?? =

    # AdvA
    msg.addr = MACAddr(buf[pos:pos+6][::-1])
    pos += 6

    len2 = buf[pos]
    pos += 1

    handle_buf_inner2(msg, buf[pos:pos + len2])
    pos += len2

    # TODO:
    # always seems to be one more byte
    # msg.?? = buf[pos]

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

    event_sub = buf[pos]
    pos += 1
    if event_sub != EVT_LE_META_EVENT:
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
    assert devid >= 0

    dev = bluez.hci_open_dev(devid)

    # Maybe:
    # hciconfig hci0 up
    # btmgmt le on

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

    while True:
        buf = dev.recv(64)
        print(handle_buf(buf))

    # If saved, restore
    # dev.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, filter_saved)


if __name__ == "__main__":
    main()
