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
import sys


EVT_LE_META_EVENT = 0x3e


class MACAddr:
    def __init__(self, buf):
        self.addr = buf

    def __str__(self):
        a = []
        for b in self.addr:
            a.append(f"{b:02x}")
        return ":".join(a)


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


class BLE_Tag_Flags(BLE_Tag_Base):
    def __init__(self, buf):
        super().__init__(buf)
        self.short = "F"
        self.desc = "Flags"
        # rawdata is 1 byte bitmapped flags


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
        id = buf[0]

        id2cls = {
            0x01: BLE_Tag_Flags,
            0x02: BLE_Tag_UUID,
            0x09: BLE_Tag_Name,
            0x0a: BLE_Tag_TXpower,
            0x19: BLE_Tag_Appearance,
            0xff: BLE_Tag_Manufacturer,
        }
        cls = id2cls.get(id, BLE_Tag_Base)

        return cls(buf)


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


def handle_buf_inner2(msg, buf):
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
        sys.stdout.flush()

    # If saved, restore
    # dev.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, filter_saved)


if __name__ == "__main__":
    main()
