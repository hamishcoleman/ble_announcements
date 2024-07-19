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


EVT_LE_META_EVENT = 0x3e


def handle_buf_inner1(buf):
    """first layer wrapped message"""
    # TODO: It probably has a type name
    pos = 0

    # TODO:
    # - this is a LTVi
    # - how do we know it ends?
    flags = buf[pos:pos+3]
    pos += 3
    if flags not in [b'\x02\x01\x00', b'\x02\x01\x03'] :
        raise ValueError(f"unexpected {flags} {pos} {buf}")

    # unknown
    if buf[pos] not in [0, 1]:
        raise ValueError(f"unexpected {buf[pos]} {pos} {buf}")
    pos += 1

    print(buf)


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
        handle_buf(buf)

    # If saved, restore
    # dev.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, filter_saved)


if __name__ == "__main__":
    main()
