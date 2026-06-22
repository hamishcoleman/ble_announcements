"""
Some simple helpers to make dealing with bluetooth easier
"""

import bluetooth._bluetooth as bluez
import ctypes

EVT_LE_META_EVENT = 0x3e


def open(name):
    """
    Given the bluetooth kernel device name, perform all the steps needed to
    get a working handle to it
    """
    # TODO:
    # rfkill unblock $n
    # hcitool $name up

    devid = bluez.hci_devid(name)
    assert devid >= 0

    dev = bluez.hci_open_dev(devid)
    return dev


def scan_enable(dev):
    dll = ctypes.CDLL("libbluetooth.so.3")

    # # These are often the default values, maybe we can skip setting it?
    # dll.hci_le_set_scan_parameters(
    #     dev.fileno(),
    #     0,            # scan_type = passive
    #     16,           # interval
    #     16,           # window
    #     0,            # own_type (unused if passive?)
    #     0,            # filter_policy = unfiltered
    #     10000         # to
    # )

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
        # - get scane enable and check before set
        print(f"WARNING: le set scan enable returned {r}")


def set_filter(dev):
    """
    Apply filters to the socket to allow BLE event reception
    """

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
