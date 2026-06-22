"""
Some simple helpers to make dealing with bluetooth easier
"""

import bluetooth._bluetooth as bluez
import ctypes


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
