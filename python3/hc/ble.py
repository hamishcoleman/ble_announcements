"""
Some simple helpers to make dealing with bluetooth easier
"""

import bluetooth._bluetooth as bluez
import ctypes
import struct

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


class HCI_Packet:
    # https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host-controller-interface/uart-transport-layer.html
    # 2. Protocol
    #
    # https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host-controller-interface/host-controller-interface-functional-specification.html
    # 5.4.4. HCI Event packet
    #
    # TODO:
    # - the above links are incomplete, document the rest of the structure

    @classmethod
    def from_bytes(cls, buf):
        fmt0 = "BBBB3B6sB"
        len0 = struct.calcsize(fmt0)
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
        ) = struct.unpack(fmt0, buf[0:len0])
        len3 = len0 + len2

        # Store the remainder bytes
        buf1 = buf[len0:len3]

        self = cls()
        self.packet_type = event1
        self.event_code = event_code
        self.subevent_code = subevent_code

        if len(buf) == len3 + 1:
            self.rssi = struct.unpack("b", buf[len3:len3 + 1])[0]
        else:
            # TODO: I thought that the buffer was /always/ followed by a rssi
            # byte.  Check if it is allowed to be optional and raise an error
            # on unexpected conditions.
            self.rssi = None

        if self.packet_type != bluez.HCI_EVENT_PKT:
            return None
        if self.event_code != EVT_LE_META_EVENT:
            return None
        # if len1 != len(buf1) + size of decoded fields:
        #     return None

        if self.subevent_code != 2:
            return None
        if num_reports != 1:
            raise ValueError("Cannot handle num_reports != 1")

        self.event_type = event_type
        self.address_type = address_type
        self.addr = addr
        self.remainder = buf1
        return self


def test_HCI_Packet():
    import pytest

    # data too short
    data = b"\x00"
    with pytest.raises(struct.error):
        HCI_Packet.from_bytes(data)

    # Wrong packet_type
    data = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    assert HCI_Packet.from_bytes(data) is None

    # Wrong event_code
    data = b"\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    assert HCI_Packet.from_bytes(data) is None

    # Wrong subevent_code
    data = b"\x04\x3e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    assert HCI_Packet.from_bytes(data) is None

    # unexpected num_reports
    data = b"\x04\x3e\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    with pytest.raises(ValueError):
        HCI_Packet.from_bytes(data)

    data = b"\x04\x3e\x00\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x5a"
    hci = HCI_Packet.from_bytes(data)

    assert hci.packet_type == bluez.HCI_EVENT_PKT
    assert hci.event_code == EVT_LE_META_EVENT
    assert hci.subevent_code == 2
    # assert hci.event_type ==
    # assert hci.address_type ==
    # assert hci.addr ==
    assert hci.remainder == b"\x5a"
