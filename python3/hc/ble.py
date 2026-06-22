"""
Some simple helpers to make dealing with bluetooth easier
"""

import bluetooth._bluetooth as bluez
import ctypes
import hc.measurements
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


class BTHome:
    debug = False

    @classmethod
    def from_buf(cls, buf):
        return cls(buf)

    def __init__(self, buf):
        self.info = buf[0]
        self.measurements = {}
        self._parse_measurements(buf[1:])

        if self.debug:
            print("DEBUG:", str(self))

    def __str__(self):
        s = ["BTHome"]
        for k, v in self.measurements.items():
            s += [k, str(v)]

        return " ".join(s)

    def _parse_measurements(self, buf):
        pos = 0
        while pos < len(buf):
            item = hc.measurements.Measurement.from_bthome(buf, pos)
            pos = item._end_pos

            # TODO:
            # - this could return objects

            if self.debug:
                print("DEBUG: obj_id=", item._obj_id, "pos=", item._data_pos)

            self.measurements[item.name] = item.value


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
    # https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/CSS_v11/out/en/supplement-to-the-bluetooth-core-specification/data-types-specification.html#UUID-b1d0edbc-fc9e-507a-efe4-3fd4b4817a52
    # 2.1.2. Example advertising data – Complete Local Name
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
        # https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host/generic-access-profile.html#UUID-c2a0b759-8ef4-7055-c13b-17c083691361
        if len(buf) < 1:
            return None
        # extract AD_Type and use that to find a specific class
        id = buf[0]

        # https://bitbucket.org/bluetooth-SIG/public/src/6e06a498f44bc1e7e2de65524ed6509d26409d22/assigned_numbers/core/ad_types.yaml#lines-59
        id2cls = {
            0x09: BLE_Tag_Name,
            0x16: BLE_Tag_Service_Data,
        }
        cls = id2cls.get(id, BLE_Tag_Base)

        return cls.from_buf(buf)


def test_BLE_Tag():
    import pytest

    # Unspecific tag
    data = b"\x01\x02\x03"
    tag = BLE_Tag.from_buf(data)
    assert str(tag) == "1=0203"

    # Name tag
    data = b"\x09test_name"
    tag = BLE_Tag.from_buf(data)
    assert str(tag) == "N=test_name"

    # Generic service tag
    data = b"\x16\x01\x02\x03"
    tag = BLE_Tag.from_buf(data)
    assert str(tag) == "S=0102:03"
    assert tag.rawdata == b"\x03"

    # BTHome service tag with unknown measurement
    data = b"\x16\xd2\xfc\x00\x5a\x11"
    with pytest.raises(ValueError):
        BLE_Tag.from_buf(data)

    # BTHome service tag
    data = b"\x16\xd2\xfc\x00\x00\x11\x01\x40"
    tag = BLE_Tag.from_buf(data)
    assert str(tag) == "BTHome sequence 17 battery 64"
    assert tag.measurements == {
        "sequence": 17,
        "battery": 64,
    }


class HCI_Packet:
    # https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host-controller-interface/uart-transport-layer.html
    # 2. Protocol
    #
    # https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host-controller-interface/host-controller-interface-functional-specification.html
    # 5.4.4. HCI Event packet
    # 7.7.65. LE Meta event
    # 7.7.65.2. LE Advertising Report event
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

        if self.subevent_code != 2:  # HCI_LE_Advertising_Report event
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
