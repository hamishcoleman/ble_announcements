"""
Provide generic measurement objects
"""

import struct


class Measurement:
    @classmethod
    def from_bthome(cls, buf, pos):
        """
        Lookup the correct object and return an instance
        """
        obj_id = buf[pos]
        pos += 1
        data_pos = pos

        # TODO:
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
            0x11: {
                "name": "opening",
                "size": 1,
                "type": "?",
            },
            0x3e: {
                "name": "count",
                "size": 4,
                "type": "<L",
            },
        }

        # if self.debug:
        #     print("DEBUG: obj_id=", obj_id, "pos=", pos)

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

        self = cls()
        self.value = value
        self.raw = raw
        self.name = type["name"]
        self.rawdata = rawdata

        self._obj_id = obj_id
        self._data_pos = data_pos
        self._end_pos = pos
        return self
