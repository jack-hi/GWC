#!/usr/bin/python3
# -*- coding: utf-8 -*-


from copy import copy as _copy
from struct import pack, unpack
from binascii import hexlify
from socket import inet_aton, inet_ntoa
from time import localtime
from mcrptos import AES128, MD5, Icrc16
from crc16 import crc16xmodem
import time
import logging


Log = logging.getLogger("App0")


class Packet(object):
    def __init__(self, data = None, *args, **kwargs):
        # super().__init__(*args, **kwargs)

        if data is None:
            self.pdata = bytearray()
        elif isinstance(data, (bytes, bytearray)):
            self.pdata = bytearray(data)
        elif isinstance(data, Packet):
            self.pdata = _copy(data.pdata)
        else:
            raise TypeError("bytes or bytearray needed.")

    def encode(self):
        # raise NotImplemented("Abstract Method")
        if len(self.pdata) is not 0:
            raise RuntimeError("Could not call this method more than once")

    def decode(self):
        raise NotImplemented("Abstract Method")

    def get_all(self):
        all = self.pdata[:]
        del self.pdata[:]
        return all

    def get(self):
        """ get the first byte in the byte array and delete from the bytearray """
        if len(self.pdata) == 0:
            raise ValueError("packet is empty.")

        octet = self.pdata[0]
        del self.pdata[0]
        return octet

    def get_data(self, dlen):
        """ get len bytes from the bytearray and delete from the bytearray """
        if len(self.pdata) < dlen:
            raise ValueError("out of range")

        data = self.pdata[:dlen]
        del self.pdata[:dlen]
        return data

    def get_short(self):
        """ get a short int from the head of the bytearray
            the short int is big-endian in bytearray"""
        return unpack('>H', self.get_data(2))[0]

    def get_long(self):
        return unpack('>L', self.get_data(4))[0]

    def put(self, n):
        self.pdata += bytes([n])

    def put_data(self, data):
        if isinstance(data, bytes):
            pass
        elif isinstance(data, bytearray):
            pass
        elif isinstance(data, list):
            data = bytes(data)
        else:
            raise ValueError("need bytes/bytearray/list")

        self.pdata += data

    def put_short(self, s):
        self.pdata += pack('>H', s & 0xFFFF)

    def put_long(self, l):
        self.pdata += pack('>L', l & 0xFFFFFFFF)

    def __str__(self):
        hexstr = str(hexlify(self.pdata), 'ascii').upper()
        sep = ' '
        return sep.join(hexstr[i:i+2] for i in range(0, len(hexstr), 2))


class HbFrame(Packet):
    """
    HbFrame: big-endian
    +--------+--------+--------+--------+
    |    sequence     |     year        |
    +--------+--------+--------+--------+
    | month  |  day   |  hour  | minute |
    +--------+--------+--------+--------+
    | second |           0              |
    +--------+--------+--------+--------+
    |        0        |
    +--------+--------+
    """
    TYPE = 0

    seq = 0
    def __init__(self):
        super().__init__()

    def encode(self):
        super().encode()
        self.put_short(self.get_seq())
        self.update_seq()
        time = localtime()
        self.put_short(time.tm_year)
        self.put(time.tm_mon)
        self.put(time.tm_mday)
        self.put(time.tm_hour)
        self.put(time.tm_min)
        self.put(time.tm_sec)
        self.put_data(bytes(5))
        return self

    def update_seq(self):
        HbFrame.seq += 1

    def get_seq(self):
        if HbFrame.seq > 0xFFFF:
            HbFrame.seq = 0
        return HbFrame.seq


class LgiFrame(Packet):
    """
    frame: (big-endian)
    +--------+--------+--------+--------+
    |      year       | month  |   day  |
    +--------+--------+--------+--------+
    |  hour  | minute | second |    0   |
    +--------+--------+--------+--------+
    |                 0                 |
    +--------+--------+--------+--------+
    |                 0                 |
    +--------+--------+--------+--------+
    |                                   |
    +                                   +
    |                                   |
    +              AES/MD5              +
    |                                   |
    +                                   +
    |                                   |
    +--------+--------+--------+--------+
    """
    TYPE = 1
    def __init__(self, key=None):
        super().__init__()

        if key is None:
            self.key = bytes([0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35])
        else:
            self.key = key

    def encode(self):
        super().encode()
        time = localtime()
        self.put_short(time.tm_year)
        self.put(time.tm_mon)
        self.put(time.tm_mday)
        self.put(time.tm_hour)
        self.put(time.tm_min)
        self.put(time.tm_sec)
        self.put_data(bytes(9))
        aes_crypto = AES128(self.key).encrypt(bytes(self.pdata))
        self.put_data(MD5().digest(aes_crypto[:16]))
        return self

    def verify(self, data):
        if not isinstance(data, (bytes, bytearray)):
            #raise TypeError("data must be a byte-like array.")
            Log.warning("Type Error, data must be a byte-like array.")
            return False
        if len(data) is not 16*2:
            #raise ValueError("data length error.")
            Log.warning("Type Error, data length error.")
            return False
        crypto = MD5().digest(AES128(self.key).encrypt(bytes(data[:16]))[:16])
        return crypto == data[16:]


class BacFrame(Packet):
    TYPE = 2
    def __init__(self, data):
        super().__init(data)


class FcFrame(Packet):
    """
     **
     * PacketSegment Structure: (big-endian)
     *	0       8       16      24     31
     *	+-------+-------+---------------+
     *	| 0x88  | flags |     length    |
     *	+-------+-------+-------+-------+
     *	|    packetID   |   segmentNum  |
     *	+---------------+---------------+
     *	|             DATA              |
     *	+-------------------------------+
     *
     *	flags:
     *	 7 6 5 4 3 2 1 0
     *	+-+-+-+-+-+-+-+-+
     *	| | | | | | |f|a|
     *	|0|0|0|0|0|0|l|c|
     *	| | | | | | |w|k|
     *	+-+-+-+-+-+-+-+-+
     *	flw: more follow flags
     *	ack: ACK flags
     *

    """
    TYPE = 6

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.identity = Segment.INDENTITY
        self.flags = 0
        self.packet_id = 0
        self.length = 0
        self.seq = 0
        self.data = None

    def update(self, flags, id, seq, data):
        self.flags = flags
        self.packet_id = id
        self.seq = seq
        if data is None:
            self.length = 8
            return
        else:
            if not isinstance(data, (list, bytes, bytearray)):
                raise ValueError(" value type error ")
            self.data = data
            self.length = 8 if data == None else 8 + len(data)
        return self

    def encode(self):
        self.put(self.identity)
        self.put(self.flags)
        self.put_short(self.length)
        self.put_short(self.packet_id)
        self.put_short(self.seq)
        if self.data is not None:
            self.put_data(self.data)

        return self

    def decode(self):
        self.get()  # identity: 0x88
        self.flags = self.get()
        self.length = self.get_short()
        self.packet_id = self.get_short()
        self.seq = self.get_short()
        self.data = self.get_all()

        return self

    def get_flags(self):
        return self.flags

    def get_packet_id(self):
        return self.packet_id

    def get_length(self):
        return self.length

    def get_seq(self):
        return self.seq

    def get_segment_data(self):
        return self.data

    def __str__(self):
        tmp = Packet.__str__(self)
        tmp += \
            f"\nidentity: 0x{self.identity:x}, " \
            f"flags: {self.flags}, " \
            f"length: {self.length}, " \
            f"packet_id: {self.packet_id}, " \
            f"segment_num: {self.seq}\n"
        return tmp


class WxFrame(Packet):
    TYPE = 7
    def __init__(self, data):
        super().__init(data)


class Dwrap(Packet):
    """
    " simple wrap
    +--------+--------+--------+--------+
    |    identity     |     length      |
    +--------+--------+--------+--------+
    |  type  |
    +--------+--------+--------+--------+
    |                 ID                |
    +--------+--------+--------+--------+
    |                 IP                |
    +--------+--------+--------+--------+
    |      port       |
    +--------+--------+--------+--------+
    |                                   |
    +           reserveed 17B           +
    |                                   |
    +--------+--------+--------+--------+
    |                                   |
    +                DATA               +
    |                                   |
    +--------+--------+--------+--------+
    |       CRC       |
    +--------+--------+

    length: len([type:])
    CRC: CRC([length:CRC])
    """
    IDENTITY = bytes([0x55, 0xaa])

    def __init__(self, type=None, id=None, dip=None, dport=None, data=None):
        super().__init__()
        self.length = 30
        self.type = type
        self.disp_id = id
        self.dip = dip #IP:PORT
        self.dport = dport
        self.data = data
        self.crc = 0

    def update(self, type=None, id=None, dip=None, dport=None, data=None):
        if type is not None: self.type = type
        if id is not None: self.disp_id = id
        if dip is not None: self.dip = dip
        if dport is not None: self.dport = dport
        if data is not None:
            if not isinstance(data, (list, bytes, bytearray)):
                raise ValueError("value type error")
            self.data = data
        return self

    def encode(self):
        super().encode()
        self.put_data(Dwrap.IDENTITY)  # identity: 2
        if self.data is not None:
            self.length = 30 + len(self.data)
        self.put_short(self.length)  # length: 2
        self.put(self.type)  # type: 1
        self.put_long(self.disp_id)  # id: 4
        self.put_data(inet_aton(self.dip))  # ip: 4
        self.put_short(self.dport)  # port: 2
        self.put_data(bytes(17))  # reserved: 17
        if self.data is not None:
            self.put_data(self.data)  # data: n
        # crc = crc16xmodem(bytes(self.pdata[2:]))
        crc = Icrc16.CRC16(bytes(self.pdata[2:]))
        self.put(crc&0xFF)
        self.put((crc&0xFF00) >> 8)
        return self

    def decode(self, data):
        if not isinstance(data, (bytes, bytearray)):
            # raise ValueError("data type ERROR, must be byte-like array.")
            Log.warning("Value Error, data must be byte-like array.")
            return None
        p = Packet(data)
        if Dwrap.IDENTITY != p.get_data(2):
            # raise ValueError("packet data error, identity error")
            Log.warning("Value Error, identity error.")
            return None
        # crc = crc16xmodem(bytes(p.pdata[:-2]))
        crc = Icrc16.CRC16(bytes(p.pdata[:-2]))
        self.length = p.get_short()
        if len(p.pdata) != self.length:
            # raise ValueError("packet data error, Length error")
            Log.warning("Value Error, pakcet length error.")
            return None
        self.type = p.get()
        self.disp_id = p.get_long()
        self.dip = inet_ntoa(p.get_data(4))
        self.dport = p.get_short()
        p.get_data(17)
        self.data = p.get_data(self.length-30)
        crcl = p.get()
        crch = p.get()
        self.crc = crch<<8 | crcl
        if crc != self.crc:
            # raise ValueError("packet data error, CRC error")
            Log.warning("Value Error, packet CRC error.")
            return None
        return self


if __name__ == '__main__':

    l = LgiFrame()
    t1 = l.encode().get_all()
    print(t1)
    if l.verify(t1):
        print("OK")

    h1 = HbFrame()
    print(h1.encode())
    time.sleep(1)
    h2 = HbFrame()
    print(h2.encode())
    time.sleep(1)
    h3 = HbFrame()
    print(h3.encode())

    sr = Dwrap()
    sr.update(1, 101, '10.98.1.178', 7894, h3.get_all())
    sr.encode()
    print(sr)

