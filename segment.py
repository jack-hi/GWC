#!/usr/bin/python3
# -*- coding: utf-8 -*-

from copy import copy as _copy
from struct import pack, unpack
from binascii import hexlify
from socket import inet_aton, inet_ntoa
from time import localtime, strftime, time
from mcrptos import AES128, MD5, Icrc16
from json import loads, dumps


class Packet(object):
    def __init__(self, data = None, *args, **kwargs):

        if data is None:
            self.pdata = bytearray()
        elif isinstance(data, (bytes, bytearray)):
            self.pdata = bytearray(data)
        elif isinstance(data, Packet):
            self.pdata = _copy(data.pdata)
        else:
            raise TypeError("bytes or bytearray needed.")

    def get_all(self):
        return self.pdata

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

    def _encode(self):
        raise NotImplementedError("Need to override.")

    def _decode(self):
        raise NotImplementedError("Need to override.")

    def __str__(self):
        hexstr = str(hexlify(self.pdata), 'ascii').upper()
        return ' '.join(hexstr[i:i+2] for i in range(0, len(hexstr), 2))


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
        self._encode()

    def _encode(self):
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
    ase = AES128(frame[0:16])
    ret = MD5(ase[:16])

    """
    TYPE = 1
    def __init__(self, key=None):
        super().__init__()

        if key is None:
            self.key = b'0123456789012345'
        else:
            self.key = key
        self._encode()

    def _encode(self):
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

    def verify(self, data):
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be a byte-like array.")
        if len(data) is not 16*2:
            raise ValueError("data length error.")

        crypto = MD5().digest(AES128(self.key).encrypt(bytes(data[:16]))[:16])
        return crypto == data[16:]


class BacFrame(Packet):
    TYPE = 2
    def __init__(self, data):
        super().__init__(data)


class FcFrame(Packet):
    """
    +--------+--------+--------+-------+
    |         pakcet length            |
    +--------+--------+--------+-------+
    |  flag  | pktid  |   segmentnum   |
    +--------+--------+--------+-------+
    |               DATA               |
    +--------+--------+--------+-------+


    """
    TYPE = 6

    def __init__(self, pkt_len=0, flag=0, pkt_id=0, segment_num=0, data=b'', pkt=None):
        super().__init__(data=pkt)
        if pkt is not None:
            self._decode()
        else:
            self.pkt_len = pkt_len
            self.flag = flag
            self.pkt_id = pkt_id
            self.segment_num = segment_num
            self.data = data
            self._encode()

    def _encode(self):
        self.put_long(self.pkt_len)
        self.put(self.flag)
        self.put(self.pkt_id)
        self.put_short(self.segment_num)
        self.put_data(self.data)

    def _decode(self):
        p = Packet(self)
        self.pkt_len = p.get_long()  # 4
        self.flag = p.get()  # 1
        self.pkt_id = p.get()  # 1
        self.segment_num = p.get_short()  # 2
        self.data = p.get_all()

    def __str__(self):
        return "FcFrame {pkt_len: %d, flag: %d, pkt_id: %d: segment_num: %d}" \
               % (self.pkt_len, self.flag, self.pkt_id, self.segment_num)


dict2json = lambda x: dumps(x)
json2dict = lambda x: loads(x)
cts = lambda t: strftime("%Y-%m-%d %H:%M:%S.", localtime(t)) + "%03d" % ((t-int(t))*1000)
json_idx = {
    "ACK": 0xff,
    "ODR": 0x04,
    "OER": 0x05,
    "CVC": 0x08,
    "ESR": 0x09,
}
json_tpl = {
    # "handshake": {"key": "0123456789012345"}
    # "heartbeat": {"ConnectTime": strftime("%Y-%m-%d %H:%M:%S")}
    "ACK": {"ErrMsg": "",
            "IsSuccess":True,
            "OperationTime": cts(time()),
            "Remark":"",
            "ReplyCommand":1,
            "Wx_FlcNum":120,
            "Wx_buildNum":"F1021"},

    "ODR": {"Wx_DoorName":"2",
            "Wx_DrNumInFlc":12,
            "Wx_DrShowFlr":"11F",
            "Wx_buildNum":"F0000000 ",
            "Wx_FlcNum":111},

    "OER": {"Wx_EleNum":2,
            "WX_Ele_PhysicFlr":12,
            "Wx_EleShowFlr":"11F",
            "Wx_buildNum":"F01231 ",
            "Wx_FlcNum":101},

    "CVC": {"Wx_EleNum":2,
            "WX_Ele_PhysicFlr":12,
            "Wx_EleShowFlr":"11F",
            "Wx_buildNum":"F01231 ",
            "Wx_FlcNum":101 ,
            "WX_Ele_PhysicFlr_dest":11,
            "Wx_EleShowFlr_dest":"10F"},

    "ESR": {"Wx_buildNum":"F01231 ",
            "Wx_FlcNum":101}

}

class WxFrame(Packet):
    """
    frame:
    +--------+--------+--------+--------+--------+--------+
    |  0xAD  | number |     sequence    |     length      |
    +--------+--------+--------+--------+--------+--------+
    |                      JSON (N byte)                  |
    +--------+--------+--------+--------+--------+--------+
    |  XOR   |  0xDA  |
    +--------+--------+

    length = len(number + sequence + JSON) = 5 + N
    XOR = XOR(number + sequence + JSON)

    """
    TYPE = 7
    f_head = 0xAD
    f_tail = 0xDA
    
    def __init__(self, number=0, sequence=0, json=b' ', pkt=None):
        super().__init__(data=pkt)
        if pkt is not None:
            self._decode()
        else:
            self.number = number
            self.sequence = sequence
            self.length = 5 + len(json)
            self.json = json
            self.xor = WxFrame.XOR(number, sequence, self.length, json)
            self._encode()

    def XOR(*args):
        ret = 0
        for a in args:
            if isinstance(a, int):
                b =  a.to_bytes(2, byteorder='big')
                ret ^= b[0] ^ b[1]
            elif isinstance(a, (bytes, bytearray)):
                for b in a:
                    ret ^= b
            else:
                raise ValueError("Value type error.")
        return ret

    def _encode(self):
        self.put(WxFrame.f_head)
        self.put(self.number)
        self.put_short(self.sequence)
        self.put_short(self.length)
        self.put_data(self.json)
        self.put(self.xor)
        self.put(WxFrame.f_tail)

    def _decode(self):
        p = Packet(self)
        p.get() # 0xAD
        self.number = p.get()
        self.sequence = p.get_short()
        self.length = p.get_short()
        self.json = p.get_data(self.length - 5)
        self.xor = p.get()
        p.get() # 0xDA


    def __str__(self):
        return "WxFrame {number=%d, sequence=%d, length=%d, json=%s, xor=%d}" \
               % (self.number, self.sequence, self.length, self.json.decode(), self.xor)


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

    def __init__(self, type=0, id=0, dip=None, dport=0, data=None, pkt=None):
        super().__init__(data=pkt)
        if pkt is not None:
            self._decode()
        else:
            self.length = 30
            self.type = type
            self.id = id
            self.dip = "0.0.0.0" if dip is None else dip
            self.dport = dport
            self.data = b'' if data is None else data
            self.crc = 0
            self._encode()

    def update(self, **kargs):
        for arg in kargs.keys():
            if arg in ("type", "id", "dip", "dport", "data"):
                self.__setattr__(arg, kargs.get(arg))
        self.get_all().clear()
        self._encode()

    def _encode(self):
        self.put_data(Dwrap.IDENTITY)  # identity: 2
        self.length = 30 + len(self.data)
        self.put_short(self.length)  # length: 2
        self.put(self.type)  # type: 1
        self.put_long(self.id)  # id: 4
        self.put_data(inet_aton(self.dip))  # ip: 4
        self.put_short(self.dport)  # port: 2
        self.put_data(bytes(17))  # reserved: 17
        self.put_data(self.data)  # data: n
        self.crc = Icrc16.CRC16(bytes(self.pdata[2:]))
        self.put(self.crc&0xFF)
        self.put((self.crc&0xFF00) >> 8)

    def _decode(self):
        p = Packet(self)  # identity
        p.get_data(2)
        self.length = p.get_short()
        self.type = p.get()
        self.id = p.get_long()
        self.dip = inet_ntoa(p.get_data(4))
        self.dport = p.get_short()
        p.get_data(17)  # reserved
        self.data = p.get_data(self.length-30)
        crcl = p.get()
        crch = p.get()
        self.crc = ((crch & 0xff) << 8) | crcl

    def __str__(self):
        return "Dwarp {length=%d, type=%d, id=%d, ip=%s:%d, crc=0x%02X}" % \
               (self.length, self.type, self.id, self.dip, self.dport, self.crc)


if __name__ == '__main__':

    l = LgiFrame()
    t1 = l.get_all()
    print(t1)
    if l.verify(t1):
        print("OK")

    h3 = HbFrame()
    print(h3)

    sr = Dwrap()
    sr.update(type=1, id=101, dip='10.98.1.178', dport=7894, data=h3.get_all())
    print(sr)

    pkt = sr.get_all()

    nd = Dwrap(pkt=pkt)
    print(nd)

    # cts test
    print(cts(time()))
