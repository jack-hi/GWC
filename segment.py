#!/usr/bin/python3
# -*- coding: utf-8 -*-


from copy import copy as _copy
from struct import pack, unpack
from binascii import hexlify


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
        raise NotImplemented("Abstract Method")

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


class Segment(Packet):
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

    INDENTITY = 0x88

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
        self.length = 8 if data == None else 8 + len(data)
        self.packet_id = id
        self.seq = seq
        self.data = data

    def encode(self):
        self.put(self.identity)
        self.put(self.flags)
        self.put_short(self.length)
        self.put_short(self.packet_id)
        self.put_short(self.seq)
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


class SimpleWrap(Packet):
    """
    " simple wrap
    " +------+------+-------------+
    " | 0x8e | 0x8f |    length   |
    " +------+------+-------------+
    " | type |
    " +---------------------------+
    " |      dispatcherId         |
    " +---------------------------+
    " |          ip               |
    " +-------------+-------------+
    " |    port     |
    " +-------------+-------------+
    " |           DATA            |
    " +---------------------------+
    """
    IDENTITY = [0x8e, 0x8f]
    def __init__(self):
        super().__init__()
        self.length = None
        self.type = None
        self.daddr = None #IP:PORT

if __name__ == '__main__':
    seg = Segment()
    seg.update(8, 1000, 2, [i for i in range(0, 10)])
    seg.encode()
    print(seg)
    '''
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # sock.bind(('', ))
        # sock.sendto(t.encode(), ('10.98.1.235', 0xbacb))
        sock.connect(('10.98.1.178', 7894))
        sock.send(seg.get_all())

        while True:
            buf, addr = sock.recvfrom(100)
            ack = Segment()
            ack.put_data(buf)
            print(ack)
            print(ack.decode())
    '''

