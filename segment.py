#!/usr/bin/python3
# -*- coding: utf-8 -*-

from utils import Packet

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
        self.get() # identity: 0x88
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
        tmp += "\nidentity: 0x{:x}\n" \
               "flags: {}\n" \
               "length: {}\n" \
               "packet_id: {}\n" \
               "segment_num: {}".format(self.identity,
                                        self.flags,
                                        self.length,
                                        self.packet_id,
                                        self.seq)
        return tmp

import socket
if __name__ == '__main__':
    seg = Segment()
    seg.update(8, 1000, 2, [i for i in range(0, 10)])
    seg.encode()
    print(seg)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #sock.bind(('', ))
        #sock.sendto(t.encode(), ('10.98.1.235', 0xbacb))
        sock.connect(('10.98.1.178', 7894))
        sock.send(seg.get_all())

        while True:
            data, addr = sock.recvfrom(100)
            ack = Segment()
            ack.put_data(data)
            print(ack)
            print(ack.decode())

