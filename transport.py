#!/usr/bin/python3
# -*- coding: utf-8 -*-


from segment import Segment
import time

class Transport:
    """
    Base class for Transport
    """
    def __init__(self, network):
        self.network = network

    def send(self, addr, data):
        raise NotImplemented("Abstract method")

    def incoming(self, addr, data):
        raise NotImplemented("Abstract method")

class SegmentNode:
    """
    Segment node is the transport unit
    """
    TIMEOUT = 5
    RETRIES = 3
    def __init__(self, segment, timeout=TIMEOUT, retries=RETRIES):
        self.deadline = time.time() + timeout
        self.timeout = timeout
        self.retries = retries
        self.segment = segment

    def is_timeout(self):
        return self.deadline < time.time()

class PacketSendCtx:
    """
    Packet Send context
    """
    def __init__(self, packet, packet_id):
        self.packet = packet
        self.packet_id  = packet_id
        self.seg_size = 512
        self.segnum = 0
        self.segments = []

    def get_next_segment(self)
        if len(self.packet) == 0:
            return None
        flags = 0
        sn = self.segnum
        self.segnum += 1
        segment = Segment()
        if len(self.packet) > self.seg_size:
            flags |= 0x02
            data = self.packet[:self.seg_size]
            del self.packet[:self.seg_size]
        else:
            data = self.packet[:]
            del self.packet[:]
        segment.update(flags, self.packet_id, sn, data).encode()
        self.segments.append(SegmentNode(segment))
        return segment



class SegmentTransport(Transport):
    """
    Segment Transport
    """
    def __init__(self, network):
        super().__init__(network)
        self.packet_id = 0
        self.send_ctx = {}

    def get_packet_id(self):
        if self.packet_id > 0xffff:
            self.packet_id = 0
        self.packet_id += 1
        return self.packet_id

    def send(self, addr, data):
        packet_id = self.get_packet_id()
        key = addr + (packet_id,)
        ctx = PacketSendCtx(data, packet_id)
        self.send_ctx[key] = ctx
        segment = ctx.get_next_segment()
        self.network.send(segment)

    def incoming(self, addr, data):
        pass




