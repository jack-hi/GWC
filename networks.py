#!/usr/bin/python3
# -*- coding: utf-8 -*-

import socket
import queue
from asyncore import dispatcher
from commons import debugging
from segment import Dwrap, LgiFrame, HbFrame, BacFrame



@debugging
class TcpHandler(dispatcher):
    def __init__(self, id, ip, port, wq, rq):
        super().__init__()
        self.remote_offline = False
        self.create_socket()
        self.connect((ip, port))
        self.id = id
        self.ip = ip
        self.port = port
        self.recv_buf = bytearray()
        self.send_buf = bytearray()
        # handle received data
        self.packet = None
        # send data
        self.wq = wq
        self.rq = rq
        # forward bacnet
        self.udp_handler = None

    def set_udp_handler(self, udp):
        self.udp_handler = udp

    def _decode(self):
        while len(self.recv_buf) >= 4:
            if self.recv_buf[:2] != bytes([0x55, 0xaa]):
                del self.recv_buf[0]
            else:
                break

        if len(self.recv_buf) < 4:
            return self

        length = ((self.recv_buf[2] & 0x00ff) << 8) | self.recv_buf[3]
        if len(self.recv_buf) >= 4 + length:
            TcpHandler._debug("Decode a frame, length: 0x%X" % length)
            self.packet = self.recv_buf[:4+length]
            del self.recv_buf[:4+length]

        return self

    def _handler(self):
        if self.packet is not None:
            # App._info("Received frame: %s..." % self.packet[:15].hex())
            pkt = Dwrap().decode(self.packet)
            if pkt is None:
                return
            type = pkt.type
            if type == LgiFrame.TYPE or type == HbFrame.TYPE:
                TcpHandler._info("Handle: lgi/hb, %s" % str(pkt))
                self.rq.put(pkt)
            elif type == BacFrame.TYPE:
                TcpHandler._info("Handle: Bacnet/IP message: %s" % str(pkt))
                self.udp_handler.send_queue.append((pkt.data, ("10.98.1.218", 0xBAC0)))
            else:
                TcpHandler._info("Handle: %s" % str(pkt))
                # TODO
            self.packet = None

    def handle_connect(self):
        TcpHandler._info("Connected to " + str(self.socket.getpeername()))

    def handle_read(self):
        buf = self.recv(100)
        if len(buf) is 0:
            TcpHandler._error("**Disconnect from server**")
            self.remote_offline = True
            return
        self.recv_buf += buf
        self._decode()._handler()

    def handle_write(self):
        if len(self.send_buf) is 0:
            try:
                pkt = self.wq.get_nowait()
                self.wq.task_done()
                self.send_buf += pkt.get_all()
            except queue.Empty:
                return
        if len(self.send_buf):
            ret = self.send(self.send_buf)
            TcpHandler._debug("Sent: " + self.send_buf[0:ret].hex())
            del self.send_buf[:ret]

@debugging
class UdpHandler(dispatcher):
    def __init__(self, port):
        super().__init__()
        self.create_socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.bind(('', port))
        self.recv_queue = set() # item: {addr: message}
        self.send_queue = list() # item: [message, addr]
        # tcp handler
        self.tcp_handler = None

    def set_tcp_handler(self, tcp):
        self.tcp_handler = tcp

    def handle_read(self):
        data, addr = self.socket.recvfrom(1024)
        # if self.recv_queue.get(addr) is None:
        #     self.recv_queue[addr] = bytearray(data)
        # else:
        #     self.recv_queue[addr] += data
        bac = BacFrame(data)
        UdpHandler._info("Received BACnet/IP data: %s, addr: %s" % (str(bac), addr))
        pkt = Dwrap(BacFrame.TYPE, self.tcp_handler.id,
                    self.tcp_handler.ip, self.tcp_handler.port,
                    bac.get_all()).get_all()
        self.tcp_handler.send_buf += pkt

    def handle_write(self):
        if len(self.send_queue) == 0:
            return
        if len(self.send_queue[0][0]) == 0:
            self.send_queue.pop(0)
            return
        UdpHandler._info("Send BACnet/IP data: %s" % str(self.send_queue[0]))
        ret = self.socket.sendto(*self.send_queue[0])
        del self.send_queue[0][0][0:ret]
