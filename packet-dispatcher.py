#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncore
from segment import Segment
import socket
import threading
import struct

SERVER_ADDRESS = ("", 7896)


class PacketDispatcher():
    """
         TCP <------> UDP
    """
    def __init__(self, ip, port):
        self.tcp_handler = TcpHandler(ip, port)
        self.udp_handler = UdpHandler(port)
        self._thread = threading.Thread(target=asyncore.loop)

    def start(self):
        self._thread.start()


class TcpHandler(asyncore.dispatcher):
    def __init__(self, ip, port):
        super().__init__()
        self.create_socket()
        self.connect((ip, port))
        self.recv_buf = bytearray()
        self.send_buf = bytearray()
        self.udp_handler = None

    def set_udp_handler(self, sock):
        self.udp_handler = sock

    def _forward_packet(self):
        """
        Get a segment packet, forward using udphandler
        """
        als = self.recv_buf
        while len(als) > 0 and als[0] != Segment.INDENTITY:
            als.pop(0)
        if len(als) < 4:
            return
        length = struct.unpack('>H', als[2:4])[0]
        if len(als) < length:
            return
        # TODO segment
        segment = Segment(als[:len])
        del als[:len]
        print(segment)
        self.udp_handler.send_queue.append([segment.get_all(), ('', 0xbac1)])


    def handle_read(self):
        self.recv_buf += self.recv(100)
        self._forward_packet()

    def handle_write(self):
        if len(self.send_buf) == 0:
            return
        ret = self.send(self.send_buf)
        self.send_buf = self.send_buf[ret:]


class UdpHandler(asyncore.dispatcher):
    def __init__(self, port):
        super().__init__()
        self.create_socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.bind(('', port))
        self.recv_queue = {}
        self.send_queue = [
        self.tcp_handler = None

    def set_tcp_handler(self, sock):
            self.tcp_handler = sock

    def _forward_packet(self):
        for addr, data in self.recv_queue.items():
            while len(data) > 0 and data[0] != Segment.INDENTITY:
                data.pop(0)
            if len(data) < 4:
                continue
            length = struct.unpack('>H', data[2:4])[0]
            if len(data) < length:
                continue
            self.tcp_handler.send_buf += data[:length]
            del data[:length]

    def handle_read(self):
        data, addr = self.socket.recvfrom(100)
        if self.recv_queue.get(addr) is None:
            self.recv_queue[addr] = bytearray(data)
        else:
            self.recv_queue[addr] += data

        self._forward_packet()



        # TODO received data

    def handle_write(self):
        if len(self.send_queue) == 0:
            return
        if len(self.send_queue[0][0]) == 0:
            self.send_queue.pop(0)
            return
        ret = self.socket.sendto(*self.send_queue[0])
        # self.send_queue[0][0] = self.send_queue[0][0][ret:]
        del self.send_queue[0][0][0:ret]


if __name__ == '__main__':
    asyncore.loop()
