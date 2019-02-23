#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncore
from segment import Segment
import socket
import threading

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

    def handle_read(self):
        self.recv_buf += self.recv(100)

    def handle_write(self):
        if len(self.send_buf) == 0:
            return
        ret = self.send(self.send_buf)
        self.send_buf = self.send_buf[ret:]


class UdpHandler(asyncore.dispatcher):
    def __init__(self, port):
        self.create_socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.bind(('', port))
        self.recv_buf = bytearray()
        self.send_buf = bytearray()
        self.cli = None

    def handle_read(self):
        rd, self.cli = self.socket.recvfrom(100)
        # TODO with received data

    def handle_write(self):
        if len(self.send_buf) == 0:
            return
        ret = self.socket.sendto(self.send_buf, self.cli)
        self.send_buf = self.send_buf[ret:]


if __name__ == '__main__':
    asyncore.loop()
