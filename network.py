#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncore

SERVER_ADDRESS = ("", 7896)
class PacketDispatcher(asyncore.dispatcher):
    def __init__(self):
        super().__init__(self)
        self.create_socket()
        self.connect(SERVER_ADDRESS)
        self.recv_buf = bytearray()
        self.send_buf = bytearray()
        self.forward_sock = None

    def set_forward_sock(self, sock):
        self.forward_sock = sock

    def packet_send(self, packet):
        self.send_buf += packet

    def forward_packet(self):
        self.forward_sock.forward_packet(self.get_packet())

    def get_packet(self):
        pass

    def has_entire_packet(self):
        pass

    def handle_read(self):
        self.recv_buf += self.recv(100)
        if self.has_packet():
            self.forward_packet()

    def handle_write(self):
        ret = self.send(self.send_buf)
        self.send_buf = self.send_buf[ret:]
