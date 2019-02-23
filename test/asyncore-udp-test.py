#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncore
import socket
import threading


class UDPServer(asyncore.dispatcher):
    def __init__(self):
        super().__init__()
        self.create_socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.bind(('', 0xbac1))
        self.cli = None
        self.send_buf = bytearray()

    def handle_read(self):
        data, addr = self.socket.recvfrom(100)
        print(f'server recv: {addr}, data {data}')
        self.cli = addr
        self.send_buf += b'i am received: ' + data

    def handle_write(self):
        if len(self.send_buf) == 0:
            return
        ret = self.socket.sendto(self.send_buf, self.cli)
        self.send_buf = self.send_buf[ret:]


class UDPClient(asyncore.dispatcher):
    def __init__(self):
        super().__init__()
        self.create_socket(socket.AF_INET, socket.SOCK_DGRAM)

    def handle_read(self):
        data, addr = self.socket.recvfrom(100)
        print(f'client recv:{addr}, data {data}')


if __name__ == '__main__':
    server = UDPServer()
    client = UDPClient()
    client.socket.sendto(b'hello async UDP server', ("", 0xbac1))
    # threading.Thread(target=asyncore.loop,daemon=True).start()
    threading.Thread(target=asyncore.loop).start()

    import time
    time.sleep(1)
    print("Start asyncore UDP test")
