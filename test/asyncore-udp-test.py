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
        self.send_buf = []
        self.recv_buf = {}

    def handle_read(self):
        data, addr = self.socket.recvfrom(100)
        print(f'server recv: {addr}, data {data}')
        # TODO send
        if self.recv_buf.get(addr) is None:
            self.recv_buf[addr] = bytearray(data)
        else:
            self.recv_buf[addr] += data

        sd = b'received: ' + data
        self.send_buf.append([sd, addr])

    def handle_write(self):
        if len(self.send_buf) == 0:
            return
        if len(self.send_buf[0][0]) == 0:
            self.send_buf.pop(0)
            return
        ret = self.socket.sendto(*self.send_buf[0])
        # self.send_buf[0][0] = self.send_buf[0][0][ret:]
        del self.send_buf[0][0][:ret]


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
    print("Start asyncore UDP test")
    # threading.Thread(target=asyncore.loop,daemon=True).start()
    threading.Thread(target=asyncore.loop).start()



