#!/usr/bin/python3
# -*- coding: utf-8 -*-

import socket
from segment import LgiFrame, Dwrap
 
HOST = ''
PORT = 41400

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(1)
    print(f"Start TCP server at {sock.getsockname()}")
    while 1:
        conn, addr = sock.accept()
        while conn:
            data = conn.recv(100)
            print(data.hex())
            pkt = Dwrap().decode(data)
            if pkt is not None:
                if pkt.type == LgiFrame.TYPE:
                    if LgiFrame().verify(pkt.data):
                        pkt.update(data = LgiFrame().encode().get_all())
                        conn.send(pkt.encode().get_all())

