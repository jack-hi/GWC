#!/usr/bin/python3
# -*- coding: utf-8 -*-

import socket
from asyncore import dispatcher, loop as asyncore_loop
from segment import WxFrame, json2dict, dict2json
from commons import addlog, init_log


@addlog
class WxServer(dispatcher):
    def __init__(self, ip, port):
        super().__init__()
        self.create_socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.bind((ip, port))
        self.listen(5)
        WxServer._info("Start WxServer ...")

    def handle_accepted(self, sock, addr):
        WxServer._info("Accept client: " + str(addr))
        Wservice(sock)


@addlog
class Wservice(dispatcher):
    def __init__(self, sock):
        super().__init__(sock=sock)
        self.sbuf = bytearray()
        self.rbuf = bytearray()

    def handle_write(self):
        if len(self.sbuf) is 0:
            return
        else:
            ret = self.send(self.sbuf)
            del self.sbuf[:ret]

    def handle_read(self):
        ret = self.recv(1024)
        if len(ret) is 0:
            Wservice._warning("Client connection closed.")
            return
        Wservice._info("Received: %s" % ret.decode())


if __name__ == "__main__":
    init_log('/tmp/wx.log')
    WxServer("", 12345)
    asyncore_loop()