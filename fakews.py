#!/usr/bin/python3
# -*- coding: utf-8 -*-

import socket
from asyncore import dispatcher, loop as asyncore_loop
from segment import WxFrame, json2dict, dict2json, json_tpl
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
    ending = bytes([0xFB, 0xFC, 0xFD, 0xFE, 0xFF])
    def __init__(self, sock):
        super().__init__(sock=sock)
        self.frms = list() # frames waiting for send.
        self.sbuf = bytearray()
        self.rbuf = bytearray()

    def handle_write(self):
        if len(self.sbuf) is 0:
            if len(self.frms) is 0:
                return
            self.sbuf += self._encode(self.frms.pop(0))
        ret = self.send(self.sbuf)
        del self.sbuf[:ret]

    def handle_read(self):
        buf = self.recv(1024)
        if len(buf) is 0:
            Wservice._warning("Client connection closed.")
            return
        Wservice._info("Received: %s" % str(buf.hex()))
        self.rbuf += buf
        self._service(self._decode())

    def _encode(self, frame):
         return frame.get_all() + Wservice.ending

    def _decode(self):
        if len(self.rbuf) < 5:
            return b''

        index = 0
        while len(self.rbuf[index:]) >= 5:
            if self.rbuf[index:index+5] != Wservice.ending:
                index += 1
            else:
                ret = self.rbuf[:index]
                del self.rbuf[:index+5]
                return ret
        return b''

    def _service(self, data):
        if len(data) is 0:
            return

        frame = WxFrame(pkt=data)
        rjs = frame.json.decode(encoding="utf-8")
        Wservice._info("INST: " + rjs)
        rj = json2dict(rjs)
        ack = json_tpl['ACK']
        for key in ack.keys():
            ack[key] = rj.get(key) if rj.get(key) is not None else ack[key]
        Wservice._info("ACK: " + dict2json(ack))
        self.frms.append(WxFrame(255, frame.sequence, dict2json(ack).encode()))

if __name__ == "__main__":
    init_log('/tmp/wx.log')
    WxServer("", 12345)
    asyncore_loop()