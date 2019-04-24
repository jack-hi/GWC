#!/usr/bin/python3
# -*- coding: utf-8 -*-

import socket
from struct import unpack
from pickle import loads
from logging import makeLogRecord, root
from asyncore import dispatcher, loop as asyncore_loop


class LogTCPServer(dispatcher):
    def __init__(self, ip, port):
        super().__init__()
        self.create_socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.bind((ip, port))
        self.listen(5)
        print("Start LogTCPServer @ %s ..." % str(self.socket.getsockname()))

    def handle_accepted(self, sock, addr):
        print("Accept a client: %s" % str(addr))
        LogService(sock)


class LogService(dispatcher):
    def __init__(self, sock):
        super().__init__(sock=sock)
        self.rbuf = bytearray()

    def handle_read(self):
        buf = self.recv(1024)
        if len(buf) is 0: return

        self.rbuf += buf
        self._service(self._decode())

    def handle_close(self):
        print("Client closed...")
        self.close()

    def _decode(self):
        if len(self.rbuf) < 4: return b''

        length = unpack('>L', self.rbuf[:4])[0]
        if len(self.rbuf) < 4+length: return b''

        ret = self.rbuf[4: 4+length]
        del self.rbuf[:4+length]
        return ret

    def _service(self, data):
        if len(data) is 0: return

        record = loads(data)
        # root.handle(makeLogRecord(record))
        print(record)


if __name__ == '__main__':
    LogTCPServer("", 41400)

    try:
        asyncore_loop()
    except KeyboardInterrupt:
        print('Quit')


