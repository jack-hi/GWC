#!/usr/bin/python3
# -*- coding: utf-8 -*-

import socket
from os import unlink
from os.path import exists
from asyncore import dispatcher, loop as asyncore_loop

class LocalMessageServer(dispatcher):
    def __init__(self, path):
        super().__init__()
        if exists(path): unlink(path)
        self.create_socket(socket.AF_UNIX)
        self.bind(path)
        self.listen(5)

    def handle_accepted(self, sock, addr):
        print(sock)
        print(addr)
        print("accept: " + sock.getsockname())
        sock.close()


class LocalMessageClient(dispatcher):
    def __init__(self, path):
        super().__init__()
        self.create_socket(socket.AF_UNIX)
        self.connect(path)

    def handle_write(self):
        pass

    def handle_read(self):
        pass

    def handle_close(self):
        pass


if __name__ == '__main__':
    LocalMessageServer('/tmp/af-unix')
    LocalMessageClient('/tmp/af-unix')
    try:
        asyncore_loop()
    except KeyboardInterrupt:
        print("Quit.")

