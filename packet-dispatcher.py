#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncore
import socket
import logging
import queue
import time
from segment import Dwrap, HbFrame, LgiFrame, BacFrame, WxFrame, FcFrame
from threading import Thread, Timer

Log = logging.getLogger("App0")
Log.setLevel(logging.DEBUG)
s_handler = logging.StreamHandler()  # sys.stderr
s_handler.setLevel(logging.DEBUG)
s_handler.setFormatter(logging.Formatter("%(asctime)s %(name)s [%(levelname)s] %(funcName)s(): %(message)s"))
Log.addHandler(s_handler)
f_handler = logging.FileHandler("app.log")
f_handler.setLevel(logging.DEBUG)
f_handler.setFormatter(logging.Formatter("%(asctime)s %(name)s [%(levelname)s] %(module)s:%(funcName)s(): %(message)s"))
Log.addHandler(f_handler)


class TcpHandler(asyncore.dispatcher):
    def __init__(self, ip, port, wq, rq):
        super().__init__()
        self.create_socket()
        self.connect((ip, port))
        self.recv_buf = bytearray()
        self.send_buf = bytearray()
        # handle received data
        self.wfhd = None
        self._dec_func = None
        # send data
        self.wq = wq
        self.rq = rq

    def set_decode(self, func):
        self._dec_func = func

    def decode(self):
        if self._dec_func is not None:
            len, self.wfhd = self._dec_func(self.recv_buf)
            del self.recv_buf[:len]
        else:
            self.wfhd = self.recv_buf[:]
            del self.recv_buf[:]
        return self

    def handler(self):
        if self.wfhd is not None:
            self.rq.put(self.wfhd)
            Log.info("Handled: " + self.wfhd.hex())
            self.wfhd = None

    def handle_read(self):
        buf = self.recv(100)
        if len(buf) is 0:
            Log.error("**Disconnect from server**")
            return
        self.recv_buf += buf
        Log.debug("Received: " + self.recv_buf.hex())
        self.decode().handler()

    def handle_write(self):
        if len(self.send_buf) is 0:
            try:
                self.send_buf += self.wq.get_nowait()
                self.wq.task_done()
            except queue.Empty:
                return
        if len(self.send_buf):
            ret = self.send(self.send_buf)
            Log.debug("Sent: " + self.send_buf[0:ret].hex())
            del self.send_buf[:ret]


class UdpHandler(asyncore.dispatcher):
    def __init__(self, port):
        super().__init__()
        self.create_socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.bind(('', port))
        self.recv_queue = set() # item: {addr: message}
        self.send_queue = list() # item: [message, addr]

    def handle_read(self):
        data, addr = self.socket.recvfrom(100)
        if self.recv_queue.get(addr) is None:
            self.recv_queue[addr] = bytearray(data)
        else:
            self.recv_queue[addr] += data

    def handle_write(self):
        if len(self.send_queue) == 0:
            return
        if len(self.send_queue[0][0]) == 0:
            self.send_queue.pop(0)
            return
        ret = self.socket.sendto(*self.send_queue[0])
        del self.send_queue[0][0][0:ret]


class App(Thread):
    def __init__(self, ip, port, udp_port = 0xbac0):
        super().__init__()
        self.running = False
        self.auth = False
        self.state =
        self.ip = ip
        self.port = port

        self.tcpwq = queue.Queue()
        self.tcprq = queue.Queue()
        self.tcp_handler = TcpHandler(ip, port, self.tcpwq, self.tcprq)
        # self.udp_handler = UdpHandler(udp_port)
        self._thread = Thread(target=asyncore.loop)

    def send(self, data):
        self.tcpwq.put(data)

    def run(self):
        while self.running:
            if not self.tcp_handler.connected:
                time.sleep(1); continue

            if not self.auth:
                pkt = Dwrap(LgiFrame.TYPE, 999, self.ip, self.port)
                pkt.update(data=LgiFrame().get_packet())
                self.send(pkt.get_packet())
                try:
                    item = self.tcprq.get(timeout=10)
                    self.tcprq.task_done()
                    pkt = Dwrap().decode(item)
                    if pkt is not None:
                        if pkt.type is LgiFrame.TYPE:
                            if (LgiFrame().verify(pkt.data))
                                self.auth = True
                                Log.info("Authenticate successed.")
                        else:
                            Log.warning("Expeced for LgiFrame. but received: %d" % pkt.type)
                    else:
                        Log.warning("Received a frame error packet.")
                except queue.Empty:
                    Log.warning("Waiting for LgiFrame timeout. clear send and try again.")
                    if not self.tcpwq.empty():
                        self.tcpwq.get()
                        self.tcpwq.task_done()
                    continue
            else:
                # send HbFrame Timer
                # handle received packet



    def initialize(self):
        Log.info("Start Transport thread.")
        self._thread.start()

        self.running = True
        self.start()


if __name__ == '__main__':
    app = App('10.98.1.178', 46060)
    app.initialize()