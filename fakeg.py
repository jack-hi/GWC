#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncore
import socket
import logging
import queue
import time
from segment import Dwrap, HbFrame, LgiFrame, BacFrame, WxFrame, FcFrame, Packet
from threading import Thread, Timer

Log = logging.getLogger("App0")
Log.setLevel(logging.DEBUG)
s_handler = logging.StreamHandler()  # sys.stderr
s_handler.setLevel(logging.INFO)
s_handler.setFormatter(logging.Formatter(
    "%(asctime)s %(name)s [%(levelname)s] %(filename)s:%(funcName)s() %(message)s"))
Log.addHandler(s_handler)
f_handler = logging.FileHandler("app.log")
f_handler.setLevel(logging.DEBUG)
f_handler.setFormatter(logging.Formatter(
    "%(asctime)s %(name)s [%(levelname)s] %(filename)s:%(funcName)s() %(message)s"))
Log.addHandler(f_handler)


class TcpHandler(asyncore.dispatcher):
    def __init__(self, id, ip, port, wq, rq):
        super().__init__()
        self.remote_offline = False
        self.create_socket()
        self.connect((ip, port))
        self.id = id
        self.ip = ip
        self.port = port
        self.recv_buf = bytearray()
        self.send_buf = bytearray()
        # handle received data
        self.packet = None
        # send data
        self.wq = wq
        self.rq = rq
        # forward bacnet
        self.udp_handler = None

    def set_udp_handler(self, udp):
        self.udp_handler = udp

    def _decode(self):
        while len(self.recv_buf) >= 4:
            if self.recv_buf[:2] != bytes([0x55, 0xaa]):
                del self.recv_buf[0]
            else:
                break

        if len(self.recv_buf) < 4:
            return self

        length = ((self.recv_buf[2] & 0x00ff) << 8) | self.recv_buf[3]
        if len(self.recv_buf) >= 4 + length:
            Log.debug("Decode a frame, length: 0x%X" % length)
            self.packet = self.recv_buf[:4+length]
            del self.recv_buf[:4+length]

        return self

    def _handler(self):
        if self.packet is not None:
            # Log.info("Received frame: %s..." % self.packet[:15].hex())
            pkt = Dwrap().decode(self.packet)
            if pkt is None:
                return
            type = pkt.type
            if type == LgiFrame.TYPE or type == HbFrame.TYPE:
                Log.info("Handle: lgi/hb, %s" % str(pkt))
                self.rq.put(pkt)
            elif type == BacFrame.TYPE:
                 Log.info("Handle: Bacnet/IP message: %s" % str(pkt))
                 self.udp_handler.send_queue.append((pkt.data, ("10.98.1.218", 0xBAC0)))
            else:
                Log.info("Handle: %s" % str(pkt))
                # TODO
            self.packet = None

    def handle_connect(self):
        Log.info("Connected to " + str(self.socket.getpeername()))

    def handle_read(self):
        buf = self.recv(100)
        if len(buf) is 0:
            Log.error("**Disconnect from server**")
            self.remote_offline = True
            return
        self.recv_buf += buf
        self._decode()._handler()

    def handle_write(self):
        if len(self.send_buf) is 0:
            try:
                pkt = self.wq.get_nowait()
                self.wq.task_done()
                self.send_buf += pkt.get_packet()
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
        # tcp handler
        self.tcp_handler = None

    def set_tcp_handler(self, tcp):
        self.tcp_handler = tcp

    def handle_read(self):
        data, addr = self.socket.recvfrom(1024)
        # if self.recv_queue.get(addr) is None:
        #     self.recv_queue[addr] = bytearray(data)
        # else:
        #     self.recv_queue[addr] += data
        bac = BacFrame(data)
        Log.info("Received BACnet/IP data: %s" % str(bac))
        pkt = Dwrap(BacFrame.TYPE, self.tcp_handler.id,
                    self.tcp_handler.ip, self.tcp_handler.port,
                    bac.get_packet()).get_packet()
        self.tcp_handler.send_buf += pkt

    def handle_write(self):
        if len(self.send_queue) == 0:
            return
        if len(self.send_queue[0][0]) == 0:
            self.send_queue.pop(0)
            return
        Log.info("Send BACnet/IP data: %s" % str(self.send_queue[0]))
        ret = self.socket.sendto(*self.send_queue[0])
        del self.send_queue[0][0][0:ret]


class App(Thread):
    def __init__(self, id, ip, port, udp_port = 0xbac1):
        super().__init__()
        self.running = False
        self.authenticated = False
        self.send_heartbeat_flag = False
        self.id = id
        self.ip = ip
        self.port = port

        self.tcpwq = queue.Queue()
        self.tcprq = queue.Queue()
        self.tcp_handler = TcpHandler(id, ip, port, self.tcpwq, self.tcprq)
        self.udp_handler = UdpHandler(udp_port)
        self.tcp_handler.set_udp_handler(self.udp_handler)
        self.udp_handler.set_tcp_handler(self.tcp_handler)
        self._thread = Thread(target=asyncore.loop)

    def is_connect(self):
        return self.tcp_handler.connected

    def is_authenticated(self):
        return self.authenticated

    def is_remote_offline(self):
        return self.tcp_handler.remote_offline

    def send(self, data):
        if isinstance(data, Packet):
            pkt = Dwrap(data.TYPE, self.id, self.ip, self.port, data.get_packet())
            self.tcpwq.put(pkt)
        else:
            Log.warning("Data type must be Packet.")
        # if isinstance(data, (bytes, bytearray)):
        #     self.tcpwq.put(data)
        # elif isinstance(data, Dwrap):
        #     self.tcpwq.put(data.get_packet())
        # else:
        #     Log.warning("Data type error, need bytes or Dwrap.")

    def _send_heartbeat(self):
        while self.send_heartbeat_flag:
            if not self.is_connect() or not self.is_authenticated():
                time.sleep(10); continue

            # frame = Dwrap(HbFrame.TYPE, app.id, app.ip, app.port,
            #               HbFrame().get_packet())
            Log.info("Send heartbeat frame.")
            self.send(HbFrame())
            time.sleep(10)

    def start_heartbeat_thread(self):
        if not self.send_heartbeat_flag:
            self.send_heartbeat_flag = True
            self.hb_thread = Thread(target=self._send_heartbeat)
            self.hb_thread.start()

    def authenticate(self):
        # pkt = Dwrap(LgiFrame.TYPE, self.id, self.ip, self.port,
        #             LgiFrame().get_packet())
        Log.info("Send Authenticate frame.")
        self.send(LgiFrame())
        try:
            pkt = self.tcprq.get(timeout=10)
            self.tcprq.task_done()
            if pkt is not None:
                if pkt.type is LgiFrame.TYPE:
                    if (LgiFrame().verify(pkt.data)):
                        Log.info("Authenticate successed.")
                        self.authenticated = True
                else:
                    Log.warning("Expeced for LgiFrame. but received: %d" % pkt.type)
            else:
                Log.warning("Received a frame error packet.")
        except queue.Empty:
            Log.warning("Waiting for LgiFrame timeout. clear send and try again.")
            if not self.tcpwq.empty():
                self.tcpwq.get()
                self.tcpwq.task_done()

    def run(self):
        while self.running:
            if not self.is_connect():
                time.sleep(1); continue

            if not self.is_authenticated():
                self.authenticate()
            else:
                self.start_heartbeat_thread()
                # print("TODO")

            if self.is_remote_offline():
                # BUG  blocked ...
                self.quit()

    def initialize(self):
        Log.info("Start Transport thread.")
        self._thread.start()

        self.running = True
        self.start()

    def quit(self):
        Log.info("Quit.")
        self.send_heartbeat_flag = False
        self.running = False


if __name__ == '__main__':
    app = App(999, '10.98.1.178', 46060)
    app.initialize()