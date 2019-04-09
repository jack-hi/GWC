#!/usr/bin/python3
# -*- coding: utf-8 -*-

import queue
import time
from segment import Dwrap, HbFrame, LgiFrame, BacFrame, WxFrame, FcFrame, Packet
from threading import Thread
from networks import TcpHandler, UdpHandler
from asyncore import loop as asyncore_loop
from commons import debugging

@debugging
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
        self._thread = Thread(target=asyncore_loop)

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
            App._warning("Data type must be Packet.")
        # if isinstance(data, (bytes, bytearray)):
        #     self.tcpwq.put(data)
        # elif isinstance(data, Dwrap):
        #     self.tcpwq.put(data.get_packet())
        # else:
        #     App._warning("Data type error, need bytes or Dwrap.")

    def _send_heartbeat(self):
        while self.send_heartbeat_flag:
            if not self.is_connect() or not self.is_authenticated():
                time.sleep(10); continue

            # frame = Dwrap(HbFrame.TYPE, app.id, app.ip, app.port,
            #               HbFrame().get_packet())
            App._info("Send heartbeat frame.")
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
        App._info("Send Authenticate frame.")
        self.send(LgiFrame())
        try:
            pkt = self.tcprq.get(timeout=10)
            self.tcprq.task_done()
            if pkt is not None:
                if pkt.type is LgiFrame.TYPE:
                    if (LgiFrame().verify(pkt.data)):
                        App._info("Authenticate successed.")
                        self.authenticated = True
                else:
                    App._warning("Expeced for LgiFrame. but received: %d" % pkt.type)
            else:
                App._warning("Received a frame error packet.")
        except queue.Empty:
            App._warning("Waiting for LgiFrame timeout. clear send and try again.")
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
        App._info("Start Transport thread.")
        self._thread.start()

        self.running = True
        self.start()

    def quit(self):
        App._info("Quit.")
        self.send_heartbeat_flag = False
        self.running = False


if __name__ == '__main__':
    app = App(999, '10.98.1.178', 46060)
    app.initialize()