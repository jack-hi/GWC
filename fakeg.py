#!/usr/bin/python3
# -*- coding: utf-8 -*-

import socket
from time import sleep, time
from segment import Dwrap, HbFrame, LgiFrame, BacFrame, WxFrame, FcFrame, Packet
from threading import Thread
from asyncore import dispatcher, loop as asyncore_loop
from commons import init_log, addlog

local_ip = '10.98.1.218'
udp_ifc = ("", 0xBAC0)
udp_msg = list()  # item: (bytes,('xx.xx.xx.xx', port))
frm_buf = list()  # item: (('xx.xx.xx.xx', port), Frame)
running = True

@addlog
class TcpHandler(dispatcher):
    def __init__(self, id, ip, port):
        super().__init__()
        self.create_socket()
        self.connect((ip, port))
        self.sbuf = bytearray()
        self.rbuf = bytearray()

        # status
        self.id = id
        self.authenticated = False
        self.auth_send_flag = False
        self.hb_tsmp = 0.0

    def handle_connect(self):
        TcpHandler._info("Connected to Server.")

    def _decode(self):
        while len(self.rbuf) >= 4:
            if self.rbuf[:2] != bytes([0x55, 0xaa]):
                del self.rbuf[0]
            else:
                break

        if len(self.rbuf) < 4:
            return None

        length = ((self.rbuf[2] & 0x00ff) << 8) | self.rbuf[3]
        if len(self.rbuf) >= 4 + length:
            TcpHandler._debug("Decode a frame, length: 0x%X" % length)
            pkt = self.rbuf[:4 + length]
            del self.rbuf[:4 + length]
            return pkt

        return None

    def _encode(self):
        if len(frm_buf) is not 0:
            (ip, port), frame = frm_buf.pop(0)
            pkt = Dwrap(frame.TYPE, self.id, ip, port, frame.get_packet())
            TcpHandler._info("Encode frame: " + str(pkt))
            return pkt.get_packet()
        else:
            return b''

    def _fakeg_func(self, pkt):
        if pkt is None:
            return

        d = Dwrap().decode(pkt)
        if self.authenticated:
            if d.type == HbFrame.TYPE:
                TcpHandler._info("Received HbFrame:" + str(d))
            elif d.type == BacFrame.TYPE:
                TcpHandler._info("Received BacFram: " + str(d))
                udp_msg.append((d.data, udp_ifc))
            elif d.type == WxFrame.TYPE:
                TcpHandler._info("Received WxFram: " + str(d))
                # TODO
            else:
                TcpHandler._warning("Receive Unkonw frame: " + str(d))
        else:
            if d.type == LgiFrame.TYPE:
                TcpHandler._info("Recvice authentic frame: " + str(d))
                self.authenticated = True
                self.hb_tsmp = time()
            else:
                TcpHandler._warnning("Not authenticated: " + str(d))

    def _send_hbframe(self):
        if self.authenticated:
            cur = time()
            if cur - self.hb_tsmp > 10.0:
                frm_buf.append(((local_ip, 0), HbFrame()))
                self.hb_tsmp = cur

    def handle_read(self):
        buf = self.recv(1024)
        if len(buf) is 0:
            TcpHandler._error("Disconnect from Server.")
            global running
            running = False
            return

        self.rbuf += buf
        self._fakeg_func(self._decode())

    def handle_write(self):
        if len(self.sbuf) is 0:
            if self.authenticated:
                self._send_hbframe()
                self.sbuf += self._encode()
            else:
                if not self.auth_send_flag:
                    frm_buf.append(((local_ip,0), LgiFrame()))
                    self.auth_send_flag = True
                    self.sbuf += self._encode()

        if len(self.sbuf) is not 0:
            ret = self.send(self.sbuf)
            TcpHandler._info("Send to Server: " + self.sbuf[:ret].hex())
            del self.sbuf[:ret]

@addlog
class UdpHandler(dispatcher):
    def __init__(self, port):
        super().__init__()
        self.create_socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.bind((local_ip, port))
        self.smsg = list()
        # self.rmsg = set()

    def handle_read(self):
        data, addr = self.socket.recvfrom(1024)
        UdpHandler._info("Received from %s: %s" % (addr, data.hex()))
        if data[0] == 0x81:
            frame = BacFrame(data)
            frm_buf.append((addr, frame))

    def handle_write(self):
        if len(self.smsg) is 0:
            if len(udp_msg) is 0:
                return
            else:
                self.smsg.append(udp_msg.pop(0))

        if len(self.smsg) is not 0:
            if len(self.smsg[0][0]) is not 0:
                UdpHandler._info("Send to %s: %s" %
                                 (self.smsg[0][1], self.smsg[0][0].hex()))
                ret = self.socket.sendto(*self.smsg[0])
                del self.smsg[0][0][:ret]
            else:
                self.smsg.pop(0)

@addlog
class FakeG(Thread):
    def __init__(self, id, ip, port):
        FakeG._info("Start fakeg....")
        super().__init__(name="FakeG", daemon=True, target=asyncore_loop)
        self.tcp_handler = TcpHandler(id, ip, port)
        self.udp_handler = UdpHandler(0xBAC1)


if __name__ == '__main__':
    init_log('/tmp/fakeg.log')
    FakeG(999, "10.98.1.178", 46060).start()
    while running:
        sleep(1)



# @addlog
# class App(Thread):
#     def __init__(self, id, ip, port, udp_port = 0xbac1):
#         super().__init__()
#         self.running = False
#         self.authenticated = False
#         self.send_heartbeat_flag = False
#         self.id = id
#         self.ip = ip
#         self.port = port
#
#         self.tcpwq = queue.Queue()
#         self.tcprq = queue.Queue()
#         self.tcp_handler = TcpHandler(id, ip, port, self.tcpwq, self.tcprq)
#         self.udp_handler = UdpHandler(udp_port)
#         self.tcp_handler.set_udp_handler(self.udp_handler)
#         self.udp_handler.set_tcp_handler(self.tcp_handler)
#         self._thread = Thread(target=asyncore_loop)
#
#     def is_connect(self):
#         return self.tcp_handler.connected
#
#     def is_authenticated(self):
#         return self.authenticated
#
#     def is_remote_offline(self):
#         return self.tcp_handler.remote_offline
#
#     def send(self, data):
#         if isinstance(data, Packet):
#             pkt = Dwrap(data.TYPE, self.id, self.ip, self.port, data.get_packet())
#             self.tcpwq.put(pkt)
#         else:
#             App._warning("Data type must be Packet.")
#         # if isinstance(data, (bytes, bytearray)):
#         #     self.tcpwq.put(data)
#         # elif isinstance(data, Dwrap):
#         #     self.tcpwq.put(data.get_packet())
#         # else:
#         #     App._warning("Data type error, need bytes or Dwrap.")
#
#     def _send_heartbeat(self):
#         while self.send_heartbeat_flag:
#             if not self.is_connect() or not self.is_authenticated():
#                 time.sleep(10); continue
#
#             # frame = Dwrap(HbFrame.TYPE, app.id, app.ip, app.port,
#             #               HbFrame().get_packet())
#             App._info("Send heartbeat frame.")
#             self.send(HbFrame())
#             time.sleep(10)
#
#     def start_heartbeat_thread(self):
#         if not self.send_heartbeat_flag:
#             self.send_heartbeat_flag = True
#             self.hb_thread = Thread(target=self._send_heartbeat)
#             self.hb_thread.start()
#
#     def authenticate(self):
#         # pkt = Dwrap(LgiFrame.TYPE, self.id, self.ip, self.port,
#         #             LgiFrame().get_packet())
#         App._info("Send Authenticate frame.")
#         self.send(LgiFrame())
#         try:
#             pkt = self.tcprq.get(timeout=10)
#             self.tcprq.task_done()
#             if pkt is not None:
#                 if pkt.type is LgiFrame.TYPE:
#                     if (LgiFrame().verify(pkt.data)):
#                         App._info("Authenticate successed.")
#                         self.authenticated = True
#                 else:
#                     App._warning("Expeced for LgiFrame. but received: %d" % pkt.type)
#             else:
#                 App._warning("Received a frame error packet.")
#         except queue.Empty:
#             App._warning("Waiting for LgiFrame timeout. clear send and try again.")
#             if not self.tcpwq.empty():
#                 self.tcpwq.get()
#                 self.tcpwq.task_done()
#
#     def run(self):
#         while self.running:
#             if not self.is_connect():
#                 time.sleep(1); continue
#
#             if not self.is_authenticated():
#                 self.authenticate()
#             else:
#                 self.start_heartbeat_thread()
#                 # print("TODO")
#
#             if self.is_remote_offline():
#                 # BUG  blocked ...
#                 self.quit()
#
#     def initialize(self):
#         App._info("Start Transport thread.")
#         self._thread.start()
#
#         self.running = True
#         self.start()
#
#     def quit(self):
#         App._info("Quit.")
#         self.send_heartbeat_flag = False
#         self.running = False
#
#
# if __name__ == '__main__':
#     init_debug("/tmp/fake.log")
#     app = App(999, '10.98.1.178', 46060)
#    app.initialize()