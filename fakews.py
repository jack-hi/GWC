#!/usr/bin/python3
# -*- coding: utf-8 -*-

import socket
from asyncore import dispatcher, loop as asyncore_loop
from segment import WxFrame, json2dict, dict2json, json_tpl, json_idx
from commons import addlog, init_log
from threading import Thread, Lock
from time import sleep


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
        self.frms_lock = Lock()
        self.sbuf = bytearray()
        self.rbuf = bytearray()

    def send_frame(self, frame):
        with self.frms_lock:
            self.frms.append(frame)

    def _get_frame(self):
        with self.frms_lock:
            frame = self.frms.pop(0) if len(self.frms) > 0 else None
        return frame

    def handle_write(self):
        if len(self.sbuf) is 0:
            self.sbuf += self._encode(self._get_frame())
        if len(self.sbuf) > 0:
            ret = self.send(self.sbuf)
            del self.sbuf[:ret]

    def handle_read(self):
        buf = self.recv(1024)
        if len(buf) is 0: return
        Wservice._info("Received: %s" % str(buf.hex()))
        self.rbuf += buf
        self._service(self._decode())

    def handle_close(self):
        Wservice._warning("Client connection closed.")
        global mock_thread_running
        mock_thread_running = False

        self.close()

    def _encode(self, frame):
        return b'' if frame is None else (frame.get_all()+Wservice.ending)

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
        rj = json2dict(rjs)
        if frame.number is 0x01:  # hs
            Wservice._info("Received HS: " + rjs)
            self._generate_ack(frame, rj)
            # start sending mock insts.
            global mock_thread, mock_thread_running
            if mock_thread is None:
                mock_thread = Thread(target=mock_inst, args=[self], daemon=True)
                mock_thread_running = True
                mock_thread.start()
        elif frame.number is 0x02:  # hb
            Wservice._info("Received HB: " + rjs)
            self._generate_ack(frame, rj)
        elif frame.number is 0xff:  # ack
            Wservice._info("Received ACK: " + rjs)
        else:
            Wservice._info("Unknow inst: " + rjs)

    def _generate_ack(self, frame, rj, is_success=True, err_msg=""):
        ack = json_tpl['ACK']

        for key in ack.keys():
            ack[key] = rj.get(key) if rj.get(key) is not None else ack[key]

        ack["IsSuccess"] = is_success
        ack["ErrMsg"] = err_msg

        Wservice._info("Reply ACK: " + dict2json(ack))
        self.send_frame(WxFrame(0xff, frame.sequence, dict2json(ack).encode()))


mock_thread  = None
mock_thread_running = False
@addlog
def mock_inst(*args, **kwargs):
    ws = args[0]
    seq = 0
    insts = ("ODR", "OER", "CVC", "ESR")
    while mock_thread_running:
        for key in insts:
            if not mock_thread_running: break
            sj = json_tpl[key]
            # sj["Wx_buildNum"] = "F0001231"
            sj["Wx_buildNum"] = "F0000101"
            sj["Wx_FlcNum"] = 101
            frame = WxFrame(json_idx[key], seq, dict2json(sj).encode())
            ws.send_frame(frame)
            mock_inst._info("Send inst: " + str(frame) +
                            ", json: " + dict2json(sj))
            seq = 0 if seq ^ 0xFFFF is 0 else seq + 1
            sleep(30)


if __name__ == "__main__":
    init_log('/tmp/wx.log')
    WxServer("", 12345)
    try:
        asyncore_loop()
    except KeyboardInterrupt:
        print('Quit.')