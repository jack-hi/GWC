#!/usr/bin/python3
# -*- coding: utf-8 -*-

class Transport:
    """
    Base class for Transport
    """
    def __init__(self):
        pass

    def send(self, data):
        pass

    def incoming(self, data):
        pass

class SegmentTransport(Transport):
    """
    Segment Transport
    """
    def __init__(self):
        super().__init__();
        self.socket = None
        pass
