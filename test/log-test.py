#!/usr/bin/python3
# -*- coding: utf-8 -*-

import logging

Log = logging.getLogger("test")
Log.setLevel(logging.DEBUG)
s_handler = logging.StreamHandler()  # sys.stderr
s_handler.setLevel(logging.DEBUG)
s_handler.setFormatter(logging.Formatter(
    "%(asctime)s %(name)s [%(levelname)s] %(filename)s:%(funcName)s() %(message)s"))
Log.addHandler(s_handler)
f_handler = logging.FileHandler("log.test")
f_handler.setLevel(logging.DEBUG)
f_handler.setFormatter(logging.Formatter(
    "%(asctime)s %(name)s [%(levelname)s] %(filename)s:%(funcName)s() %(message)s"))
Log.addHandler(f_handler)


Log.info("info")
Log.warning("warn")
Log.debug("debg")