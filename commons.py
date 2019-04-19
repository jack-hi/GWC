#!/usr/bin/python3
# -*- coding: utf-8 -*-

from logging import getLogger, root, StreamHandler,FileHandler, Formatter


def init_log(logfile="log.log", level="INFO"):
    if len(root.handlers) is 0:
        # root record all
        root.setLevel(0)
        fmt = "%(asctime)s %(name)s,line:%(lineno)d [%(levelname)s] %(message)s"
        # display on screen
        s_handler = StreamHandler()
        s_handler.setLevel(level)
        s_handler.setFormatter(Formatter(fmt=fmt))
        root.addHandler(s_handler)
        # write all levels to logfile
        f_handler = FileHandler(logfile)
        # f_handler.setLevel(0)
        f_handler.setFormatter(Formatter(fmt=fmt))
        root.addHandler(f_handler)
    else:
        raise RuntimeError("init_debug() can only call once.")


def addlog(obj):
    """Function for attaching a debugging logger to a class or function."""
    # create a logger for this object
    logger = getLogger(obj.__module__ + '.' + obj.__name__)

    # make it available to instances
    obj.logger = logger
    obj.debug = logger.debug
    obj.info = logger.info
    obj.warn = logger.warning
    obj.error = logger.error
    obj.exception = logger.exception
    obj.fatal = logger.fatal

    return obj


@addlog
class test():
    def __init__(self):
        test.fatal("fatal")
        test.exception("exception")
        test.error("error")
        test.warn("warning")
        test.info("test")
        test.debug("debug")


if __name__ == "__main__":
    init_log(level='INFO')
    # init_log()
    test()
