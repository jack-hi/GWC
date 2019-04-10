#!/usr/bin/python3
# -*- coding: utf-8 -*-

from logging import basicConfig, getLogger, root, FileHandler, Formatter


def init_debug(logfile="log.log"):
    if len(root.handlers) is 0:
        basicConfig(level="DEBUG",
                    format="%(asctime)s %(name)s,line:%(lineno)d [%(levelname)s] %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S")

        f_handler = FileHandler(logfile)
        f_handler.setFormatter(
            Formatter(fmt="%(asctime)s %(name)s,line:%(lineno)d [%(levelname)s] %(message)s",
                      datefmt="%Y-%m-%d %H:%M:%S"))
        root.addHandler(f_handler)
    else:
        raise RuntimeError("init_debug() can only call once.")


def debugging(obj):
    """Function for attaching a debugging logger to a class or function."""
    # create a logger for this object
    logger = getLogger(obj.__module__ + '.' + obj.__name__)

    # make it available to instances
    obj._logger = logger
    obj._debug = logger.debug
    obj._info = logger.info
    obj._warning = logger.warning
    obj._error = logger.error
    # obj._exception = logger.exception
    # obj._fatal = logger.fatal

    return obj


@debugging
class test():
    def __init__(self):
        #test._fatal("fatal")
        #test._exception("exception")
        test._error("error")
        test._warning("warning")
        test._info("test")
        test._debug("debug")


if __name__ == "__main__":
    init_debug()
    init_debug()
    test()
