#!/usr/bin/python3
# -*- coding: utf-8 -*-

import logging

def debugging(obj):
    """Function for attaching a debugging logger to a class or function."""
    # create a logger for this object
    logger = logging.getLogger(obj.__module__ + '.' + obj.__name__)
    logger.setLevel("INFO")
    # make it available to instances
    obj._logger = logger
    obj._debug = logger.debug
    obj._info = logger.info
    obj._warning = logger.warning
    obj._error = logger.error
    obj._exception = logger.exception
    obj._fatal = logger.fatal

    return obj

@debugging
class test():
    def __init__(self):
        test._info("test")

test()

test._info('test')

