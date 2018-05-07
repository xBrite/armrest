# -*- coding: utf-8 -*-

from __future__ import absolute_import

import logging


__all__ = (
    'LogLevel',
    'LEVELS',
    'verbosity_level',
    'init_console_logging',
    'dump_logging_config',
)


class LogLevel(object):
    """Temporarily change logging level."""
    def __init__(self, logger_name, new_level, use_max=True):
        self.logger = logging.getLogger(logger_name)
        self.old_level = self.logger.level
        self.new_level = max(self.old_level, new_level) if use_max else new_level

    def __enter__(self):
        """Override the logging level."""
        self.logger.setLevel(self.new_level)
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        """Restore the original logging level."""
        self.logger.setLevel(self.old_level)


LEVELS = [logging.DEBUG, logging.INFO, logging.WARN, logging.ERROR, logging.FATAL]


def verbosity_level(verbosity=0):
    level = 2 - verbosity
    if level < 0:
        return LEVELS[0]
    elif level >= len(LEVELS):
        return LEVELS[-1]
    else:
        return LEVELS[level]


def init_console_logging(logger, level=logging.DEBUG):
    handler = logging.StreamHandler()  # log to console
    handler.setLevel(level)
    logger.addHandler(handler)
    logger.setLevel(level)
    return logger


def dump_logging_config():
    handler_name = lambda h: "{}_{}".format(h.get_name() or h.__class__.__name__, id(h))
    handlers = {}
    response = []
    for wr in logging._handlerList:
        h = wr()  # weakref
        if h is not None:
            name = handler_name(h)
            s = 'handler: name={} class={} level={}'.format(
                name, h.__class__.__name__, logging._levelNames[h.level])
            if isinstance(h, logging.FileHandler):
                s += ' filename="{}"'.format(h.baseFilename)
            elif isinstance(h, logging.StreamHandler):
                s += ' stream="{}"'.format(h.stream.name)
            handlers[name] = s
            response.append(s)
    for name, log in logging.Logger.manager.loggerDict.items():
        if not isinstance(log, logging.PlaceHolder):
            logger_handlers = {}
            l = log
            while l:
                for h in l.handlers:
                    logger_handlers.setdefault(handler_name(h), h)
                l = l.parent
            response.append(
                "logger: {} level={} handlers={}".format(
                    name, logging._levelNames.get(log.level),
                    logger_handlers.keys()))
    return response
