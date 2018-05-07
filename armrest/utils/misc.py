# -*- coding: utf-8 -*-

import datetime
import json


def hexdump(src, length=8):
    """Generate ASCII hexdump of bytes or unicode data."""
    result = []
    digits = 4 if isinstance(src, unicode) else 2
    for i in xrange(0, len(src), length):
        s = src[i:i+length]
        hexa = b' '.join(["%0*X" % (digits, ord(x))  for x in s])
        text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.'  for x in s])
        result.append( b"%04X   %-*s   %s" % (i, length*(digits + 1), hexa, text) )
    return b'\n'.join(result)


def seconds_to_minutes_rounded_up(seconds):
    return (seconds + 59) // 60


def datetime_date(dt=None):
    """Extract YMD from a datetime.datetime. Defaults to "today"."""
    # Note: For mocking reasons, this function must not be in ./date.py
    dt = dt or datetime.datetime.today()
    return dt.replace(hour=0, minute=0, second=0, microsecond=0)


truthy = frozenset(('t', 'true', 'y', 'yes', 'on', '1'))


def asbool(s):
    """ Return the boolean value ``True`` if the case-lowered value of string
    input ``s`` is any of ``t``, ``true``, ``y``, ``on``, or ``1``;
    otherwise return the boolean value ``False``. """
    if s is None:
        return False
    if isinstance(s, bool):
        return s
    s = str(s).strip()
    return s.lower() in truthy


def as_lower(s):
    """ Return s.lower(), even if s is None """
    return str(s).lower() if s else ''


def pretty_print_json(obj, indent=1, sort_keys=True):
    return json.dumps(obj, indent=indent, sort_keys=sort_keys)


def pretty_number(n):
    """Format number with comma as thousands separator"""
    return "{:,}".format(n)


def sorted_list_of_dicts_by_common_key(lst, key):
    """Return the given list of dicts sorted by the given key they all have in common."""
    return sorted(lst, cmp=lambda x, y: cmp(x[key], y[key]))


def sorted_by_value(d):
    """Return a list of (key, value) tuples from the given dict, sorted by value."""
    return [(k, d[k]) for k in sorted(d, key=d.get, reverse=True)]


def chunks(lst, *lens):
    """Split the supplied list into sub-lists of the given lengths, and return the list of sub-lists."""
    retval = []
    start = 0
    for n in lens:
        retval.append(lst[start:start + n])
        start += n
    return retval

