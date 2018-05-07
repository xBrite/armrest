# -*- coding: utf-8 -*-

from __future__ import absolute_import

import codecs
import fnmatch
import json
import os
import shutil
import errno

import sys

import six


def abspath(path):
    return os.path.abspath(os.path.expanduser(path))


def make_dir(target_dir, mode=0o777):
    """Create (if needed) a directory with a certain file mode."""
    if os.path.exists(target_dir):
        if not os.path.isdir(target_dir):
            raise ValueError("'%s' is not a directory" % target_dir)
    else:
        try:
            os.makedirs(target_dir, mode)
        except OSError as e:
            # Handle race condition of simultaneous dir creation
            if e.errno != errno.EEXIST:
                raise
            elif not os.path.isdir(target_dir):
                raise
    os.chmod(target_dir, mode)


def move_file_to_dir(source_file, target_dir, target_basename=None):
    make_dir(target_dir)
    target_dir = abspath(target_dir)
    target_file = os.path.join(
        target_dir, target_basename or os.path.basename(source_file))
    if os.path.exists(target_file):
        os.remove(target_file)
    shutil.move(source_file, target_file)
    return target_file


def find_in_path(command):
    for p in os.getenv("PATH").split(os.pathsep):
        f = os.path.join(p, command)
        if os.path.exists(f):
            return f


def find_recursive_pattern(base_dir, pattern):
    for root, dirnames, filenames in os.walk(base_dir):
        for filename in fnmatch.filter(filenames, pattern):
            yield os.path.join(root, filename)


def find_in_directory_path(filename, path):
    """
    Attempt to locate the given file in the specified directory or any ancestor directory,
    up to the filesystem root.
    :param filename: name of file to look for
    :type filename: str
    :param path: starting directory
    :type path: str
    :return: fully-qualified path to filename or None if not found
    :rtype: str or None
    """
    path = os.path.abspath(path)
    if os.path.isfile(path):
        path = os.path.dirname(path)
    while True:
        app_settings_path = os.path.abspath(os.path.join(path, filename))
        if os.path.exists(app_settings_path):
            return app_settings_path

        path, _ = os.path.split(path)  # strip one directory
        if not path or path == os.path.sep:
            return None


def read_file_possibly_from_stdin(filename, as_json=False, as_pb=None):
    if filename == '-':
        ctx = sys.stdin
    elif as_pb:
        ctx = open(filename, 'rb')
    else:
        ctx = codecs.open(filename, 'rU', encoding='utf8')

    with ctx as fh:
        contents = fh.read()

    if as_pb:
        pb = as_pb()
        pb.ParseFromString(six.binary_type(contents))
        return pb
    elif as_json:
        return json.loads(contents)
    else:
        return contents
