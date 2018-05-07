# -*- coding: utf-8 -*-

from __future__ import absolute_import

import os
import shutil
import tempfile


class NullContext:
    """
    A context manager that can be used in a `with` statement
    when nothing needs to be done; e.g., with(foo if bar else NullContext())
    """
    def __init__(self, obj=None):
        self.obj = obj

    def __enter__(self):
        return self.obj

    def __exit__(self, exc_type, exc_value, traceback):
        pass


class FilePush(object):
    """Context Manager that temporarily creates a file at `path` with `content`,
    which is removed on exit. If there was already a file called `path`,
    it is restored on exit."""
    def __init__(self, path, content):
        self.path, self.content, self.old_path = path, content, None

    def __enter__(self):
        if os.path.exists(self.path):
            # Possible race condition where some other process
            # grabs `old_path`, but I don't care.
            self.old_path = tempfile.mktemp()
            shutil.move(self.path, self.old_path)
        with open(self.path, 'wb') as f:
            f.write(self.content)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        os.remove(self.path)
        if self.old_path:
            shutil.move(self.old_path, self.path)
