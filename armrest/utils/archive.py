# -*- coding: utf-8 -*-

from __future__ import absolute_import

import io
import os
import sys
import json
import tarfile
import zipfile
import hashlib

from .file import abspath


def file_open(filename, mode="rt", encoding="utf-8", **kwargs):
    """Open a file with a compression codec, if necessary, based on the file"s extension.

    For use with in `with` blocks."""
    if filename == "-":
        return sys.stdin if mode.startswith("r") else sys.stdout

    f = abspath(filename)

    if mode.endswith("b"):
        # To prevent ValueError("Argument "encoding" not supported in binary mode")
        encoding = None

    if filename.endswith(".gz"):
        import gzip
        return gzip.open(f, mode=mode, encoding=encoding, **kwargs)
    elif filename.endswith(".bz2"):
        import bz2
        return bz2.open(f, mode=mode, encoding=encoding, **kwargs)
    elif filename.endswith(".xz"):
        import lzma  # Python 3.3+ or backports.lzma
        return lzma.open(f, mode=mode, encoding=encoding, **kwargs)
    # TODO: .lz4 -> python-lz4, .zst -> python-zstandard
    else:
        return io.open(f, mode=mode, encoding=encoding, **kwargs)


def read_json_lines(filename, loads=json.loads):
    """Read a decoded sequence of objects from a (possibly compressed) JSONLines file."""
    with file_open(filename, "rt") as fp:
        for line in fp:
            line = line.rstrip()  # Remove trailing \n
            yield loads(line)


def write_json_lines(sequence, filename, mode="wt", dumps=json.dumps):
    """Write a sequence of objects, encoding them as JSON, to a (possibly compressed) JSONLines file."""
    with file_open(filename, mode) as fp:
        for d in sequence:
            fp.write(dumps(d))
            fp.write("\n")


def tar_compression_mode(filename):
    if filename.endswith(".tar.gz") or filename.endswith(".tgz"):
        return ":gz"    # gzip
    elif filename.endswith(".tar.bz2") or filename.endswith(".tbz2"):
        return ":bz2"   # bzip2
    elif filename.endswith(".tar.xz") or filename.endswith(".txz"):
        return ":xz"    # lzma
    elif filename.endswith(".tar"):
        return ""
    else:
        return None


def make_tarfile(output_filename, source_dir):
    with tarfile.open(output_filename,
                      "w" + tar_compression_mode(output_filename)) as tar:
        tar.add(source_dir, arcname=os.path.basename(source_dir))


def zip_add_directory(
        zip_archive, source_dir,
        exclude_dirs=None, exclude_extensions=None, exclude_filenames=None,
        prefix_dir=None, logger=None):
    """Recursively add a directory tree to `zip_archive`."""
    exclude_dirs = set(exclude_dirs or ())
    exclude_extensions = set(exclude_extensions or ())
    exclude_filenames = set(exclude_filenames or ())
    # TODO: just use regular logging
    logger = logger or (lambda s: None)
    relroot = abspath(os.path.join(source_dir, "."))


    def filename_extention_excluded(name):
        return any([name.endswith(ext) for ext in exclude_extensions])

    for dirpath, dirnames, filenames in os.walk(source_dir):
        logger("zip: dirpath={0!r}, dirnames={1!r}, filenames={2!r}".format(
            dirpath, dirnames, filenames))

        # Must modify dirnames in-place, per os.walk documentation,
        # to prevent traversal of excluded subdirectories.
        # We must enumerate a copy of `dirnames` as the in-place modifications
        # confuse the iterator.
        for dir in list(dirnames):
            logger("zip: Examining dir {0!r}".format(dir))
            if dir in exclude_dirs or filename_extention_excluded(dir):
                logger("zip: Removing dir {0!r}".format(dir))
                dirnames.remove(dir)
            else:
                logger("zip: Retaining dir {0!r}".format(dir))

        files = []

        for filename in filenames:
            if filename in exclude_filenames or filename_extention_excluded(filename):
                logger("zip: Removing filename {0!r}".format(filename))
                continue
            else:
                files.append(filename)

        arcdir = os.path.join(
            prefix_dir or '', os.path.relpath(dirpath, relroot))
        zip_write_directory(
            zip_archive, arcdir, dirpath, files, logger)


def zip_write_directory(
        zip_archive, arcdir, dirpath, filenames, logger=None):
    logger = logger or (lambda s: None)
    if not filenames:
        # add directory `dirpath` (needed for empty dirs)
        logger("zip: Adding dir {0!r} -> {1!r}".format(dirpath, arcdir))
        zip_archive.write(dirpath, arcdir)

    for filename in filenames:
        filepath = os.path.join(dirpath, filename)
        if os.path.isfile(filepath):  # regular files only
            arcname = os.path.join(arcdir, filename)
            logger("zip: Zipping {0!r} -> {1!r}".format(filepath, arcname))
            zip_archive.write(filepath, arcname)
            # TODO add symlink support, per https://gist.github.com/kgn/610907


def make_zipfile(
        output_filename, source_dir,
        exclude_dirs=None, exclude_extensions=None):
    with zipfile.ZipFile(output_filename, "w", zipfile.ZIP_DEFLATED) as zip_file:
        zip_add_directory(zip_file, source_dir, exclude_dirs, exclude_extensions)


def check_zipfile(zip_filename):
    if not zipfile.is_zipfile(zip_filename):
        raise Exception("Not a ZIP file")
    with zipfile.ZipFile(zip_filename) as zip_file:
        zip_file.testzip()
        filenames = zip_file.namelist()
        seen = set()
        for filename in filenames:
            if filename in seen:
                raise Exception("Duplicate filename found: {}".format(filename))
            else:
                seen.add(filename)


_MASK64 = ((1 << 64) - 1)
_CRC_SEED = 12764787846358441471  # large prime


def zipfile_checksum(filename):
    h = _CRC_SEED
    with zipfile.ZipFile(filename, "r") as zf:
        for n in sorted(zf.namelist()):
            chksum = zf.getinfo(n).CRC
            h = (h * 101 + chksum) & _MASK64
    return "{:016x}".format(h)


def tarfile_checksum(filename):
    h = _CRC_SEED
    with tarfile.open(filename, "r" + tar_compression_mode(filename)) as tf:
        for n in sorted(tf.getnames()):
            f = tf.extractfile(n)
            if f is not None:
                md5 = hashlib.md5()
                for d in iter(lambda: f.read(16 * 1024), b""):
                    md5.update(d)
                chksum = int(md5.hexdigest(), 16)
                h = (h * 101 + chksum) & _MASK64
    return "{:016x}".format(h)
