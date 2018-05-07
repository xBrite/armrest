# -*- coding: utf-8 -*-

import os
from .image_info import get_image_info


class MimetypeExtension(object):
    @classmethod
    def guess_content_type(cls, file_contents):
        content_type, _, _ = cls.get_image_info(file_contents)
        return content_type

    @classmethod
    def get_image_info(cls, file_contents):
        content_type, width, height = get_image_info(file_contents)
        return content_type, width, height

    Json = 'application/json'
    Xml = 'application/xml'
    Yaml = 'application/x-yaml'
    Gif = 'image/gif'
    Jpeg = 'image/jpeg'
    Png = 'image/png'
    Webp = 'image/webp'
    Text = 'text/plain'
    Protobuf = 'application/x-protobuf'
    Web = 'application/x-www-form-urlencoded'

    CommonMimetypes = {
        Json: '.json',
        Xml: '.xml',
        Yaml: '.yaml',
        Gif: '.gif',
        Jpeg: '.jpg',
        Png: '.png',
        Webp: '.webp',
        Text: '.txt',
        Protobuf: '.pb',
        Web: '.html'
    }

    @classmethod
    def mimetype_to_extension(cls, mimetype):
        return cls.CommonMimetypes.get(mimetype, '')

    @classmethod
    def extension_to_mimetype(cls, extension):
        for mimetype, ext in cls.CommonMimetypes.items():
            if ext == extension:
                return mimetype
        return None

    @classmethod
    def filename_to_mimetype(cls, filename):
        base, extension = os.path.splitext(filename)
        return cls.extension_to_mimetype(extension)
