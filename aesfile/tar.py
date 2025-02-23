# -*- encoding: utf-8 -*-
""" TarFile interface.

"""
__author__ = 'bibi21000 aka Sébastien GALLET'
__email__ = 'bibi21000@gmail.com'

import tarfile

from cofferfile import _open_cls
from . import CHUNK_SIZE, READ, WRITE, APPEND, EXCLUSIVE # noqa F401
from .zstd import AesFile as ZstdAesFile


class TarFile(tarfile.TarFile):
    """The container of the store. Based on TarFfile with encryption"""

    def __init__(self, name, mode='r', fileobj=None,
            chunk_size=CHUNK_SIZE,
            level_or_option=None, zstd_dict=None,
            aes_key=None, **kwargs
        ):
        """Init the TarZstdAesFile"""
        chunk_size = kwargs.pop('chunk_size', CHUNK_SIZE)
        kwargs.pop('cryptor', None)
        self.aes_file = ZstdAesFile(name, mode, fileobj=fileobj,
            aes_key=aes_key, level_or_option=level_or_option,
                zstd_dict=zstd_dict, chunk_size=chunk_size)
        try:
            super().__init__(fileobj=self.aes_file, mode=mode.replace('b', ''), **kwargs)

        except Exception:
            self.aes_file.close()
            raise

    def close(self):
        """Close the TarZstdAesFile"""
        try:
            super().close()

        finally:
            if self.aes_file is not None:
                self.aes_file.close()

    def __repr__(self):
        """ """
        s = repr(self.aes_file)
        return '<TarZstdAes ' + s[1:-1] + ' ' + hex(id(self)) + '>'

def open(filename, mode="rb", aes_key=None,
        chunk_size=CHUNK_SIZE,
        level_or_option=None, zstd_dict=None,
        **cryptor_args):
    """Open a ZstdAES TarFile in binary mode.

    The filename argument can be an actual filename (a str or bytes object), or
    an existing file object to read from or write to.

    The mode argument can be "r", "w", "x" or "a" for binary mode.

    """
    return _open_cls(filename, mode=mode,
        chunk_size=chunk_size, aes_key=aes_key,
        coffer_cls = TarFile,
        level_or_option=level_or_option, zstd_dict=zstd_dict,
        cryptor='aes', **cryptor_args)
