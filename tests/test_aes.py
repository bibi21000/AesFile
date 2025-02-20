# -*- encoding: utf-8 -*-
"""Test module

"""
import os
import io
from random import randbytes
import tarfile
import lzma
import bz2
import zipfile
import struct

from Crypto.Random import get_random_bytes
from aesfile import AesFile, open as aes_open

import pytest


@pytest.mark.parametrize("chunk_size, file_size",
    [
        (1024 * 1, 1024 * 10), (1024 * 1, 1024 * 10 + 4), (1024 * 1, 1024 * 10 + 5),
        (1024 * 10, 1024 * 10), (1024 * 10, 1024 * 10 + 7), (1024 * 10, 1024 * 10 + 3),
        (1024 * 100, 1024 * 10), (1024 * 100, 1024 * 10 + 9), (1024 * 100, 1024 * 10 + 11),
    ])
def test_buffer_aes_file(random_path, random_name, chunk_size, file_size):

    key = get_random_bytes(16)
    iv = b'Sixteen byte key'

    data = randbytes(file_size)
    dataf = os.path.join(random_path, random_name)
    with AesFile(dataf, mode='wb', aes_key=key, chunk_size=chunk_size) as ff:
        ff.write(data)
    with open(dataf, "rb") as ff:
        datar = ff.read()
    assert data != datar
    with AesFile(dataf, "rb", aes_key=key) as ff:
        datar = ff.read()
    assert data == datar

    data = random_name * 2
    dataf = os.path.join(random_path, random_name)
    with aes_open(dataf, mode='wt', aes_key=key, chunk_size=chunk_size) as ff:
        ff.write(data)
    with open(dataf, "rb") as ff:
        datar = ff.read()
    assert data != datar
    with aes_open(dataf, "rt", aes_key=key) as ff:
        datar = ff.read()
    assert data == datar

@pytest.mark.parametrize("chunk_size, file_size",
    [
        (1024 * 1, 1024 * 10), (1024 * 1, 1024 * 10 + 4), (1024 * 1, 1024 * 10 + 5),
        (1024 * 10, 1024 * 10), (1024 * 10, 1024 * 10 + 7), (1024 * 10, 1024 * 10 + 3),
        (1024 * 100, 1024 * 10), (1024 * 100, 1024 * 10 + 9), (1024 * 100, 1024 * 10 + 11),
    ])
def test_buffer_aes_open(random_path, random_name, chunk_size, file_size):

    key = get_random_bytes(16)
    iv = b'Sixteen byte key'

    data = randbytes(file_size)
    dataf = os.path.join(random_path, random_name)
    with aes_open(dataf, mode='wb', aes_key=key, chunk_size=chunk_size) as ff:
        ff.write(data)
    with open(dataf, "rb") as ff:
        datar = ff.read()
    assert data != datar
    with aes_open(dataf, "rb", aes_key=key) as ff:
        datar = ff.read()
    assert data == datar

    data = random_name * 2
    dataf = os.path.join(random_path, random_name)
    with aes_open(dataf, mode='wt', aes_key=key, chunk_size=chunk_size) as ff:
        ff.write(data)
    with open(dataf, "rb") as ff:
        datar = ff.read()
    assert data != datar
    with aes_open(dataf, "rt", aes_key=key) as ff:
        datar = ff.read()
    assert data == datar


def test_bad(random_path, random_name):
    key = get_random_bytes(16)
    iv = b'Sixteen byte key'
    data = randbytes(128)
    dataf = os.path.join(random_path, 'test_bad_%s.frnt'%random_name)
    dataok = os.path.join(random_path, 'test_ok_%s.frnt'%random_name)

    with AesFile(dataok, mode='wb', aes_key=key) as ff:
        assert repr(ff).startswith('<AesFile')

    with pytest.raises(ValueError):
        with AesFile(dataf, mode='wbt', aes_key=key) as ff:
            ff.write(data)

    with pytest.raises(ValueError):
        with AesFile(dataf, mode='zzz', aes_key=key) as ff:
            ff.write(data)

    with pytest.raises(FileNotFoundError):
        with AesFile(None, mode='wb', aes_key=key) as ff:
            ff.write(data)

    with pytest.raises(FileNotFoundError):
        with AesFile(dataf, aes_key=key) as ff:
            data = ff.read()

    with pytest.raises(ValueError):
        with aes_open(dataf, mode='wbt', aes_key=key) as ff:
            ff.write(data)

    with pytest.raises(ValueError):
        with aes_open(dataf, mode='wb', aes_key=key, encoding='utf-8') as ff:
            ff.write(data)

    with pytest.raises(ValueError):
        with aes_open(dataf, mode='wb', aes_key=key, errors=True) as ff:
            ff.write(data)

    with pytest.raises(ValueError):
        with aes_open(dataf, mode='wb', aes_key=key, newline='\n') as ff:
            ff.write(data)

    with pytest.raises(TypeError):
        with aes_open(None, mode='wb', aes_key=key) as ff:
            ff.write(data)

    with pytest.raises(ValueError):
        with aes_open(dataf, mode='wb', aes_key=None) as ff:
            ff.write(data)
