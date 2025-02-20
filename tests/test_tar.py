# -*- encoding: utf-8 -*-
"""Test module

"""
import os
import io
from random import randbytes
import tarfile
import struct

from Crypto.Random import get_random_bytes

import cofferfile
from aesfile.zstd import CParameter, DParameter
from aesfile.tar import TarFile, open as tar_open

import pytest
from unittest import mock

@pytest.mark.parametrize("chunk_size, file_size",
    [
        (1023 * 1, 1024 * 10), (1024 * 1, 1024 * 10 + 4), (1024 * 1, 1024 * 10 + 5),
        (1024 * 10, 1024 * 10), (1024 * 10, 1024 * 10 + 7), (1024 * 10, 1024 * 10 + 3),
        (1024 * 100, 1024 * 10), (1024 * 100, 1024 * 10 + 9), (1024 * 100, 1024 * 10 + 11),
    ])
def test_buffer_aes_file(random_path, random_name, chunk_size, file_size):

    key = get_random_bytes(16)

    dataf = os.path.join(random_path, random_name)

    level_or_option = {
        CParameter.compressionLevel : 15,
    }

    data1 = randbytes(file_size)
    dataf1 = os.path.join(random_path, "file1%s.data"%random_name)
    with open(dataf1, 'wb') as ff:
        ff.write(data1)

    data2 = randbytes(file_size // 2)
    dataf2 = os.path.join(random_path, "file2%s.data"%random_name)
    with open(dataf2, 'wb') as ff:
        ff.write(data2)

    with TarFile(dataf, mode='wb', aes_key=key, level_or_option=level_or_option, chunk_size=chunk_size) as ff:
        ff.add(dataf1,'file1.data')
        ff.add(dataf2,'file2.data')

    tarpath = os.path.join(random_path, "extract_%s"%random_name)
    with TarFile(dataf, "rb", aes_key=key) as ff:
        ff.extractall(path=tarpath, filter='data')

    with open(os.path.join(tarpath, 'file1.data'), 'rb') as ff:
        assert data1 == ff.read()
    with open(os.path.join(tarpath, 'file2.data'), 'rb') as ff:
        assert data2 == ff.read()


@pytest.mark.parametrize("chunk_size, file_size",
    [
        (1021 * 1, 1024 * 10), (1024 * 1, 1024 * 10 + 4), (1024 * 1, 1024 * 10 + 5),
        (1024 * 10, 1024 * 10), (1024 * 10, 1024 * 10 + 7), (1024 * 10, 1024 * 10 + 3),
        (1024 * 100, 1024 * 10), (1024 * 100, 1024 * 10 + 9), (1024 * 100, 1024 * 10 + 11),
    ])
def test_buffer_aes_open(random_path, random_name, chunk_size, file_size):

    key = get_random_bytes(16)

    dataf = os.path.join(random_path, random_name)

    level_or_option = {
        CParameter.compressionLevel : 15,
    }

    data1 = randbytes(file_size)
    dataf1 = os.path.join(random_path, "file1%s.data"%random_name)
    with open(dataf1, 'wb') as ff:
        ff.write(data1)

    data2 = randbytes(file_size // 2)
    dataf2 = os.path.join(random_path, "file2%s.data"%random_name)
    with open(dataf2, 'wb') as ff:
        ff.write(data2)

    with tar_open(dataf, mode='wb', aes_key=key, level_or_option=level_or_option, chunk_size=chunk_size) as ff:
        ff.add(dataf1,'file1.data')
        ff.add(dataf2,'file2.data')

    tarpath = os.path.join(random_path, "extract_%s"%random_name)
    with tar_open(dataf, "rb", aes_key=key) as ff:
        ff.extractall(path=tarpath, filter='data')

    with open(os.path.join(tarpath, 'file1.data'), 'rb') as ff:
        assert data1 == ff.read()
    with open(os.path.join(tarpath, 'file2.data'), 'rb') as ff:
        assert data2 == ff.read()

def test_bad(random_path, random_name):
    key = get_random_bytes(16)
    data = randbytes(128)
    dataf = os.path.join(random_path, 'test_bad_%s.frnt'%random_name)
    dataok = os.path.join(random_path, 'test_ok_%s.frnt'%random_name)

    with TarFile(dataok, mode='wb', aes_key=key) as ff:
        assert repr(ff).startswith('<TarZstdAes')

    with pytest.raises(ValueError):
        with TarFile(dataf, mode='wbt', aes_key=key) as ff:
            ff.write(data)

    with pytest.raises(ValueError):
        with TarFile(dataf, mode='zzz', aes_key=key) as ff:
            ff.write(data)

    with pytest.raises(FileNotFoundError):
        with TarFile(None, mode='wb', aes_key=key) as ff:
            ff.write(data)

    with pytest.raises(FileNotFoundError):
        with TarFile(dataf, aes_key=key) as ff:
            data = ff.read()

    with pytest.raises(ValueError):
        with tar_open(dataf, mode='wbt', aes_key=key) as ff:
            ff.write(data)

    with pytest.raises(ValueError):
        with tar_open(dataf, mode='wb', aes_key=key, encoding='utf-8') as ff:
            ff.write(data)

    with pytest.raises(ValueError):
        with tar_open(dataf, mode='wb', aes_key=key, errors=True) as ff:
            ff.write(data)

    with pytest.raises(ValueError):
        with tar_open(dataf, mode='wb', aes_key=key, newline='\n') as ff:
            ff.write(data)

    with pytest.raises(TypeError):
        with tar_open(None, mode='wb', aes_key=key) as ff:
            ff.write(data)

    with pytest.raises(ValueError):
        with tar_open(dataf, mode='wb', aes_key=None) as ff:
            ff.write(data)

    with pytest.raises(TypeError):
        with tar_open(dataf, mode='wb', aes_key=key, zstd_dict=1) as ff:
            ff.write(data)

    with mock.patch('tarfile.TarFile.__init__') as mocked:
        mocked.side_effect = AssertionError('Boooooom')
        with pytest.raises(AssertionError):
            with TarFile(dataok, mode='wb', aes_key=key) as ff:
                assert repr(ff).startswith('<TarZstdAes')
