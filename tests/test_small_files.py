# -*- encoding: utf-8 -*-
"""Test module

"""
import os
import importlib
import time
from random import randbytes
import urllib.request
import zipfile
import tarfile

from Crypto.Random import get_random_bytes

import aesfile
from aesfile import AesFile
from aesfile.zstd import AesFile as _ZstdAesFile, open as aesz_open
from aesfile.tar import TarFile as _TarZstdAesFile

import pytest


class ZstdAesFile(_ZstdAesFile):
    pass

class TarZstdAesFile(_TarZstdAesFile):
    pass

@pytest.mark.parametrize("fcls, size, nb", [
    (TarZstdAesFile, 129, 100),
    (TarZstdAesFile, 533, 20),
    (TarZstdAesFile, 1089, 5),
])
def test_tar(random_path, fcls, size, nb):

    params = {
        'aes_key': get_random_bytes(16),
    }
    dataf = os.path.join(random_path, 'test.frnt')
    time_start = time.time()
    file_size = 0
    data1f = os.path.join(random_path, 'file.data')
    data1 = randbytes(size)
    with open(data1f, 'wb') as ff:
        ff.write(data1)
    with fcls(dataf, mode='w', **params) as ff:
        for i in range(nb):
            ff.add(data1f, "%s-%s"%(i, data1f))
            file_size += os.path.getsize(data1f)
    time_write = time.time()
    with fcls(dataf, "r", **params) as ff:
        ff.extractall('extract_tar')
    time_read = time.time()
    # ~ assert data == datar
    comp_size = os.path.getsize(dataf)
    for i in range(nb):
        with open(os.path.join('extract_tar', "%s-%s"%(i, data1f)),'rb') as ff:
            data1r = ff.read()
            assert data1 == data1r

