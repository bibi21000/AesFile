# -*- encoding: utf-8 -*-
"""Test module

"""
import os
import io

from Crypto.Random import get_random_bytes

from aesfile import AesCryptor as Cryptor

import pytest


def test_cryptor(random_path, random_name):
    key = get_random_bytes(16)
    cryptor = Cryptor(aes_key=key)
    derive = cryptor.derive('test')

def test_cryptor_bad(random_path, random_name):
    key = get_random_bytes(16)
    cryptor = Cryptor(aes_key=key)

    with pytest.raises(TypeError):
        derive = cryptor.derive(None)
