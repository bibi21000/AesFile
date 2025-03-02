# -*- encoding: utf-8 -*-
"""

.. include:: ../README.md
   :start-line: 1


"""
__author__ = 'bibi21000 aka Sébastien GALLET'
__email__ = 'bibi21000@gmail.com'

__all__ = ["AesCryptor", "AesFile", "open"]

from cofferfile import EncryptFile, Cryptor, _open_t
from cofferfile import WRITE_BUFFER_SIZE, CHUNK_SIZE, READ, WRITE, APPEND, EXCLUSIVE # noqa F401
from cofferfile.decorator import reify

class AesFile(EncryptFile):
    """
    `aesfile.zstd`
    `aesfile.tar`
    """

    def __init__(self, filename=None, mode=None, fileobj=None,
            chunk_size=CHUNK_SIZE, write_buffer_size=WRITE_BUFFER_SIZE,
            aes_key=None,
        ):
        """Constructor for the AesFile class.

        At least one of fileobj and filename must be given a
        non-trivial value.

        The new class instance is based on fileobj, which can be a regular
        file, an io.BytesIO object, or any other object which simulates a file.
        It defaults to None, in which case filename is opened to provide
        a file object.

        When fileobj is not None, the filename argument is only used to be
        included in the gzip file header, which may include the original
        filename of the uncompressed file.  It defaults to the filename of
        fileobj, if discernible; otherwise, it defaults to the empty string,
        and in this case the original filename is not included in the header.

        The mode argument can be any of 'r', 'rb', 'a', 'ab', 'w', 'wb', 'x', or
        'xb' depending on whether the file will be read or written.  The default
        is the mode of fileobj if discernible; otherwise, the default is 'rb'.
        A mode of 'r' is equivalent to one of 'rb', and similarly for 'w' and
        'wb', 'a' and 'ab', and 'x' and 'xb'.

        The aes_key argument is the AES key used to crypt/decrypt data.

        Encryption is done by chunks to reduce memory footprint. The default
        chunk_size is 64KB.
        """
        super().__init__(filename=filename, mode=mode, fileobj=fileobj,
            chunk_size=chunk_size, write_buffer_size=write_buffer_size,
            cryptor='aes', aes_key=aes_key)

    def __repr__(self):
        s = repr(self.myfileobj)
        return '<AesFile ' + s[1:-1] + ' ' + hex(id(self)) + '>'


class AesCryptor(Cryptor):

    @reify
    def _imp_Crypto_Cipher_AES(cls):
        """Lazy loader for Crypto.Cipher.AES"""
        import importlib
        return importlib.import_module('Crypto.Cipher.AES')

    @classmethod
    @reify
    def _imp_Crypto_Protocol_KDF(cls):
        """Lazy loader for Crypto.Protocol.KDF"""
        import importlib
        return importlib.import_module('Crypto.Protocol.KDF')

    @classmethod
    @reify
    def _imp_Crypto_Random(cls):
        """Lazy loader for Crypto.Random"""
        import importlib
        return importlib.import_module('Crypto.Random')

    def __init__(self, aes_key=None, **kwargs):
        super().__init__(**kwargs)
        if aes_key is None:
            raise ValueError("Invalid aes_key: {!r}".format(aes_key))
        self.aes_key = aes_key

    @classmethod
    def derive(self, password, salt=None, key_len=16, N=2 ** 14, r=8, p=1, num_keys=1):
        """Derive a key from password (experimental)
        See https://pycryptodome.readthedocs.io/en/latest/src/protocol/kdf.html#scrypt
        """
        if salt is None:
            salt = self._imp_Crypto_Random.get_random_bytes(16)
        return salt, self._imp_Crypto_Protocol_KDF.scrypt(password, salt,
            key_len, N=N, r=r, p=p, num_keys=num_keys)

    def _decrypt(self, chunk):
        tag = chunk[0:16]
        nonce = chunk[16:31]
        ciphertext = chunk[31:]
        cipher = self._imp_Crypto_Cipher_AES.new(self.aes_key, self._imp_Crypto_Cipher_AES.MODE_OCB, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    def _encrypt(self, chunk):
        cipher = self._imp_Crypto_Cipher_AES.new(self.aes_key, self._imp_Crypto_Cipher_AES.MODE_OCB)
        ciphertext, tag = cipher.encrypt_and_digest(chunk)
        # ~ assert len(cipher.nonce) == 15
        return tag + cipher.nonce + ciphertext


def open(filename, mode="rb", aes_key=None,
         encoding=None, errors=None, newline=None,
         chunk_size=CHUNK_SIZE):
    """Open a AES file in binary or text mode.

    The filename argument can be an actual filename (a str or bytes object), or
    an existing file object to read from or write to.

    The mode argument can be "r", "rb", "w", "wb", "x", "xb", "a" or "ab" for
    binary mode, or "rt", "wt", "xt" or "at" for text mode. The default mode is
    "rb".

    For binary mode, this function is equivalent to the AesFile constructor:
    AesFile(filename, mode, aes_key). In this case, the encoding, errors
    and newline arguments must not be provided.

    For text mode, a AesFile object is created, and wrapped in an
    io.TextIOWrapper instance with the specified encoding, error handling
    behavior, and line ending(s).

    Encryption is done by chunks to reduce memory footprint. The default
    chunk_size is 64KB.
    """
    return _open_t(filename, mode=mode,
         encoding=encoding, errors=errors, newline=newline,
         chunk_size=chunk_size,
         cryptor='aes', aes_key=aes_key)
