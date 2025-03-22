from Crypto.Hash import SHA1
from os import urandom


class CustomSha1:
    def __init__(self, key_size=16):
        assert int == type(key_size)

        self.key = urandom(key_size)

    def Secret_Prefix_Hash(self, message: bytes) -> bytes:
        return SHA1(self.key + message)
