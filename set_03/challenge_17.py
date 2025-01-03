from base64 import b64decode
from os import urandom
from random import randint
import common


gBlockSize = 16
gEncryptionKey = urandom(gBlockSize)
gFile = "set_03/challenge_17_input.txt"


def EncryptionAPI() -> tuple:
    lines = common.GetFileContents(gFile)
    line = lines[randint(0, len(lines) - 1)]
    plaintext = b64decode(line)
    plaintext = common.AddPKCS7Padding(line, gBlockSize)
    iv = urandom(gBlockSize)
    ciphertext = common.AES_CBC_Encrypt(plaintext, gEncryptionKey, iv)

    return (ciphertext, iv)


def PaddingOracle(ciphertext: bytes, iv: bytes) -> bool:
    plaintext = common.AES_CBC_Decrypt(ciphertext, gEncryptionKey, iv)

    return common.ValidatePKCS7Padding(plaintext)


def GetValidByte(
        ciphertext: bytes,
        iv: list,
        position: int) -> int:
    for b in range(256):
        iv[-position] = b
        inputIv = b"".join([bytes([b]) for b in iv])

        if True is PaddingOracle(ciphertext, inputIv):
            if 1 == position:
                iv[-2] ^= 1
                inputIv = b"".join([bytes([b]) for b in iv])

                if False is PaddingOracle(ciphertext, inputIv):
                    continue
            return b

    return 0


def GetZeroIV(ciphertext: bytes, blockSize: int):
    zeroIv = [0] * blockSize

    for i in range(1, blockSize + 1):
        nextIv = [b ^ i for b in zeroIv]
        nextByte = GetValidByte(ciphertext, nextIv, i)
        zeroIv[-i] = nextByte ^ i

    return b"".join([bytes([b]) for b in zeroIv])


if __name__ == "__main__":
    ciphertext, iv = EncryptionAPI()
    blocks = [ciphertext[i:i+gBlockSize]
              for i in range(0, len(ciphertext), gBlockSize)]
    plaintext = b""

    for i in range(len(blocks)):
        zeroIv = GetZeroIV(blocks[i], gBlockSize)
        plaintext += common.LogicalXor(iv, zeroIv)
        iv = blocks[i]

    plaintext = common.RemovePKCS7Padding(plaintext)
    print(b64decode(plaintext))
