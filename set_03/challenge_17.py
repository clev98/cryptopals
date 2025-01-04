from base64 import b64decode
from os import urandom
from random import randint
import common


# https://www.nccgroup.com/us/research-blog/cryptopals-exploiting-cbc-padding-oracles/


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
        # Set the candidate byte
        iv[-position] = b
        inputIv = b"".join([bytes([b]) for b in iv])

        # Loop until the padding is correct. 
        if True is PaddingOracle(ciphertext, inputIv):
            # If this the first byte, make the next byte isn't
            # \x02, resulting in the oracle returning true for
            # \x02\x02 instead of the result we want for \x01.
            if 1 == position:
                iv[-2] ^= 1
                inputIv = b"".join([bytes([b]) for b in iv])

                if False is PaddingOracle(ciphertext, inputIv):
                    continue

            return b

    return 0


# Create a zeroing IV for this block.
def GetZeroIV(ciphertext: bytes, blockSize: int):
    # Create an initial IV of all 0's
    zeroIv = [0] * blockSize

    # For each possible padding value
    for i in range(1, blockSize + 1):
        # XOR the zeroing IV values with the current padding byte
        # so the Oracle will set the lower bytes to the correct padding.
        # Remember, this is a Zeroing IV. 
        nextIv = [b ^ i for b in zeroIv]
        nextByte = GetValidByte(ciphertext, nextIv, i)
        # Set the next value in the zeroing IV, XOR'd with the current
        # padding byte to get the actual value.
        # i.e. we know the plaintext at this position is the padding byte,
        # remove that value to get the original.
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
