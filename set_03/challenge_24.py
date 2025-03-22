import struct
import random
import string
import time
import common


gUsedSeed = random.randint(0, 2**16 - 1)
gUsedTokenSeed = None


def MTStreamEncrypt(plaintext: bytes, seed: bytes) -> bytes:
    ciphertext = b""

    common.InitializeState(seed)

    for b in range(0, len(plaintext), 4):
        nextBlock = plaintext[b:b + 4]
        stream = struct.pack('I', common.MT19937())[:len(nextBlock)]
        ciphertext += common.LogicalXor(nextBlock, stream)

    return ciphertext


def EncryptAPI(plaintext: bytes) -> bytes:
    global gUsedSeed

    chars = bytes(string.ascii_letters + string.digits, 'ascii')
    length = random.randint(0, 16)
    prefix = bytes([random.choice(chars) for _ in range(length)])

    return MTStreamEncrypt(prefix + plaintext, gUsedSeed)


def BreakSeed():
    global gUsedSeed

    plaintext = b"A" * 14
    ciphertext = EncryptAPI(plaintext)

    for seed in range(2**16 - 1):
        test = MTStreamEncrypt(ciphertext, seed)

        if plaintext in test:
            print(seed)

            assert seed == gUsedSeed

            break


def BreakResetToken():
    global gUsedTokenSeed

    def CreateToken():
        global gUsedTokenSeed

        gUsedTokenSeed = int(time.time()) & (2**16 - 1)

        common.InitializeState(gUsedTokenSeed)

        token = b""

        for _ in range(16):
            token += struct.pack('I', common.MT19937())

        return token

    token = CreateToken()

    for seed in range(2**16 - 1):
        common.InitializeState(seed)
        test = b""

        for _ in range(16):
            test += struct.pack('I', common.MT19937())

        if test == token:
            print(seed)

            assert seed == gUsedTokenSeed

            break


def Test():
    test = b"12345678123"

    ciphertext = MTStreamEncrypt(test, 0x1337)
    plaintext = MTStreamEncrypt(ciphertext, 0x1337)

    assert test == plaintext

    print("Test 1 Passed!")


if __name__ == "__main__":
    Test()
    BreakSeed()
    BreakResetToken()
