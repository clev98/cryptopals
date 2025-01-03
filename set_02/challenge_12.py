import random
import base64
import common


gKeySize = 16
gEncryptionKey = random.randbytes(gKeySize)


def Oracle(plaintext: bytes) -> bytes:
    global gEncryptionKey

    append = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRv"
    append += b"d24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyB"
    append += b"vbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaW"
    append += b"QgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    append = base64.b64decode(append)

    modifiedPlaintext = common.AddPKCS7Padding(
        plaintext + append,
        gKeySize)

    ciphertext = common.AES_ECB_Encrypt(modifiedPlaintext, gEncryptionKey)

    return ciphertext


def GetBlockLength() -> int:
    plaintext = b""
    ciphertext = Oracle(plaintext)
    initialLength = len(ciphertext)

    while True:
        plaintext += b"A"
        ciphertext = Oracle(plaintext)

        if initialLength != len(ciphertext):
            return len(ciphertext) - initialLength


def FindByte(inputBytes: bytes, blockSize: int) -> int:
    prefixLength = (blockSize - len(inputBytes) - 1) % blockSize
    prefix = b"A" * prefixLength
    target = Oracle(prefix)
    target = target[:prefixLength + len(inputBytes) + 1]

    for b in range(256):
        comparison = Oracle(prefix + inputBytes + bytes([b]))
        comparison = comparison[:prefixLength + len(inputBytes) + 1]

        if comparison == target:
            return b

    return 0


def BreakCiphertext(blockSize: int) -> bytes:
    ciphertext = Oracle(b"")
    discoveredPadding = b""

    for _ in range(len(ciphertext)):
        nextByte = FindByte(discoveredPadding, blockSize)

        discoveredPadding += bytes([nextByte])
        print(discoveredPadding)

    return discoveredPadding


if __name__ == "__main__":
    blockSize = GetBlockLength()

    assert True is common.DetectAES_ECB(b"\x00" * blockSize * 16, blockSize)

    print(BreakCiphertext(blockSize))
