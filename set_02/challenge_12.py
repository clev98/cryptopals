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

    # Get the output with just our prefix
    # Say our prefix is 1234567
    # Say our plaintext is ABCDEFG_ABCDEFG_ABCDEFG_ (3 8 byte blocks)
    # Our full plaintext is now: (| to split blocks for visibility)
    #   1234567A|BCDEFG_A|BCDEFG_A|BCDEFG_
    # Shifting the first byte of the plaintext into our prefix
    # We can shorten the prefix to move more bytes into our block like so
    #   123456AB|CDEFG_AB|CDEFG_AB|CDEFG_
    #   12345ABC|DEFG_ABC|DEFG_ABC|DEFG_
    #   etc
    # This is our needle with our currently unknown byte.
    # In the first case, we know that our prefix, 1234567 + some byte
    # is now the first block that the Oracle returns. 
    # In later cases we can move the prefix but instead use the later 
    # blocks, such, with BCDEFG_ being our known prefix, plus some
    # unknown byte.
    target = Oracle(prefix)
    target = target[:prefixLength + len(inputBytes) + 1]

    # We have our needle, add a byte to the end of the prefix until
    # we find a matching block.
    # We add our known inputBytes here so we get the correct
    # encrypted block
    for b in range(256):
        comparison = Oracle(prefix + inputBytes + bytes([b]))
        comparison = comparison[:prefixLength + len(inputBytes) + 1]

        if comparison == target:
            return b

    return 0


def BreakCiphertext(blockSize: int) -> bytes:
    # Get the ciphertext without our meddling, get it's length so
    # we know how many bytes we need to break. 
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
