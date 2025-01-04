import random
import base64
import common


gKeySize = 16
gEncryptionKey = random.randbytes(gKeySize)
gEncryptionKey = b"\x00" * 16


def Oracle(plaintext: bytes) -> bytes:
    global gEncryptionKey

    append = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRv"
    append += b"d24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyB"
    append += b"vbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaW"
    append += b"QgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    append = base64.b64decode(append)

    prefix = random.randbytes(random.randint(0, 256))

    modifiedPlaintext = common.AddPKCS7Padding(
        prefix + plaintext + append,
        gKeySize)

    ciphertext = common.AES_ECB_Encrypt(modifiedPlaintext, gEncryptionKey)

    return ciphertext


def CreatePoisonBlock(numBlocks: int, blockSize: int):
    return (b"1" + b"P" * (blockSize - 2) + b"2") * numBlocks


# Create some series of blocks and feed them to the Oracle. 
# Since ECB encrypts each block separately, at some point
# we'll get lucky with Oracle's prefix being a multiple of the 
# blocksize and we'll see a succession of our poison blocks 
# encrypted. 
def FindPoisonedBlock(blockSize: int) -> bytes:
    poison = CreatePoisonBlock(3, blockSize)

    while True:
        ciphertext = Oracle(poison)
        blocks = [ciphertext[i:i+blockSize]
                  for i in range(0, len(ciphertext), blockSize)]

        # Very high chance to be correct?
        for block in blocks:
            if blocks.count(block) == 3:
                return block


# This is very similar to challenge 12, but now we need to keep making
# requests to the Oracle until we see our poisoned blocks. 
# Once the poisoned block is found we can test another byte for each block.
def FindByte(inputBytes: bytes, blockSize: int, encryptedPoison: bytes) -> int:
    prefixLength = (blockSize - len(inputBytes) - 1) % blockSize
    poison = CreatePoisonBlock(3, blockSize)
    prefix = b"A" * prefixLength
    target = Oracle(poison + prefix)

    while encryptedPoison not in target:
        target = Oracle(poison + prefix)

    target = target.split(encryptedPoison)[3]
    target = target[:prefixLength + len(inputBytes) + 1]

    for b in range(256):
        comparison = Oracle(poison + prefix + inputBytes + bytes([b]))

        while encryptedPoison not in comparison:
            comparison = Oracle(poison + prefix + inputBytes + bytes([b]))

        comparison = comparison.split(encryptedPoison)[3]
        comparison = comparison[:prefixLength + len(inputBytes) + 1]

        if comparison == target:
            return b

    return 0


def BreakCiphertext(blockSize: int) -> bytes:
    ciphertext = Oracle(b"")
    discoveredPadding = b""
    poison = FindPoisonedBlock(blockSize)

    for _ in range(len(ciphertext)):
        nextByte = FindByte(discoveredPadding, blockSize, poison)

        discoveredPadding += bytes([nextByte])

    return discoveredPadding


def GetBlockLength() -> int:
    # Try to get the absolute minimum block size with no
    # input text
    length = min([len(Oracle(b"")) for i in range(50)])
    previousLength = length
    string = b""

    # Try to get the next smallest length when adding text. 
    while length == previousLength:
        string += b"A"
        length = min([len(Oracle(string)) for i in range(50)])

    # This is most likely the block size
    return abs(length - previousLength)


if __name__ == "__main__":
    blockSize = GetBlockLength()

    assert True is common.DetectAES_ECB(b"\x00" * blockSize * 16, blockSize)

    print(BreakCiphertext(blockSize))
