import common
import random


gEncryptionMethod = 0


def Oracle(plaintext: bytes) -> bytes:
    global gEncryptionMethod

    key = random.randbytes(16)
    iv = random.randbytes(16)
    prepend = random.randbytes(random.randint(5, 10))
    append = random.randbytes(random.randint(5, 10))
    gEncryptionMethod = random.randint(0, 1)

    modifiedPlaintext = common.AddPKCS7Padding(
        prepend + plaintext + append,
        len(key))

    if 0 == gEncryptionMethod:
        ciphertext = common.AES_CBC_Encrypt(
            modifiedPlaintext,
            key,
            iv)
    else:
        ciphertext = common.AES_ECB_Encrypt(modifiedPlaintext, key)

    return ciphertext


def Detector(ciphertext: bytes, keySize: int):
    global gEncryptionMethod

    result = common.DetectAES_ECB(ciphertext, keySize)

    if result:
        print("Detector found ECB!")
        assert 1 == gEncryptionMethod
    else:
        print("Detector found CBC!")
        assert 0 == gEncryptionMethod

    return


if __name__ == "__main__":
    for _ in range(16):
        plaintext = b"\x00" * random.randint(1024, 2048)
        ciphertext = Oracle(plaintext)
        Detector(ciphertext, 16)
