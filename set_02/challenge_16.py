from os import urandom
import re
import common


gTargetString = b";admin=true;"
gBlockSize = 16
gIV = urandom(gBlockSize)
gEncryptionKey = urandom(gBlockSize)


def WebEncrypt(userData: bytes) -> bytes:
    global gIV
    global gEncryptionKey

    prepend = b"comment1=cooking%20MCs;userdata="
    append = b";comment2=%20like%20a%20pound%20of%20bacon"

    userData = re.sub(b';|=', b'', userData)

    outputData = prepend + userData + append
    outputData = common.AddPKCS7Padding(outputData, gBlockSize)

    return common.AES_CBC_Encrypt(outputData, gEncryptionKey, gIV)


def AdminCheck(userData: bytes) -> bool:
    global gIV
    global gEncryptionKey
    global gTargetString

    plaintext = common.AES_CBC_Decrypt(userData, gEncryptionKey, gIV)

    assert True is common.ValidatePKCS7Padding(plaintext)

    plaintext = common.RemovePKCS7Padding(plaintext)

    print(plaintext)

    if gTargetString in plaintext:
        return True

    return False


def CBCBitFlip():
    poison = b"_admin_true_AAAA"
    offset1 = 0
    offset2 = 6
    offset3 = 11
    ciphertext = WebEncrypt(poison)
    blocks = [ciphertext[i:i+gBlockSize]
              for i in range(0, len(ciphertext), gBlockSize)]
    prevBlock = list(blocks[1])

    prevBlock[offset1] = prevBlock[offset1] ^ ord("_") ^ ord(";")
    prevBlock[offset2] = prevBlock[offset2] ^ ord("_") ^ ord("=")
    prevBlock[offset3] = prevBlock[offset3] ^ ord("_") ^ ord(";")

    blocks[1] = b"".join(bytes([b]) for b in prevBlock)

    newCiphertext = b"".join(blocks)

    assert True is AdminCheck(newCiphertext)


if __name__ == "__main__":
    CBCBitFlip()
