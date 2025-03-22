from os import urandom
import re
import common


gTargetString = b";admin=true;"
gNonce = urandom(8)
gEncryptionKey = urandom(16)


def WebEncrypt(userData: bytes) -> bytes:
    global gNonce
    global gEncryptionKey

    # This is two blocks
    prepend = b"comment1=cooking%20MCs;userdata="
    append = b";comment2=%20like%20a%20pound%20of%20bacon"

    userData = re.sub(b';|=', b'', userData)

    outputData = prepend + userData + append

    return common.AES_CTR_Encrypt(outputData, gEncryptionKey, gNonce)[1]


def AdminCheck(userData: bytes) -> bool:
    global gNonce
    global gEncryptionKey
    global gTargetString

    plaintext = common.AES_CTR_Decrypt(userData, gEncryptionKey, gNonce)

    print(plaintext)

    if gTargetString in plaintext:
        return True

    return False


def CTRBitFlip():
    poison = b"_admin_true"
    offset1 = 32
    offset2 = 38
    ciphertext = bytearray(WebEncrypt(poison))

    # The previous block will be used as the IV for our targeted block
    # This operation is essentially '_' ^ '_' ^ ';'
    ciphertext[offset1] = ciphertext[offset1] ^ ord("_") ^ ord(";")
    ciphertext[offset2] = ciphertext[offset2] ^ ord("_") ^ ord("=")

    assert True is AdminCheck(ciphertext)


if __name__ == "__main__":
    CTRBitFlip()
