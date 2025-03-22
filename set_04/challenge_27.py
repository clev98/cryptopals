from os import urandom
import re
import common


gTargetString = b";admin=true;"
gBlockSize = 16
gIV = urandom(gBlockSize)
gEncryptionKey = gIV


def WebEncrypt(userData: bytes) -> bytes:
    global gIV
    global gEncryptionKey

    # This is two blocks
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

    # assert True is common.ValidatePKCS7Padding(plaintext)

    plaintext = common.RemovePKCS7Padding(plaintext)

    for char in plaintext:
        if char < 32 or char > 127:
            return (False, plaintext)

    print(plaintext)

    if gTargetString in plaintext:
        return (True, plaintext)

    return (False, plaintext)


def IVKey():
    global gBlockSize
    global gEncryptionKey

    ciphertext = WebEncrypt(b"")
    block1 = ciphertext[:gBlockSize]
    new_ciphertext = block1 + b"\x00" * gBlockSize + block1

    plaintext = AdminCheck(new_ciphertext)[1]
    key = common.LogicalXor(plaintext[:gBlockSize], plaintext[gBlockSize * 2:])
    print(key)
    print(gEncryptionKey)

    assert key == gEncryptionKey


if __name__ == "__main__":
    IVKey()
