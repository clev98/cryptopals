import common


def test():
    key = b"YELLOW SUBMARINE"
    plaintext = b"Main I really love frogs."

    nonce, ciphertext = common.AES_CTR_Encrypt(plaintext, key)

    plaintext2 = common.AES_CTR_Decrypt(ciphertext, key, nonce)

    assert plaintext == plaintext2
    print("Test passed!")


if __name__ == "__main__":
    test()
