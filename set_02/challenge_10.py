from base64 import b64decode, b64encode
import common


INPUT = "set_02/challenge_10_input.txt"


def test1():
    data = common.GetFileContents(INPUT)
    key = b"YELLOW SUBMARINE"
    iv = b"\x00" * 16

    ciphertext = b64decode(data)
    plaintext = common.AES_CBC_Decrypt(ciphertext, key, iv)
    plaintext = common.RemovePKCS7Padding(plaintext)

    print(plaintext)

    print("Testing CBC Encryption...")
    plaintext = common.AddPKCS7Padding(plaintext, len(key))
    ciphertext = common.AES_CBC_Encrypt(plaintext, key, iv)
    ciphertext = b64encode(ciphertext)

    assert ciphertext == data

    print("Test 1 Passed!")


if __name__ == "__main__":
    test1()
