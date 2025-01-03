from Crypto.Cipher import AES
import base64


INPUT = "set_01/challenge_07_input.txt"


def test():
    key = b"YELLOW SUBMARINE"
    lines = None

    with open(INPUT, 'r') as fd:
        lines = fd.readlines()
        lines = [line.strip("\n") for line in lines]
        lines = "".join(lines)

    assert None is not lines

    ciphertext = base64.b64decode(lines)
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)

    print(plaintext)


if __name__ == "__main__":
    test()
