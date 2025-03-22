import base64
from os import urandom
from Crypto.Cipher import AES
import common

gCiphertext = None
gKey = urandom(16)
gNonce = urandom(8)


def AES_ECB_Decrypt(ciphertext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)

    return plaintext


def Get_Ciphertext():
    global gCiphertext
    global gKey
    global gNonce

    ciphertext = common.GetFileContents("challenge_25_input.txt")
    ciphertext = b"".join(ciphertext)
    ciphertext = base64.b64decode(ciphertext)
    plaintext = AES_ECB_Decrypt(ciphertext, b"YELLOW SUBMARINE")
    gCiphertext = common.AES_CTR_Encrypt(plaintext, gKey, gNonce)[1]


def Edit_Ciphertext(offset: int, new_text: bytes):
    global gCiphertext
    global gKey
    global gNonce

    new_ciphertext = common.AES_CTR_Encrypt(new_text, gKey, gNonce)[1]
    keep_begin = gCiphertext[:offset]
    keep_end = gCiphertext[offset + len(new_text):]
    gCiphertext = keep_begin + new_ciphertext + keep_end


if __name__ == "__main__":
    Get_Ciphertext()
    unknown_ciphertext = gCiphertext
    new_text = len(gCiphertext) * b"A"
    Edit_Ciphertext(0, new_text)
    key_stream = b""

    for b in gCiphertext:
        key_stream += common.LogicalXor(bytes([b]), b"A")

    print(common.LogicalXor(unknown_ciphertext, key_stream))
