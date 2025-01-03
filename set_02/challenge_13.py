from urllib.parse import urlencode
from random import randbytes
import common


gUid = 10
gKey = randbytes(16)


def ParameterDecode(parameters: bytes) -> dict:
    pairs = parameters.split(b"&")
    json = {}

    for pair in pairs:
        key, value = pair.split(b"=")
        json[key] = value

    return json


def ProfileFor(email: bytes) -> bytes:
    global gUid

    if b"&" in email or b"=" in email:
        return None

    json = {
        b'email': email,
        b'uid': gUid,
        b'role': b'user'
    }

    gUid += 1

    profile = urlencode(json, safe='@').encode()

    return Oracle(profile)


def DecryptProfile(ciphertext: bytes) -> dict:
    global gKey

    plaintext = common.AES_ECB_Decrypt(ciphertext, gKey)
    plaintext = common.RemovePKCS7Padding(plaintext)

    return ParameterDecode(plaintext)


def Oracle(plaintext: bytes) -> bytes:
    global gKey

    plaintext = common.AddPKCS7Padding(plaintext, len(gKey))

    return common.AES_ECB_Encrypt(plaintext, gKey)


if __name__ == "__main__":
    adminCiphertext = Oracle(b"role=admin")
    encryptedProfile = ProfileFor(b"foopadding@bar.com")

    print(DecryptProfile(encryptedProfile))

    modifiedProfile = encryptedProfile[:-16] + adminCiphertext

    print(DecryptProfile(modifiedProfile))
