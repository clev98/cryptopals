import base64
from os import urandom
import common


INPUT = "set_03/challenge_19_input.txt"


def BreakSingleByteXor(ciphertext: bytes) -> list:
    candidates = []

    for key in range(0, 256):
        decoded = common.LogicalXor(ciphertext, bytes([key]))
        score = common.GetStringScore(decoded)

        result = {
            'key': key,
            'score': score,
            'plaintext': decoded
        }

        candidates.append(result)

    return sorted(candidates, key=lambda c: c['score'], reverse=True)[0]


def Transpose(ciphertext: bytes, keySize: int) -> dict:
    blocks = [ciphertext[i:i+keySize]
              for i in range(0, len(ciphertext), keySize)]
    positions = {}

    for block in blocks:
        for i in range(len(block)):
            if i in positions.keys():
                positions[i] += bytes([block[i]])
            else:
                positions[i] = bytes([block[i]])

    return positions


def BreakFixedNonceCTR(ciphertexts: list):
    keyLength = min([len(ciphertext) for ciphertext in ciphertexts])
    truncatedCiphertexts = [
        ciphertext[:keyLength] for ciphertext in ciphertexts]
    ciphertext = b"".join(truncatedCiphertexts)

    positions = Transpose(ciphertext, keyLength)
    key = b""

    for i in range(keyLength):
        result = BreakSingleByteXor(positions[i])
        key += bytes([result['key']])

    print(key)

    for i in range(len(truncatedCiphertexts)):
        print(common.LogicalXor(truncatedCiphertexts[i], key))


# Treat this as repeating key XOR, see challenge 6.
if __name__ == "__main__":
    lines = common.GetFileContents(INPUT)
    nonce = b"\x00"
    key = urandom(16)

    plaintexts = [base64.b64decode(line) for line in lines]
    ciphertexts = [common.AES_CTR_Encrypt(plaintext, key, nonce)[1]
                   for plaintext in plaintexts]

    BreakFixedNonceCTR(ciphertexts)
