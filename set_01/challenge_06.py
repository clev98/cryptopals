import base64
from itertools import combinations
from common import LogicalXor, GetStringScore


INPUT = "set_01/challenge_06_input.txt"


def HammingDistance(string1: bytes, string2: bytes) -> int:
    assert len(string1) == len(string2)

    distance = 0

    for i in range(len(string1)):
        distance += int.bit_count(string2[i] ^ string1[i])

    return distance


# Use Hamming distance between combinations of blocks to get the
# average distance between blocks. The smallest normalized distance
# between blocks should indicate that guessed key size was the one used.
# Two bytes subjected to a single byte XOR will keep the same distance
# from one another.
def GetKeySizes(
        ciphertext: bytes,
        min: int = 2,
        max: int = 40,
        sizes: int = 1) -> list:
    assert len(ciphertext) >= max * 2

    candidates = []

    for keySize in range(min, max + 1):
        blocks = [ciphertext[i:i+keySize]
                  for i in range(0, len(ciphertext), keySize)][:4]
        distance = 0
        pairs = combinations(blocks, 2)

        for (x, y) in pairs:
            distance += HammingDistance(x, y)

        result = {
            'keySize': keySize,
            'normal': distance / 6 / keySize
        }

        candidates.append(result)

    return sorted(candidates,
                  key=lambda c: c['normal'],
                  reverse=False)[0:sizes]


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


def BreakSingleByteXor(ciphertext: bytes) -> list:
    candidates = []

    for key in range(0, 256):
        decoded = LogicalXor(ciphertext, bytes([key]))
        score = GetStringScore(decoded)

        result = {
            'key': key,
            'score': score,
            'plaintext': decoded
        }

        candidates.append(result)

    return sorted(candidates, key=lambda c: c['score'], reverse=True)[0]


def BreakRepeatingXor(ciphertext: bytes) -> list:
    keys = []
    keySizes = GetKeySizes(ciphertext)

    for size in keySizes:
        key = b""
        positions = Transpose(ciphertext, size['keySize'])

        for i in range(size['keySize']):
            result = BreakSingleByteXor(positions[i])
            key += bytes([result['key']])

        keys.append(key)

    return keys


def test1():
    string1 = b"this is a test"
    string2 = b"wokka wokka!!!"
    distance = HammingDistance(string1, string2)

    assert 37 == distance


def test2():
    lines = None

    with open(INPUT, "r") as fd:
        lines = fd.readlines()
        lines = [line.strip("\n") for line in lines]
        lines = "".join(lines)

    assert None is not lines

    ciphertext = base64.b64decode(lines)

    keys = BreakRepeatingXor(ciphertext)

    for key in keys:
        decoded = LogicalXor(ciphertext, key)
        print(decoded)

    return


if __name__ == "__main__":
    test1()
    print("Passed Hamming Distance Test!")
    test2()
