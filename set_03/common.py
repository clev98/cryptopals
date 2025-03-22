from Crypto.Cipher import AES


n = 624
m = 397
w = 32
r = 31
UMASK = 0xffffffff << r
LMASK = 0xffffffff >> (w - r)
a = 0x9908b0df
u = 11
s = 7
t = 15
L = 18
b = 0x9d2c5680
c = 0xefc60000
f = 1812433253
stateList = []
stateIndex = 0


CHARACTER_FREQUENCIES = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835,
    'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610, 'h': 0.0492888,
    'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490,
    'm': 0.0202124, 'n': 0.0564513, 'o': 0.0596302, 'p': 0.0137645,
    'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357,
    'u': 0.0225134, 'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692,
    'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
}


def GetStringScore(string: bytearray) -> int:
    score = 0

    for c in string:
        score += CHARACTER_FREQUENCIES.get(chr(c).lower(), 0)

    return score


def LogicalXor(buffer: bytes, key: bytes) -> bytes:
    current_key_pos = 0
    key_len = len(key)
    out_buf = b""

    for i in range(len(buffer)):
        out_buf += bytes([buffer[i] ^ key[current_key_pos]])
        current_key_pos = (current_key_pos + 1) % key_len

    return out_buf


def GetFileContents(file: str):
    lines = None

    with open(file, 'rb') as fd:
        lines = fd.readlines()
        lines = [line.strip(b"\r\n") for line in lines]

    assert None is not lines

    return lines


def DetectAES_ECB(ciphertext: bytes, keySize: int) -> bool:
    blocks = [ciphertext[i:i+keySize]
              for i in range(0, len(ciphertext), keySize)]

    for block in blocks:
        if blocks.count(block) > 1:
            return True

    return False


def AddPKCS7Padding(plaintext: bytes, blockSize: int) -> bytes:
    padChar = blockSize - len(plaintext) % blockSize

    if 0 == padChar:
        padChar = blockSize

    plaintext += bytes([padChar]) * padChar

    return plaintext


def RemovePKCS7Padding(plaintext: bytes) -> bytes:
    return plaintext[:len(plaintext) - plaintext[-1]]


def ValidatePKCS7Padding(plaintext: bytes) -> bool:
    potentialPadding = bytes([plaintext[-1]]) * plaintext[-1]

    if plaintext[-plaintext[-1]:] == potentialPadding:
        return True

    return False


def AES_ECB_Encrypt(plaintext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)

    return ciphertext


def AES_ECB_Decrypt(ciphertext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)

    return plaintext


def AES_CBC_Encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    blockSize = len(key)
    blocks = [plaintext[i:i+blockSize]
              for i in range(0, len(plaintext), blockSize)]
    ciphertext = b""

    assert 16 == blockSize or 32 == blockSize
    assert 0 == len(plaintext) % blockSize

    for block in blocks:
        preEncrypt = LogicalXor(block, iv)
        iv = AES_ECB_Encrypt(preEncrypt, key)
        ciphertext += iv

    return ciphertext


def AES_CBC_Decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    blockSize = len(key)
    blocks = [ciphertext[i:i+blockSize]
              for i in range(0, len(ciphertext), blockSize)]
    plaintext = b""

    assert 16 == blockSize or 32 == blockSize

    for block in blocks:
        postDecrypt = AES_ECB_Decrypt(block, key)
        plaintext += LogicalXor(postDecrypt, iv)
        iv = block

    return plaintext


def InitializeState(seed: int):
    global n, m, w, r, UMASK, LMASK, a, u, s, t, l, b, c, f
    global stateList, stateIndex

    stateList = []
    stateIndex = 0

    stateList.append(seed & 0xFFFFFFFF)

    for i in range(1, n):
        seed = f * (seed ^ (seed >> (w - 2))) + i
        stateList.append(seed & 0xFFFFFFFF)


def SetState(newStateList: list, newStateIndex: int):
    global stateList, stateIndex

    stateList = newStateList
    stateIndex = newStateIndex


def GetState() -> list:
    global stateList

    return stateList


def MT19937() -> int:
    global n, m, w, r, UMASK, LMASK, a, u, s, t, l, b, c, f
    global stateList, stateIndex

    def twist():
        global n, m, w, r, UMASK, LMASK, a, u, s, t, l, b, c, f
        global stateList, stateIndex

        for i in range(n):
            x = (stateList[i] & UMASK) + (stateList[(i + 1) % n] & LMASK)
            xA = x >> 1

            if x % 2 != 0:
                xA ^= a

            stateList[i] = stateList[(i + m) % n] ^ xA

        return

    if stateIndex >= n:
        twist()
        stateIndex = 0

    y = stateList[stateIndex]
    stateIndex += 1

    y = y ^ ((y >> u) & 0xFFFFFFFF)
    y = y ^ ((y << s) & b)
    y = y ^ ((y << t) & c)
    z = y ^ (y >> L)

    return z


# TODO: This should be done with ECB, but I was lazy.
def AES_CTR_Encrypt(
        plaintext: bytes, key: bytes, nonce: bytes = None) -> tuple:
    if None is nonce:
        cipher = AES.new(key, AES.MODE_CTR)
    else:
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)

    ciphertext = cipher.encrypt(plaintext)

    return (cipher.nonce, ciphertext)


def AES_CTR_Decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)

    return plaintext
