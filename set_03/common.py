from Crypto.Cipher import AES


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
