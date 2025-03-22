from Crypto.Cipher import AES


def LogicalXor(buffer: bytes, key: bytes) -> bytes:
    current_key_pos = 0
    key_len = len(key)
    out_buf = b""

    for i in range(len(buffer)):
        out_buf += bytes([buffer[i] ^ key[current_key_pos]])
        current_key_pos = (current_key_pos + 1) % key_len

    return out_buf


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


def GetFileContents(file: str):
    lines = None

    with open(file, 'rb') as fd:
        lines = fd.readlines()
        lines = [line.strip(b"\r\n") for line in lines]

    assert None is not lines

    return lines


def ValidatePKCS7Padding(plaintext: bytes) -> bool:
    potentialPadding = bytes([plaintext[-1]]) * plaintext[-1]

    if plaintext[-plaintext[-1]:] == potentialPadding:
        return True

    return False


def RemovePKCS7Padding(plaintext: bytes) -> bytes:
    padding = plaintext[-1]

    if padding > 16:
        return plaintext

    return plaintext[:len(plaintext) - padding]


def AddPKCS7Padding(plaintext: bytes, blockSize: int) -> bytes:
    padChar = blockSize - len(plaintext) % blockSize

    if 0 == padChar:
        padChar = blockSize

    plaintext += bytes([padChar]) * padChar

    return plaintext


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
