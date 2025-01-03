from common import AddPKCS7Padding, RemovePKCS7Padding


def test1():
    plaintext = b"YELLOW SUBMARINE"
    resultText = b"YELLOW SUBMARINE\x04\x04\x04\x04"
    blockSize = 20

    paddedText = AddPKCS7Padding(plaintext, blockSize)

    assert resultText == paddedText
    print("Test 1 Passed!")


def test2():
    plaintext = b"YELLOW"
    resultText = b"YELLOW\x06\x06\x06\x06\x06\x06"
    blockSize = 6

    paddedText = AddPKCS7Padding(plaintext, blockSize)

    assert resultText == paddedText
    print("Test 2 Passed!")


def test3():
    resultText = b"YELLOW SUBMARINE"
    plaintext = b"YELLOW SUBMARINE\x04\x04\x04\x04"

    normalText = RemovePKCS7Padding(plaintext)

    assert resultText == normalText
    print("Test 3 Passed!")


if __name__ == "__main__":
    test1()
    test2()
    test3()
