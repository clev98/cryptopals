import common


def test():
    string1 = b"AAAAAAAA\x08\x08\x08\x08\x08\x08\x08\x08"

    assert True is common.ValidatePKCS7Padding(string1)

    string2 = b"AAAAAAAA\x08\x08\x08\x08\x08\x08\x08\x07"

    assert False is common.ValidatePKCS7Padding(string2)


if __name__ == "__main__":
    test()
