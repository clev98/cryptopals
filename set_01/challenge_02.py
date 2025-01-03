from common import LogicalXor


def test():
    buffer = bytes.fromhex("1c0111001f010100061a024b53535009181c")
    key = bytes.fromhex("686974207468652062756c6c277320657965")
    target_result = bytes.fromhex("746865206b696420646f6e277420706c6179")

    result = LogicalXor(buffer, key)

    assert result == target_result

    print("Test passed!")


if __name__ == "__main__":
    test()
