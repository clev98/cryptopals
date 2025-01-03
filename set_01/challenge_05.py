from common import LogicalXor


def test():
    text = b"Burning 'em, if you ain't quick and nimble\n"
    text += b"I go crazy when I hear a cymbal"
    key = b"ICE"
    target = bytes.fromhex("0b3637272a2b2e63622c2e69692a2"
                           "3693a2a3c6324202d623d63343c2a"
                           "26226324272765272a282b2f20430"
                           "a652e2c652a3124333a653e2b2027"
                           "630c692b20283165286326302e272"
                           "82f")

    encoded = LogicalXor(text, key)

    assert encoded == target

    print("Test passed!")


if __name__ == "__main__":
    test()
