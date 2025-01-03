INPUT = "set_01/challenge_08_input.txt"
KEY_SIZE = 16


def test():
    lines = None

    with open(INPUT, 'r') as fd:
        lines = fd.readlines()

    assert None is not lines

    for line in lines:
        ciphertext = line.strip('\n')
        blocks = [ciphertext[i:i+KEY_SIZE]
                  for i in range(0, len(ciphertext), KEY_SIZE)]

        for block in blocks:
            occurrence = blocks.count(block)

            if occurrence > 1:
                print(line)
                break


if __name__ == "__main__":
    test()
