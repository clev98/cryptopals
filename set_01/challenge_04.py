from common import LogicalXor, GetStringScore


INPUT = "set_01/challenge_04_input.txt"


def test():
    candidates = []
    lines = None

    with open(INPUT, 'r') as fd:
        lines = fd.readlines()

    assert None is not lines

    for line in lines:
        encoded = bytes.fromhex(line)

        for key in range(0, 256):
            decoded = LogicalXor(encoded, bytes([key]))
            score = GetStringScore(decoded)

            result = {
                'key': key,
                'score': score,
                'plaintext': decoded
            }

            candidates.append(result)

    most_likely = sorted(candidates, key=lambda c: c['score'], reverse=True)[0]

    print(most_likely)


if __name__ == "__main__":
    test()
