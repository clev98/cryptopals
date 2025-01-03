from common import LogicalXor, GetStringScore


def test():
    candidates = []
    encoded = bytes.fromhex("1b37373331363f78151b7f2b783431333d7"
                            "8397828372d363c78373e783a393b3736")

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
