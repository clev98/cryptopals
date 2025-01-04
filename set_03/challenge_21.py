import random
import common


def test():
    random.seed(0)
    state = random.getstate()

    pyRandom = [random.randrange(0xFFFFFFFF) for _ in range(10)]
    implRandom = []

    # Copy Python's rand state
    stateList = list(state[1][:-1])
    stateIndex = state[1][-1]

    common.SetState(stateList, stateIndex)

    for _ in range(10):
        z = common.MT19937()
        implRandom.append(z)

    print(pyRandom)
    print(implRandom)

    assert pyRandom == implRandom


if __name__ == "__main__":
    test()
