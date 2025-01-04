import time
import random
import datetime
import common


minTime = 40
maxTime = 1000
usedSeed = None


def GetNewRandomInt():
    global minTime, maxTime, usedSeed

    time.sleep(random.randint(minTime, maxTime))
    usedSeed = int(datetime.datetime.now(datetime.timezone.utc).timestamp())

    common.InitializeState(usedSeed)

    time.sleep(random.randint(minTime, maxTime))

    return common.MT19937()


def CrackMT19937(needle: int):
    global minTime, maxTime, usedSeed

    time = int(datetime.datetime.now(datetime.timezone.utc).timestamp())

    for seed in range(time - maxTime, time - minTime):
        common.InitializeState(seed)

        if needle == common.MT19937():
            print(seed)
            print(usedSeed)

            assert seed == usedSeed


if __name__ == "__main__":
    nextInt = GetNewRandomInt()
    CrackMT19937(nextInt)
