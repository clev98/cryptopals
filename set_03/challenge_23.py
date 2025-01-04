import common


n = 624
m = 397
w = 32
r = 31
UMASK = 0xffffffff << r
LMASK = 0xffffffff >> (w - r)
a = 0x9908b0df
u = 11
s = 7
t = 15
L = 18
b = 0x9d2c5680
c = 0xefc60000
f = 1812433253


def GetBit(x, i):
    global w

    return (x & (1 << (w - i - 1)))


def ReverseBits(x):
    global w

    rev = 0

    for _ in range(w):
        rev = (rev << 1)

        if x > 0:
            if x & 1 == 1:
                rev ^= 1

            x >>= 1

    return rev


def InvertLeftShift(y: int, shiftAmount: int, mask: int) -> int:
    newY = ReverseBits(y)
    newMask = ReverseBits(mask)

    return ReverseBits(InvertRightShift(newY, shiftAmount, newMask))


def InvertRightShift(y: int, shiftAmount: int, mask: int) -> int:
    x = 0

    # For every bit in a 32 it integer
    for i in range(w):
        if i < shiftAmount:
            # If this bit was shifted out in (y >> L), get it from the result
            x |= GetBit(y, i)
        else:
            # Get the bit from the result and XOR it with 
            # (the current bit in X >> totalShift & the mask)
            reverse = GetBit(y, i)
            reverse ^= ((GetBit(x, i - shiftAmount) >> shiftAmount)
                        & GetBit(mask, i))
            x |= reverse

    return x


def Untemper(z: int):
    global n, m, w, r, UMASK, LMASK, a, u, s, t, l, b, c, f

    y = z
    y = InvertRightShift(y, L, 0xFFFFFFFF)
    y = InvertLeftShift(y, t, c)
    y = InvertLeftShift(y, s, b)
    y = InvertRightShift(y, u, 0xFFFFFFFF)

    return y


if __name__ == "__main__":
    clonedState = []

    common.InitializeState(0x1337)

    # Iterate through n times to mix up the state
    # Has to be n, can't undo the twist
    for _ in range(n):
        _ = common.MT19937()

    lastState = common.GetState()

    for _ in range(n):
        clonedState.append(Untemper(common.MT19937()))

    assert lastState == clonedState
