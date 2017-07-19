from z3 import *
from set3.utilz import MT19937


def temper(y):
    # only used for verification
    y = y ^ ((y >> MT19937.u) & MT19937.d)
    y = y ^ ((y << MT19937.s) & MT19937.b)
    y = y ^ ((y << MT19937.t) & MT19937.c)
    y = y ^ (y >> MT19937.l) & MT19937.bmask
    return y


def untemper(output):
    s = Solver()
    y_arr = [BitVec('y'+str(i), 32) for i in range(5)]
    out = BitVecVal(output, 32)

    # goddamn >> being arithmetic in Z3Py
    s.add(out == y_arr[4] ^ LShR(y_arr[4], MT19937.l))
    s.add(y_arr[4] == (y_arr[3] ^ (y_arr[3] << MT19937.t) & MT19937.c))
    s.add(y_arr[3] == (y_arr[2] ^ (y_arr[2] << MT19937.s) & MT19937.b))
    s.add(y_arr[2] == (y_arr[1] ^ LShR(y_arr[1], MT19937.u) & MT19937.d))
    s.check()
    m = s.model()
    mtv = m[y_arr[1]].as_long()
    assert temper(mtv) == output
    return mtv


def splice(state):
    mt = MT19937(0)
    mt.extract_number()
    mt.MT = state
    mt.index = 624  # to force twist
    return mt


mt = MT19937(1)
state = [0] * 624
for i in range(624):
    out = mt.extract_number()
    state[i] = untemper(out)

print()
assert mt.MT == state
spliced = splice(state)
assert(all(spliced.extract_number() == mt.extract_number() for i in range(624)))
