import itertools

from set1_again.utilz import *


pt = b'''Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal'''


def rep_xor(plaintext, key):
    res = bytes(c ^ k for c, k in zip(plaintext, itertools.cycle(key)))
    return res

print(hexlify(rep_xor(pt, b'ICE')))
