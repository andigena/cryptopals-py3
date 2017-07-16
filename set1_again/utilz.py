import itertools
import operator
from base64 import b64encode, b64decode
from binascii import hexlify, unhexlify
from functools import reduce


def xor(i1, i2):
    # assert len(i1) == len(i2)
    out = bytes(i1[idx] ^ i2[idx] for idx in range(min(len(i1), len(i2))))
    return out


freqs = {
    'a': 0.0651738,
    'b': 0.0124248,
    'c': 0.0217339,
    'd': 0.0349835,
    'e': 0.1041442,
    'f': 0.0197881,
    'g': 0.0158610,
    'h': 0.0492888,
    'i': 0.0558094,
    'j': 0.0009033,
    'k': 0.0050529,
    'l': 0.0331490,
    'm': 0.0202124,
    'n': 0.0564513,
    'o': 0.0596302,
    'p': 0.0137645,
    'q': 0.0008606,
    'r': 0.0497563,
    's': 0.0515760,
    't': 0.0729357,
    'u': 0.0225134,
    'v': 0.0082903,
    'w': 0.0171272,
    'x': 0.0013692,
    'y': 0.0145984,
    'z': 0.0007836,
    ' ': 0.1918182
}


def highest_score(cy):
    '''Calculate which single-byte XOR gives the highest score based on char frequencies. '''
    candidates = [xor(cy, bytes([i]*len(cy))) for i in range(256)]
    m = map(lambda c: reduce(lambda x, y: x + freqs.get(chr(y), 0), c, 0), candidates)
    return max(enumerate(m), key=operator.itemgetter(1))


def rep_xor(plaintext, key):
    res = [bytes([c ^ k]) for c, k in zip(plaintext, itertools.cycle(key))]
    print(res)
    return b''.join(res)


def grouper(iterable, n, fillvalue=None):
    args = [iter(iterable)] * n
    return itertools.zip_longest(*args, fillvalue=fillvalue)


def count_ones(n):
    return sum(map(int, bin(n)[2:]))


def hamming_distace(b1, b2):
    assert len(b1) == len(b2)
    diffs = itertools.starmap(operator.xor, zip(b1, b2))
    return sum(map(count_ones, diffs))
