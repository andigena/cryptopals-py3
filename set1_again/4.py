import operator
from functools import reduce

from set1_again.utilz import *

contents = ''
with open('4.txt') as f:
    contents = f.read().splitlines()


def highest_score(cy):
    '''Calculate which single-byte XOR gives the highest score based on char frequencies. '''
    candidates = [xor(cy, bytes([i]*len(cy))) for i in range(256)]
    m = map(lambda c: reduce(lambda x, y: x + freqs.get(chr(y), 0), c, 0), candidates)
    return max(enumerate(m), key=operator.itemgetter(1))

idx, (key, score) = max(enumerate(map(highest_score, map(unhexlify, contents))), key=lambda x: x[1][1])
print(contents[idx], xor(unhexlify(contents[idx]), bytes([key]*len(unhexlify(contents[idx])))))
