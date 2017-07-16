from set1_again.utilz import *
from pprint import pprint


def count_ones(n):
    return sum(map(int, bin(n)[2:]))


def hamming_distace(b1, b2):
    assert len(b1) == len(b2)
    diffs = itertools.starmap(operator.xor, zip(b1, b2))
    return sum(map(count_ones, diffs))


this = b'this is a test'
wokka = b'wokka wokka!!!'
assert hamming_distace(this, wokka) == 37


def grouper(iterable, n, fillvalue=None):
    args = [iter(iterable)] * n
    return itertools.zip_longest(*args, fillvalue=fillvalue)

contents = b64decode(open('6.txt').read())

minimal = 2**32
keysize = 0
distances = []
for guess in range(2, 40):
    g = grouper(contents, guess)

    cnt = 8
    dist = sum(hamming_distace(next(g), next(g)) / guess for _ in range(cnt)) / cnt
    if dist < minimal:
        keysize = guess
        minimal = dist
    distances.append(dist)

print(distances)

m = map(highest_score, zip(*grouper(contents, keysize, 0)))
print(bytes(list(zip(*m))[0]))
