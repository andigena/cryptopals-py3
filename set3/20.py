from set3.utilz import *
from set1.utilz import *

key = b'\x00'*16
plaintexts = map(b64decode, open('20.txt').read().splitlines())
ciphers = [aes_ctr(p, key, 0, 0) for p in plaintexts]

min_len = len(min(ciphers, key=len))
ciphers = [c[:53] for c in ciphers]

print(ciphers)
keystream = bytes(([c[0] for c in map(highest_score, zip(*ciphers))]))

for c in ciphers:
    print(xor(c, keystream))

