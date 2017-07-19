import struct
import time
from set3.utilz import *


def _mt19937_keystream(seed):
    mt = MT19937(seed)
    while True:
        yield struct.pack('<I', mt.extract_number())


def mt19937_cipher(b, seed):
    ks = _mt19937_keystream(seed)
    return b''.join(xor(blk, next(ks)) for blk in blockify(b, 4))


p = b'fostartaly'
c = mt19937_cipher(p, 1)
p2 = mt19937_cipher(c, 1)
assert p == p2


max_prefix_len = 64
known_pt_len = 14
seed = random.randint(0, 2**16-1)
p = random_bytes(random.randint(0, max_prefix_len)) + b'A'*known_pt_len
c = mt19937_cipher(p, seed)


def brute_seed(c):
    keystream_end = xor(c[-14:], b'A'*known_pt_len)
    print(hexdump(keystream_end))

    for guess in range(2**16):
        keystream = b''.join(itertools.islice(_mt19937_keystream(guess),
                                     (max_prefix_len+known_pt_len) // 4 + 1))
        if keystream_end in keystream:
            print('The seed is {}'.format(guess))
            p2 = mt19937_cipher(c, guess)
            print('The plaintext is {}'.format(p2))
            assert p2 == p
            break

        if guess % 8000 == 0:
            print('Currently at guess {}'.format(guess))


brute_seed(c)

max_time_diff = 64
token_len = 32


def gen_token(t0):
    token = mt19937_cipher(b'\x00'*token_len, t0+random.randint(0, max_time_diff))
    return token

t0 = int(time.time())
token = gen_token(t0)
for i in range(t0, t0+max_time_diff+1):
    guess = mt19937_cipher(b'\x00'*token_len, i)
    if guess == token:
        print('Found the seed: {}'.format(i))
        break
