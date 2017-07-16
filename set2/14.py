from set2.utilz import *

app = b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
app = b64decode(app)
KEYSIZE = 16
key = random_bytes(KEYSIZE)
pre = random_bytes(random.randint(1, 64))

def encryption_oracle(p):
    encryption_oracle.cnt += 1
    plain = pkcs7(pre + p + app, KEYSIZE)
    return aes_ecb_encrypt(plain, key)

encryption_oracle.cnt = 0


def is_ecb(c):
    KEYSIZE = 16
    if c[KEYSIZE:KEYSIZE*2] == c[KEYSIZE*2:KEYSIZE*3]:
        return True
    else:
        return False

# find out keysize (manually)
tmp = encryption_oracle(b'\x00'*128)
for i in (8, 16, 32):
    print()
    print(i)
    for g in grouper(tmp, i):
        try:
            print(bytes(g))
        except:
            pass


msg = b''
msglen = len(pkcs7(app, 16))

def is_ecb(c, keysize):
    for a, b in itertools.combinations(grouper(c, keysize), 2):
        if a == b:
            offset = c.find(bytes(a))
            return True, offset

    return False, 0


pad_needed = 0
offset = 0
# find out how many bytes we need to pad `pre` to a new block boundary and where that offset is
print()
print('Try guessing the needed padding for the prepended stuff')
for i in range(KEYSIZE*2, KEYSIZE*3-1):
    res = encryption_oracle(b'\x00'*i)
    ecb, offset = is_ecb(res, KEYSIZE)
    if ecb:
        pad_needed = i - KEYSIZE*2
        break

print('Pad needed: ', pad_needed)
print('Attack offset', offset)

secret_len = len(encryption_oracle(b'\x00'*pad_needed)) - offset
print('Guessed secret length vs. actual: ', secret_len, len(app))

# brute force the secret
print()
print('Start brute-force')
for i in range(1, secret_len):
    c = encryption_oracle(bytes([0]*(pad_needed + msglen - i)))
    target = c[offset+msglen-KEYSIZE:offset+msglen]
    for guess in range(256):
        p = bytes([0]*(pad_needed + msglen - i)) + msg + bytes([guess])
        t = encryption_oracle(p)
        if t[offset+msglen-KEYSIZE:offset+msglen] == target:
            msg += bytes([guess])
            # print('Found byte: ', guess)
            break

print('Recovered msg: ', msg)
print('in {} oracle calls'.format(encryption_oracle.cnt))





