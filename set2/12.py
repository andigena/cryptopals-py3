from set2.utilz import *

app = b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
app = b64decode(app)
KEYSIZE = 16
key = random_bytes(KEYSIZE)

def encryption_oracle(p):
    encryption_oracle.cnt += 1
    plain = pkcs7(p + app, KEYSIZE)
    return aes_ecb_encrypt(plain, key)

encryption_oracle.cnt = 0


def is_ecb(c):
    KEYSIZE = 16
    if c[KEYSIZE:KEYSIZE*2] == c[KEYSIZE*2:KEYSIZE*3]:
        return True
    else:
        return False

# find out keysize (manually)
# for i in range(1, 34):
#     print(i, encryption_oracle(b'\x00'*i))

msg = b''
msglen = len(pkcs7(app, 16))

for i in range(1, msglen):
    c = encryption_oracle(bytes([0]*(64 + msglen - i)))
    target = c[48+msglen:64+msglen]
    for guess in range(256):
        p = bytes([0]*(64 + msglen - i)) + msg + bytes([guess])
        t = encryption_oracle(p)
        if t[48+msglen:64+msglen] == target:
            msg += bytes([guess])
            print('Found byte: ', guess)
            break

print('Recovered msg: ', msg)
print('in {} oracle calls'.format(encryption_oracle.cnt))





