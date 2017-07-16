from set2.utilz import *


def encryption_oracle(p):
    KEYSIZE = 16

    key = random_bytes(KEYSIZE)
    pre = random_bytes(random.randint(5, 10))
    post = random_bytes(random.randint(5, 10))
    plain = pkcs7(pre + p + post, KEYSIZE)
    if random.randint(0, 1):
        iv = random_bytes(KEYSIZE)
        print('Using CBC')
        return aes_cbc_encrypt(plain, key, iv)
    else:
        print('Using ECB')
        return aes_ecb_encrypt(plain, key)


def is_ecb(c):
    KEYSIZE = 16
    if c[KEYSIZE:KEYSIZE*2] == c[KEYSIZE*2:KEYSIZE*3]:
        return True
    else:
        return False


for i in range(16):
    c = encryption_oracle(bytes([0]*45))
    print('we used {}'.format('ECB' if is_ecb(c) else 'CBC'))
    print()