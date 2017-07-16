from set3.utilz import *

KEYSIZE = 16
key = b'YELLOW SUBMARINE'
c = b'''L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='''


def aes_ctr_keystream(key, nonce, blk_cnt):
    pt = pack('<QQ', nonce, blk_cnt)
    while True:
        yield aes_ecb_encrypt(pt, key)
        blk_cnt += 1
        pt = pack('<QQ', nonce, blk_cnt)


def aes_ctr(b, key, nonce, blk_cnt_start):
    keystream = aes_ctr_keystream(key, nonce, blk_cnt_start)
    return b''.join(xor(blk, next(keystream)) for blk in blockify(b, len(key)))

print(aes_ctr(b64decode(c), key, 0, 0))