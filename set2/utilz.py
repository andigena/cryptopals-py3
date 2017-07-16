from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from Crypto import Random
from Crypto.Random import random
from set1_again.utilz import *


def random_bytes(n):
    rndfile = Random.new()
    return rndfile.read(n)


def pkcs7(b, l):
    r = len(b) % l
    return b + bytes([l-r]*(l-r))


def depkcs7(b, l):
    padding = int(b[-1])
    return b[:-padding]


def unpad_pkcs7(pt, l):
    if len(pt) == 0:
        raise RuntimeError('Empty plaintext')
    if len(pt) % l != 0:
        raise RuntimeError('Invalid length')

    padding = int(pt[-1])
    if padding > l or padding <= 0:
        raise RuntimeError('Invalid padding value')

    if pt[-padding:] != bytes([padding]*padding):
        raise RuntimeError('Invalid padding')

    return pt[:-padding]


def aes_ecb_encrypt(p, key):
    obj = AES.new(key, AES.MODE_ECB)
    return obj.encrypt(p)


def aes_ecb_decrypt(c, key):
    obj = AES.new(key, AES.MODE_ECB)
    return obj.decrypt(c)


def aes_cbc_decrypt(c, key, iv):
    block_size = len(key)
    assert block_size == len(iv)

    msg = b''
    prev = iv
    obj = AES.new(key, AES.MODE_ECB)
    for b in grouper(c, block_size):
        b = bytes(b)
        msg += strxor(obj.decrypt(b), prev)
        prev = b

    return msg


def aes_cbc_encrypt(p, key, iv):
    block_size = len(key)
    assert block_size == len(iv)

    msg = b''
    prev = iv
    obj = AES.new(key, AES.MODE_ECB)
    for b in grouper(p, block_size):
        b = bytes(b)
        c = obj.encrypt(strxor(b, prev))
        msg += c
        prev = c

    return msg
