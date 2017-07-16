from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from set1_again.utilz import *


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


contents = b64decode(open('10.txt').read())
print(contents)
msg = aes_cbc_decrypt(contents, b'YELLOW SUBMARINE', b'\x00'*16)
print(msg)
print(aes_cbc_encrypt(msg, b'YELLOW SUBMARINE', b'\x00'*16))
