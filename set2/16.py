import re
from set2.utilz import *

pre = b'comment1=cooking%20MCs;userdata='
app = b';comment2=%20like%20a%20pound%20of%20bacon'
key = random_bytes(16)
iv = random_bytes(16)


def encrypt(inp):
    def sanitize(b):
        return re.sub(b'&|;', b'_', inp)

    pt = pre + sanitize(inp) + app
    return aes_cbc_encrypt(pkcs7(pt, 16), key, iv)


def is_authenticated(req):
    req = unpad_pkcs7(aes_cbc_decrypt(req, key, iv), 16)
    print(req)
    parts = req.split(b';')
    parts = dict(map(lambda x: x.split(b'='), parts))
    print(parts)
    if parts.get(b'admin', b'false') == b'true':
        return True

    return False


#

semicolon_flipped = ord(';') ^ 1
equals_flipped = ord('=') ^ 1
print(ord(';'), semicolon_flipped, chr(semicolon_flipped), ord('='), equals_flipped, chr(equals_flipped))

inp = b'aaaaa' + bytes([semicolon_flipped]) + b'admin' + bytes([equals_flipped]) + b'true'
req = encrypt(inp)
print(is_authenticated(req))

reqarr = bytearray(req)
reqarr[16 + 5] ^= 1
reqarr[16 + 11] ^= 1
print(is_authenticated(reqarr))
