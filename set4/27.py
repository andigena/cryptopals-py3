import re
from set3.utilz import *

pre = b'comment1=cooking%20MCs;userdata='
app = b';comment2=%20like%20a%20pound%20of%20bacon'
key = random_bytes(16)
iv = key


def encrypt(inp):
    def sanitize(b):
        return re.sub(b'&|;', b'_', inp)

    pt = pre + sanitize(inp) + app
    return aes_cbc_encrypt(pkcs7(pt, 16), key, iv)


def is_authenticated(req):
    req = aes_cbc_decrypt(req, key, iv)
    if any(map(lambda c: c >= 0x80, req)):
        raise Exception('Invalid request: {}'.format(req.decode('latin1')))
    print(req)
    parts = req.split(b';')
    parts = dict(map(lambda x: x.split(b'='), parts))
    print(parts)
    if parts.get(b'admin', b'false') == b'true':
        return True

    return False


inp = b'A'*24
req1 = encrypt(inp)
print()

cipher_blocks = list(blockify(req1, 16))
req2 = cipher_blocks[0] + b'\x00'*16 + cipher_blocks[0]

try:
    is_authenticated(req2)
except Exception as e:
    resp = e.args[0].split(': ')[1].encode('latin1')
    resp_blocks = list(blockify(resp, 16))
    key_leak = xor(resp_blocks[0], resp_blocks[2])
    assert key == key_leak
