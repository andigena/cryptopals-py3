import re
from collections import OrderedDict
from set2.utilz import *

def parse_kv(s):
    d = OrderedDict()
    for kv in s.split(b'&'):
        k, v = kv.split(b'=')
        d[k] = v

    return d


def encode_kv(kv):
    def sanitize(inp):
        return re.sub(b'&|=', b'_', inp)

    parts = []
    for k, v in kv.items():
        parts.append(sanitize(k) + b'=' + sanitize(v))

    return b'&'.join(parts)


def profile_for(email):
    kv = OrderedDict([
        (b'email', email),
        (b'uid', str(profile_for.uid).encode('latin1')),
        (b'role', b'user')
    ])

    profile_for.uid += 1

    return encode_kv(kv)

profile_for.uid = 0
# KEY = random_bytes(16)
KEY = bytes([0]*16)


def encrypt_profile(p):
    return aes_ecb_encrypt(
        pkcs7(p, len(KEY)),
        KEY
    )


def decrypt_profile(c):
    return parse_kv(
        depkcs7(
            aes_ecb_decrypt(
                c, KEY
            ),
            len(KEY)
        )
    )


print(parse_kv(b'foo=bar&baz=qux&zap=zazzle'))
print(profile_for(b'fos@tartaly.com'))


# make a target block that has the 'user' part from its role starting at a new block boundary
target = profile_for(b'fos@tartaly.hu')
for idx, g in enumerate(grouper(pkcs7(target, 16), 16)):
    print(idx, bytes(g))

cypher = encrypt_profile(target)
print(decrypt_profile(cypher))


print()
# make the second block containing 'admin' with valid padding as its second block
pl = (16 - len(b'email=')) * b'a' + pkcs7(b'admin', 16)
pt = profile_for(pl)
for idx, g in enumerate(grouper(pkcs7(pt, 16), 16)):
    print(idx, bytes(g))

encrypted = encrypt_profile(pt)
c_and_p = encrypted[16:32]


# replace the the 'user' block with the 'admin' one

forged = cypher[:32] + c_and_p
print(decrypt_profile(forged))
