from Crypto import Hash
from set3.utilz import *


def hmac_sha1(key, msg):
    h = Hash.SHA1.new()
    h.update(key + msg)
    return h.digest()


def authenticate(key, msg, hmac):
    calculated_hmac = hmac_sha1(key, msg)
    return calculated_hmac == hmac

key = b'\x00'*16
message = b'authenticated message'
hmac = hmac_sha1(key, message)

print(hexdump(hmac_sha1(b'aa', b'fos')))
print(authenticate(key, message + b'aa', hmac))
