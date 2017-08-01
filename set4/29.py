import struct
from set4.utilz import *

key = b'fostartaly'
message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
mac, internal_state = mac_sha1(key, message)
state = [struct.unpack('>I', b)[0] for b in blockify(mac, 4)]
assert state == internal_state
attack_str = b'admin=true'

# we have to guess the key size to create the proper padding at the end of the original message
for guessed_len in range(16):
    print('\nIteration ', guessed_len)
    h = SHA1(state=state[:])
    prefix_size = 128   # might need to change this if the key + message pads to a longer size
    h.update(attack_str, prefix_size)
    forged_msg = h.padding(b'\x00' * guessed_len + message)[guessed_len:] + attack_str
    print('Forged msg: ', forged_msg)
    forged_mac, _ = h.digest()
    print('Forged mac: ', forged_mac)

    if authenticate(key, forged_msg, forged_mac):
        print('Found key len: {}'.format(guessed_len))
        print('Produced message with valid MAC')
        break
