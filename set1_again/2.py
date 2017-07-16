from binascii import hexlify, unhexlify


def xor(s1, s2):
    assert len(s1) == len(s2)

    res = bytes(s1[i] ^ s2[i] for i in range(len(s1)))
    return res


print(hexlify(xor(
    unhexlify('1c0111001f010100061a024b53535009181c'),
    unhexlify('686974207468652062756c6c277320657965')
)))
