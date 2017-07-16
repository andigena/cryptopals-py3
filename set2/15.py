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


print(unpad_pkcs7(b'\x10'*16, 16))
print(unpad_pkcs7(b'\x00'*12 + b'\x04'*4, 16))

try:
    unpad_pkcs7(b'\x00'*11 + b'\x04'*4, 16)
    print('Should have thrown')
except RuntimeError as rt:
    print(rt)

try:
    unpad_pkcs7(b'\x00'*12 + b'\x22'*4, 16)
    print('Should have thrown')
except RuntimeError as rt:
    print(rt)

try:
    unpad_pkcs7(b'\x00'*12 + b'\x05'*4, 16)
    print('Should have thrown')
except RuntimeError as rt:
    print(rt)