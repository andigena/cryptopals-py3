def pkcs7(b, l):
    r = len(b) % l
    if r == 0:
        return b
    else:
        return b + bytes([l-r]*(l-r))

print(pkcs7(b'YELLOW SUBMARINE', 20))
