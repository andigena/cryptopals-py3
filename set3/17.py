from set3.utilz import *

strings = [
    b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
    b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
    b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
    b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
    b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
    b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
    b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
    b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
    b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
    b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93',
]

strings = list(map(b64decode, strings))
key = random_bytes(16)
iv = random_bytes(16)

s = b''
def encrypt():
    global s
    s = random.choice(strings)
    # s = strings[1]
    return aes_cbc_encrypt(pkcs7(s, 16), key, iv), iv


def oracle(c):
    p = aes_cbc_decrypt(c, key, iv)
    try:
        unpad_pkcs7(p, 16)
    except:
        return False

    return True

c, iv = encrypt()
pt = pkcs7(s, 16)
print(len(c), c)
print(len(pt), pt)
print(aes_cbc_decrypt(c, key, iv))
print(oracle(c))

known = bytearray()
for block in range(len(c) // 16):
    padding_mask = bytearray([0] * 16)  # the mask needed to create the correct padding in the last block
    for padding in range(1, 17):
        print()
        print('known: ', known)
        print('padding mask: ', padding_mask)
        for guess in range(0, 256):
            tmp = bytearray(iv + c[:-(block * 16)] if block else c)
            lll = len(tmp)
            dump(tmp, 16)
            for i in range(16):
                tmp[-17-i] ^= padding_mask[15-i]

            dump(tmp, 16)
            tmp[-16 - padding] ^= guess
            dump(tmp, 16)


            if oracle(tmp):
                # ensure that this is indeed the correct padding
                # by messing with the byte before and seeing if it's still good
                if padding != 16:
                    tmp[-16 - padding - 1] ^= 1
                    if not oracle(tmp):
                        continue

                val = padding ^ guess
                print(guess, hex(val), chr(val))
                known.insert(0, val)
                if known != pt[-len(known):]:
                    print(len(known), known)
                    print(pt[-len(known):])
                    assert False

                padding_mask[-padding] = val ^ (padding + 1)
                # update the rest of the padding mask
                for pm_idx in range(-1, -padding, -1):
                    orig_value = padding_mask[pm_idx] ^ padding
                    padding_mask[pm_idx] = orig_value ^ (padding + 1)

                break

print(known)