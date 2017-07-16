contents = map(bytes.fromhex, open('8.txt').read().splitlines())
for c in contents:
    for i in range(0, len(c) - 32, 16):
        needle = c[i:i+16]
        for j in range(i+16, len(c) - 16, 16):
            if needle == c[j:j+16]:
                print(c)
                print(i, j)
                print(needle, c[j:j+16])
                print()
