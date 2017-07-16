from math import ceil
from pprint import pprint
from set3.utilz import *
from set3.nineteen_inp import plaintexts


def hexdump(buf, bytes_per_line=16):
    def cross_line(line_len, crosses):
        '''Return a line made of '-' chars and '|' at the indexes in the crosses array.'''
        if isinstance(crosses, int):
            crosses = [crosses]
        line = ['|' if i in crosses else '-' for i in range(line_len)]
        return ''.join(line)

    offset_width_max = len(hex(len(buf))) - 2
    out = []
    header = ''.join(' {:02x} '.format(i) for i in range(bytes_per_line))
    out.append(' '*offset_width_max + '|' + header)
    out.append(cross_line(len(out[0]), offset_width_max))

    line_fmt = '{:0=%dx}|{}' % offset_width_max
    for idx, block in enumerate(blockify(buf, bytes_per_line)):
        values = ''.join(' {:02x} '.format(b) for b in block)

        out.append(line_fmt.format(idx * bytes_per_line, values))
    return '\n'.join(out)


# key = random_bytes(16)
key = b'\x00'*16
cyphers = [aes_ctr(b64decode(pt), key, 0, 0) for pt in plaintexts]
# [print(c) for c in cyphers]
print(cyphers[0], len(cyphers[0]))
print(hexdump(cyphers[0]))

# xors = [xor(c1, c2) for (c1, c2) in itertools.combinations(cyphers, 2)]
# zero_start = filter(lambda x: x.startswith(b'\x00'*3), xors)
# print(list(zero_start))
for c1, c2 in itertools.combinations(range(len(cyphers)), 2):
    xored = xor(cyphers[c1], cyphers[c2])
    if xored.startswith(b'\x00'*3):
        print(hexdump(xored))
        print(b64decode(plaintexts[c1]), b64decode(plaintexts[c2]))
        print()



