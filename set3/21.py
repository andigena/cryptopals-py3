class MT19937(object):
    w, n, m, r = (32, 624, 397, 31)
    m = 397
    r = 31
    a = 0x9908B0DF
    u, d = (11, 0xFFFFFFFF)
    s, b = (7, 0x9D2C5680)
    t, c = (15, 0xEFC60000)
    l = 18
    f = 1812433253
    bmask = 2**w - 1

    def __init__(self, seed):
        self.MT = [None] * MT19937.n
        self.index = MT19937.n + 1
        self.lower_mask = (1 << MT19937.r) - 1
        self.upper_mask = (~self.lower_mask) & MT19937.bmask

        self._seed_mt(seed)

    def _seed_mt(self, seed):

        self.index = MT19937.n
        self.MT[0] = seed & MT19937.bmask
        for i in range(1, MT19937.n):
            self.MT[i] = (MT19937.f * (self.MT[i-1] ^ (self.MT[i-1] >> (MT19937.w-2))) + i) & MT19937.bmask

    def extract_number(self):
        if self.index >= MT19937.n:
            if self.index > MT19937.n:
                raise 'Generator was never seeded'
            self._twist()

        y = self.MT[self.index]
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)

        self.index = self.index + 1
        return y & self.bmask

    def _twist(self):
        for i in range(MT19937.n):
            x = (self.MT[i] & self.upper_mask) + (self.MT[(i+1) % MT19937.n] & self.lower_mask)
            x = x & self.bmask
            xA = x >> 1
            if x % 2:
                xA = xA ^ MT19937.a
            self.MT[i] = self.MT[(i + MT19937.m) % MT19937.n] ^ xA

        self.index = 0


mt = MT19937(0x1)
print([mt.extract_number() for _ in range(15)])
