from set3.utilz import *

ptlen = 512
pt = b'''[Chester Bennington:]
It starts with one...
[Mike Shinoda:]
One thing I don't know why
It doesn't even matter how hard you try
Keep that in mind, I designed this rhyme
To explain in due time

[Chester Bennington:]
All I know
[Mike Shinoda:]
Time is a valuable thing
Watch it fly by as the pendulum swings
Watch it count down to the end of the day
The clock ticks life away

[Chester Bennington:]
It's so unreal
[Mike Shinoda:]
Didn't look out below
Watch the time go right out the window
Trying to hold on did-didn't even know
I wasted it all just to watch you go

I kept everything inside and even though I tried, it all fell apart
What it meant to me will eventually be a memory of a time when I tried so hard

[Chester Bennington:]
I tried so hard
And got so far
But in the end
It doesn't even matter
I had to fall
To lose it all
But in the end
It doesn't even matter'''[:ptlen]
key = random_bytes(16)


def edit(c, key, off, nt):
    c = bytearray(c)
    l = len(nt)
    # do only entire blocks for now
    assert l % 16 == 0 and off % 16 == 0
    c[off:off+l] = aes_ctr(nt, key, 0, off // 16)
    return bytes(c)


def edit_api(c, off, nt):
    return edit(c, key, off, nt)


cipher = aes_ctr(pt, key, 0, 0)
recovered = b''
for i in range(0, ptlen, 16):
    newt = b'\x00'*16
    oldcipher = cipher[i:i+16]
    cipher = edit_api(cipher, i, newt)
    recovered += xor(cipher[i:i+16], oldcipher)

print(recovered)
