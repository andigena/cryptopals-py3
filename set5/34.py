import hashlib
from set5.utilz import *

r'''
A = g**a mod p
B = g**b mod p
S_A = g**a*p mod p = g**a mod p = A
S_B = g**b*p mod p = g**b mod p = B
the secrets of both parties will equal to the pubkey of the other
'''
p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2


def kex():
    a = random.randint(0, p)
    A = pow(g, a, p)
    # send it over to B

    b = random.randint(0, p)
    B = pow(g, b, p)

    # Both sides calculate the secret using the MITM-ed pubkey of the other
    S_A = pow(B, p, p)
    S_B = pow(A, p, p)
    # They calculated secrets should be equal to the pubkey of the other party
    # Mallory now know both their secrets
    print(S_A == B)
    print(S_B == A)

    return S_A, S_B


def sha1sum(msg):
    h = hashlib.sha1()
    h.update(msg)
    return h.digest()

S_A, S_B = kex()
K_A = sha1sum(S_A.to_bytes((S_A.bit_length() + 7) // 8, 'big'))[:16]
K_B = sha1sum(S_B.to_bytes((S_B.bit_length() + 7) // 8, 'big'))[:16]
print(K_A, K_B)