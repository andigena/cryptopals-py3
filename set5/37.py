from multiprocessing import Process, Pipe
from collections import namedtuple
from Crypto.Hash import SHA
from set5.utilz import *


Parameters = namedtuple('parameters', ['N', 'g', 'k', 'I', 'P'])
p = Parameters(N, 2, 3, b'a@a.com', b'passw0rd')


def calc_u(A, B):
    uH = hex(A) + hex(B)
    uH = sha256_hexdigest(uH.encode())
    return int(uH, 16)


def calc_x(P, salt):
    xH = sha256_hexdigest(salt + P)
    x = int('0x' + xH, 16)
    return x


class Server():
    def __init__(self, params):
        self.b = random.randint(1, N)
        self.salt = random_bytes(4)
        x = calc_x(params.P, self.salt)
        self.v = pow(params.g, x, params.N)
        self.p = params

    def handle(self, conn):
        I, A = conn.recv()
        print(I, A)
        B = self.p.k * self.v + pow(self.p.g, self.b, self.p.N)
        conn.send([self.salt, B])
        u = calc_u(A, B)
        S = pow(A * pow(self.v, u, N),
                self.b,
                self.p.N)
        print('Server S: ', S)
        K = sha256_hexdigest(hex(S).encode()).encode()
        mac = hmac_sha256digest(K, self.salt)
        print(u, K)
        client_mac = conn.recv()
        success = hmac.compare_digest(mac, client_mac)
        if success:
            conn.send('OK')
        else:
            conn.send('FAILURE')


def serve(r):
    s = Server(params=p)
    s.handle(r)


class Client():
    def __init__(self, params):
        self.a = random.randint(1, N)
        self.p = params

    def connect_zero(self, conn):
        A = 0
        conn.send([self.p.I, A])
        salt, B = conn.recv()
        u = calc_u(A, B)
        x = calc_x(self.p.P, salt)
        S = 0
        print('Client S: ', S)
        K = sha256_hexdigest(hex(S).encode()).encode()
        print(u, K)
        conn.send(hmac_sha256digest(K, salt))
        print(conn.recv())

    def connect_multiple_of_N(self, conn):
        A = self.p.N
        conn.send([self.p.I, A])
        salt, B = conn.recv()
        u = calc_u(A, B)
        x = calc_x(self.p.P, salt)
        S = 0
        print('Client S: ', S)
        K = sha256_hexdigest(hex(S).encode()).encode()
        print(u, K)
        conn.send(hmac_sha256digest(K, salt))
        print(conn.recv())

def client(r):
    attack_params = Parameters(N, 2, 3, b'a@a.com', b'nottheoriginalpw')
    c = Client(attack_params)
    # c.connect_zero(r)
    c.connect_multiple_of_N(r)


if __name__ == '__main__':
    server_conn, client_conn = Pipe()
    s = Process(target=serve, args=(server_conn,))
    c = Process(target=client, args=(client_conn,))
    s.start(), c.start()
