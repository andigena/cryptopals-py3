import binascii
import hmac
import operator
import urllib
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pprint import pprint

import requests

port = 8082
key = b'\x00'*16
contents = b'TOTAL SECRET'

with open('secret', 'wb') as s:
    s.write(contents)
    mac = hmac.new(key, contents, digestmod='sha1')
    digest = mac.digest()
    print('HMAC of secret: {}'.format(digest))

# HTTPRequestHandler class
class testHTTPServer_RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return
    # GET
    def do_GET(self):
        def insecure_compare(b1, b2):
            if len(b1) != len(b2):
                print(len(b1), len(b2), b1, b2)
                return False

            for i in range(len(b1)):
                if b1[i] != b2[i]:
                    return False
                time.sleep(0.05)
            return True

        parts = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(parts[3])
        try:
            f = open(q['file'][0], 'rb').read()
        except Exception as e:
            print(e)
            self.send_response(404)
            return
        mac = hmac.new(key, f, digestmod='sha1')
        digest = mac.digest()
        if insecure_compare(digest, binascii.unhexlify(q['signature'][0])):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'OK')
            return
        else:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'fuk')
            return


def run():
    print('starting server...')
    # Server settings
    # Choose port 8080, for port 80, which is normally used for a http server, you need root access
    server_address = ('127.0.0.1', port)
    httpd = HTTPServer(server_address, testHTTPServer_RequestHandler)
    print('running server...')
    httpd.serve_forever()


rt = threading.Thread(target=run)
rt.setDaemon(True)
rt.start()

bruted = b''
time_per_byte = {}
i = 0
while i < 20:
    byte_t0 = time.time()
    results = {}
    for guess in range(256):
        sign = bruted + bytes([guess]) + b'\x00'*(20 - len(bruted) - 1)
        payload = {
            'file': 'secret',
            'signature': binascii.hexlify(sign)
        }
        avg = 0
        num_of_tries = 1
        for _ in range(num_of_tries):
            t0 = time.time()
            r = requests.get('http://127.0.0.1:{}/test'.format(port), params=payload)
            delta = time.time() - t0
            avg += delta
        avg = avg / num_of_tries
        results[guess] = avg

        if guess % 64 == 0:
            print('Byte {}, guess {}'.format(i, guess))

    byte_delta = time.time() - byte_t0
    if i > 0 and byte_delta - time_per_byte[i-1] < 10:
        i -= 1
        print('Detected wrong guess, backtracking from {} to {} ({} - {})'.format(i, i-1, bruted, bruted[:-1]))
        bruted = bruted[:-1]
        continue

    time_per_byte[i] = byte_delta
    slowest = max(results.items(), key=operator.itemgetter(1))
    bruted += bytes([slowest[0]])
    if not digest.startswith(bruted):
        pprint(time_per_byte)
    print(slowest, bruted)
    i += 1

print(bruted)
print(time_per_byte)