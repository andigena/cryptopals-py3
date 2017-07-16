from Crypto.Cipher import AES
from set1_again.utilz import *

obj = AES.new('YELLOW SUBMARINE', AES.MODE_ECB)
msg = b64decode(open('7.txt').read())
plaintext = obj.decrypt(msg)
print(plaintext)
