from __future__ import print_function, unicode_literals
from Crypto.Cipher import AES
import pyDes
import onetimepad
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import Crypto
from Crypto import Random
import libnum
import sys
from os import urandom
from flask import Flask, request
from flask_cors import CORS
import random
import string


app = Flask(__name__)
CORS(app)


def randStr(chars=string.ascii_uppercase + string.digits, N=24):
    return ''.join(random.choice(chars) for _ in range(N))


def aesUtil(data):
    key = b'Sixteen byte key'
    cipher = AES.new(key, AES.MODE_EAX)

    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

    c = str(ciphertext)
    if c == str(ciphertext):
        plaintext = cipher.decrypt(ciphertext)
        return(ciphertext, plaintext.decode('utf-8'))


def de(data):
    k = pyDes.triple_des(randStr(), pyDes.CBC,
                         "\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
    d = k.encrypt(data)
    c = str(d)
    if c == str(d):
        return(d, k.decrypt(d).decode('utf-8'))


def otpUtil(i):
    ot = randStr(string.ascii_letters + string.digits + string.punctuation, 50)
    cipher = onetimepad.encrypt(i, ot)

    c = str(cipher)
    msg = onetimepad.decrypt(c, ot)

    return(cipher, msg)


def rsaUtil(msg):
    bits = 60

    p = Crypto.Util.number.getPrime(
        bits, randfunc=Crypto.Random.get_random_bytes)
    q = Crypto.Util.number.getPrime(
        bits, randfunc=Crypto.Random.get_random_bytes)

    n = p*q
    PHI = (p-1)*(q-1)

    e = 65537
    d = libnum.invmod(e, PHI)

    m = bytes_to_long(msg.encode('utf-8'))

    c = pow(m, e, n)

    ci = c
    if ci == c:
        res = pow(c, d, n)
        return(c, long_to_bytes(res).decode('utf-8'))


def xorUtil(message):

    def genkey(length: int) -> bytes:
        """Generate key."""
        return urandom(length)

    def xor_strings(s, t) -> bytes:
        """xor two strings together."""
        if isinstance(s, str):
            # Text strings contain single characters
            return b"".join(chr(ord(a) ^ ord(b)) for a, b in zip(s, t))
        else:
            # Python 3 bytes objects contain integer values in the range 0-255
            return bytes([a ^ b for a, b in zip(s, t)])

    key = genkey(len(message))

    cipherText = xor_strings(message.encode('utf8'), key)
    #print('cipherText:', cipherText)

    c = str(cipherText)
    if c == str(cipherText):
        decrypted = xor_strings(cipherText, key).decode('utf8')
        return(cipherText, decrypted)


@app.route('/')
def home():
    return {"msg": "Made with ♥ by Bhanu Prakash"}


@app.route('/aes', methods=["POST"])
def aes():
    msg = request.get_json()
    data = bytes(msg["msg"], 'utf-8')
    c, d = aesUtil(data)
    return {"plain": str(d), "cipher": str(c)}


@app.route('/3des', methods=["POST"])
def des():
    msg = request.get_json()
    data = str(msg["msg"])
    c, d = de(data)
    return {"plain": str(d), "cipher": str(c)}


@app.route('/otp', methods=["POST"])
def otp():
    msg = request.get_json()
    data = str(msg["msg"])
    c, d = otpUtil(data)
    return {"plain": str(d), "cipher": str(c)}


@app.route('/rsa', methods=["POST"])
def rsa():
    msg = request.get_json()
    data = str(msg["msg"])
    c, d = rsaUtil(data)
    return {"plain": str(d), "cipher": str(c)}


@app.route('/xor', methods=["POST"])
def xor():
    msg = request.get_json()
    data = str(msg["msg"])
    c, d = xorUtil(data)
    return {"plain": str(d), "cipher": str(c)}


if __name__ == "__main__":
    app.run(debug=False)
