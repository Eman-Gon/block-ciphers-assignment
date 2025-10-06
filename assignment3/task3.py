from Crypto.Util.number import getPrime, inverse, GCD
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import random

def generate_rsa_keypair(bits=512):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    assert GCD(e, phi) == 1
    d = inverse(e, phi)
    return n, e, d

def rsa_encrypt(m, n, e):
    return pow(m, e, n)

def rsa_decrypt(c, n, d):
    return pow(c, d, n)

def aes_encrypt(key, msg, iv=b'0'*16):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(msg.encode(), 16))

def aes_decrypt(key, ct, iv=b'0'*16):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), 16).decode()

print("TASK 3 PART 1: Textbook RSA")

n, e, d = generate_rsa_keypair(512)
print("Generated RSA keypair")

m = int.from_bytes("Hello!".encode(), "big")
c = rsa_encrypt(m, n, e)
m_dec = rsa_decrypt(c, n, d)

print("Message encrypts and decrypts correctly:", m == m_dec)

print("\nTASK 3 PART 2: RSA Malleability Attack")

n, e, d = generate_rsa_keypair(512)

c_prime = pow(2, e, n)
s_prime = rsa_decrypt(c_prime, n, d)
print("Alice decrypts modified ciphertext to:", s_prime)

k_alice = hashlib.sha256(str(s_prime).encode()).digest()[:16]
k_mallory = hashlib.sha256(str(2).encode()).digest()[:16]

print("Keys match:", k_alice == k_mallory)

ct = aes_encrypt(k_alice, "Hi Bob!")
print("Mallory decrypts:", aes_decrypt(k_mallory, ct))

print("\nRSA Signature Malleability")

n, e, d = generate_rsa_keypair(512)

m1, m2 = 42, 17
sig1 = pow(m1, d, n)
sig2 = pow(m2, d, n)

sig3 = (sig1 * sig2) % n
m3 = (m1 * m2) % n

verified = pow(sig3, e, n)
print("Forged signature valid:", verified == m3)
