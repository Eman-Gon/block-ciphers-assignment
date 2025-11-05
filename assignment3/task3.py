from Crypto.Util.number import getPrime, inverse, GCD
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import random

def generate_rsa_keypair(bits=512):
    p = getPrime(bits // 2)        # First random prime (256 bits) #might ask
    q = getPrime(bits // 2)        # Second random prime (256 bits) #might ask
    n = p * q                      # Modulus n = p*q (this is PUBLIC) #might ask
    phi = (p - 1) * (q - 1)        # Euler's totient φ(n) (kept SECRET) #might ask
    e = 65537                      # Public exponent (commonly used value) #might ask
    assert GCD(e, phi) == 1        # Make sure e and φ(n) are coprime
    d = inverse(e, phi)            # Private exponent: e*d ≡ 1 (mod φ(n)) #might ask
    return n, e, d                 # Public key: (n,e), Private key: (n,d)

def rsa_encrypt(m, n, e):
    return pow(m, e, n)            # Encrypt: C = M^e mod n #might ask

def rsa_decrypt(c, n, d):
    return pow(c, d, n)            # Decrypt: M = C^d mod n #might ask

def aes_encrypt(key, msg, iv=b'0'*16):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(msg.encode(), 16))

def aes_decrypt(key, ct, iv=b'0'*16):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), 16).decode()

print("TASK 3 PART 1: Textbook RSA")

n, e, d = generate_rsa_keypair(512)
print("Generated RSA keypair")

m = int.from_bytes("Hello!".encode(), "big")  # Convert string to integer #might ask
c = rsa_encrypt(m, n, e)                      # Encrypt: C = M^e mod n
m_dec = rsa_decrypt(c, n, d)                  # Decrypt: M = C^d mod n

print("Message encrypts and decrypts correctly:", m == m_dec)  # Should be True

print("\nTASK 3 PART 2: RSA Malleability Attack")

n, e, d = generate_rsa_keypair(512)

# *** MALLORY'S ATTACK ***
c_prime = pow(2, e, n)                # Mallory crafts: C' = 2^e mod n #might ask

# Alice decrypts Mallory's ciphertext
s_prime = rsa_decrypt(c_prime, n, d)  # Alice gets: (2^e)^d = 2^(e*d) = 2^1 = 2 #might ask
print("Alice decrypts modified ciphertext to:", s_prime)  # Will be 2!

# BOTH DERIVE THE SAME KEY
k_alice = hashlib.sha256(str(s_prime).encode()).digest()[:16]  # Alice: SHA256(2)
k_mallory = hashlib.sha256(str(2).encode()).digest()[:16]      # Mallory: SHA256(2) #might ask

print("Keys match:", k_alice == k_mallory)  # TRUE - same key! #might ask

# MALLORY CAN DECRYPT EVERYTHING
ct = aes_encrypt(k_alice, "Hi Bob!")        # Alice encrypts thinking it's secure
print("Mallory decrypts:", aes_decrypt(k_mallory, ct))  # Mallory reads it! #might ask

print("\nRSA Signature Malleability")

n, e, d = generate_rsa_keypair(512)

# Alice signs two messages
m1, m2 = 42, 17
sig1 = pow(m1, d, n)               # Alice signs 42: sig = 42^d mod n #might ask
sig2 = pow(m2, d, n)               # Alice signs 17: sig = 17^d mod n #might ask

# *** MALLORY FORGES A SIGNATURE ***
sig3 = (sig1 * sig2) % n           # Multiply signatures: (42^d * 17^d) = (42*17)^d #might ask
m3 = (m1 * m2) % n                 # New message: 42 * 17 = 714 #might ask

# Verify the forged signature
verified = pow(sig3, e, n)         # Check: sig3^e should equal m3 #might ask
print("Forged signature valid:", verified == m3)  # TRUE - forgery works! #might ask