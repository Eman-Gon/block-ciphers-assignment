from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import random

def aes_encrypt(key, msg, iv=b'0'*16):
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg.encode(), 16))

def aes_decrypt(key, ct, iv=b'0'*16):
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16).decode()

q, alpha = 37, 5

print("TASK 2 PART 1: Replace YA and YB with q")

xa = random.randint(1, q-1)
ya = pow(alpha, xa, q)
print("Alice: private =", xa, "public =", ya)

xb = random.randint(1, q-1)
yb = pow(alpha, xb, q)
print("Bob: private =", xb, "public =", yb)

print("\nMallory replaces YA and YB with q =", q)

s_alice = pow(q, xa, q)
s_bob = pow(q, xb, q)
s_mallory = 0

print("Alice secret:", s_alice)
print("Bob secret:", s_bob)
print("Mallory knows:", s_mallory)

k_alice = hashlib.sha256(str(s_alice).encode()).digest()[:16]
k_mallory = hashlib.sha256(str(s_mallory).encode()).digest()[:16]

print("Keys match:", k_alice == k_mallory)

c = aes_encrypt(k_alice, "Hi Bob!")
print("Mallory decrypts:", aes_decrypt(k_mallory, c))

print("TASK 2 PART 2: Tamper with alpha")

for mal_alpha, name in [(1, "1"), (q, "q"), (q-1, "q-1")]:
    print(f"\nSetting alpha = {name}")
    xa = random.randint(1, q-1)
    ya = pow(mal_alpha, xa, q)
    xb = random.randint(1, q-1)
    yb = pow(mal_alpha, xb, q)
    
    s = pow(yb, xa, q)
    print("Shared secret:", s)
    
    k = hashlib.sha256(str(s).encode()).digest()[:16]
    c = aes_encrypt(k, "Hi Bob!")
    print("Decrypts:", aes_decrypt(k, c))
