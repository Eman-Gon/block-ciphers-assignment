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

# NORMAL KEY GENERATION (before attack)
xa = random.randint(1, q-1)         # Alice's private key
ya = pow(alpha, xa, q)              # Alice's PUBLIC key (would normally send this) #might ask
print("Alice: private =", xa, "public =", ya)

xb = random.randint(1, q-1)         # Bob's private key
yb = pow(alpha, xb, q)              # Bob's PUBLIC key (would normally send this) #might ask
print("Bob: private =", xb, "public =", yb)

# *** THE ATTACK HAPPENS HERE ***
print("\nMallory replaces YA and YB with q =", q)  # Mallory intercepts and changes both! #might ask

# COMPUTING SHARED SECRETS (with tampered values)
s_alice = pow(q, xa, q)             # Alice computes q^XA mod q = 0 (always!) #might ask
s_bob = pow(q, xb, q)               # Bob computes q^XB mod q = 0 (always!) #might ask
s_mallory = 0                       # Mallory KNOWS the secret is 0! #might ask

print("Alice secret:", s_alice)     # Will be 0
print("Bob secret:", s_bob)         # Will be 0
print("Mallory knows:", s_mallory)  # She knows it's 0!

# ALL THREE DERIVE THE SAME KEY
k_alice = hashlib.sha256(str(s_alice).encode()).digest()[:16]      # Alice: SHA256(0)
k_mallory = hashlib.sha256(str(s_mallory).encode()).digest()[:16]  # Mallory: SHA256(0)

print("Keys match:", k_alice == k_mallory)  # TRUE - everyone has same key! #might ask

# MALLORY CAN DECRYPT EVERYTHING
c = aes_encrypt(k_alice, "Hi Bob!")         # Alice encrypts thinking it's secure
print("Mallory decrypts:", aes_decrypt(k_mallory, c))  # But Mallory can read it! #might ask

print("\nTASK 2 PART 2: Tamper with alpha")

# Test three malicious generator values
for mal_alpha, name in [(1, "1"), (q, "q"), (q-1, "q-1")]:  #might ask
    print(f"\nSetting alpha = {name}")
    
    # Alice and Bob use the BAD generator (don't know it's tampered)
    xa = random.randint(1, q-1)
    ya = pow(mal_alpha, xa, q)      # Using MALICIOUS α #might ask
    
    xb = random.randint(1, q-1)
    yb = pow(mal_alpha, xb, q)      # Using MALICIOUS α #might ask
    
    # Compute shared secret with bad generator
    s = pow(yb, xa, q)              # Secret is now PREDICTABLE! #might ask
    print("Shared secret:", s)
    # α=1: 1^anything = 1, so secret = 1
    # α=q: q^anything mod q = 0, so secret = 0
    # α=q-1: predictable (1 or q-1)
    
    # Mallory can decrypt because she knows what secret will be
    k = hashlib.sha256(str(s).encode()).digest()[:16]
    c = aes_encrypt(k, "Hi Bob!")
    print("Decrypts:", aes_decrypt(k, c))  # Attack works! #might ask