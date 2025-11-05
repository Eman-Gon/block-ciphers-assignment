from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import random

def dh_exchange(q, alpha):
    # ALICE'S  Generate her keys
    xa = random.randint(1, q-1)    # Alice picks SECRET private key (never shared) #might ask
    ya = pow(alpha, xa, q)         # Alice computes PUBLIC key: α^XA mod q #might ask
    
    # BOB'S Generate his keys  
    xb = random.randint(1, q-1)    # Bob picks SECRET private key (never shared) #might ask
    yb = pow(alpha, xb, q)         # Bob computes PUBLIC key: α^XB mod q #might ask
    
    # KEY EXCHANGE HAPPENS (YA and YB sent over public channel - everyone can see!)
    
    # BOTH COMPUTE SHARED SECRET
    s_alice = pow(yb, xa, q)       # Alice: YB^XA mod q (uses Bob's public + her private) #might ask
    s_bob = pow(ya, xb, q)         # Bob: YA^XB mod q (uses Alice's public + his private) #might ask
    
    print("Alice private:", xa, "public:", ya)
    print("Bob private:", xb, "public:", yb)
    print("Shared secret:", s_alice, "match:", s_alice == s_bob)  # Should be True! #might ask----------------------------
    
    # Hash the shared secret to get 128-bit AES key
    return hashlib.sha256(str(s_alice).encode()).digest()[:16]  # SHA256 produces uniform random bits #might ask-----------------------

def encrypt(key, msg):
    iv = b'0' * 16               
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(msg.encode(), 16))  # Pad to 16-byte blocks

def decrypt(key, ct):
    iv = b'0' * 16
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), 16).decode()

print("Testing q=37, alpha=5")
k1 = dh_exchange(37, 5)            # q=37 means only 36 possible private keys = WEAK! #might ask
c1 = encrypt(k1, "Hi Bob!")
print("Decrypts:", decrypt(k1, c1))

# TEST 2: LARGE PARAMETERS (SECURE - real-world size)
print("\nTesting 1024-bit parameters")
q = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371  # 1024-bit prime (IETF standard) #might ask
g = 0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5  # Generator
k2 = dh_exchange(q, g)             # Now 2^1024 possible keys = takes forever to break! #might ask-----------------------
c2 = encrypt(k2, "Hi Alice!")
print("Decrypts:", decrypt(k2, c2))