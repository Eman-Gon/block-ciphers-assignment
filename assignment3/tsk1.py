# ============================================================================
# Task 1: Diffie-Hellman Key Exchange
# ============================================================================
# Purpose: Shows how two parties can agree on a shared secret over a public 
#          channel without ever transmitting the secret itself.
#
# Key Insight: Even if an eavesdropper sees the public values (YA and YB),
#              they cannot compute the shared secret without solving the
#              discrete logarithm problem.
# ============================================================================

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import random

def dh_exchange(q, alpha):
    """
    Simulates Diffie-Hellman key exchange between Alice and Bob
    
    Parameters:
        q     = prime modulus (defines the field we're working in)
        alpha = generator (a number that generates a large subgroup)
    
    Returns:
        16-byte AES key derived from shared secret
    
    Protocol Flow:
        1. Alice picks random private XA, computes public YA = α^XA mod q
        2. Bob picks random private XB, computes public YB = α^XB mod q  
        3. They exchange YA and YB over the public channel
        4. Alice computes secret S = YB^XA mod q
        5. Bob computes secret S = YA^XB mod q
        6. Both get the same S because: YB^XA = (α^XB)^XA = α^(XB*XA) = α^(XA*XB) = (α^XA)^XB = YA^XB
    """
    
    # ========================================================================
    # ALICE'S SIDE - Generate private and public keys
    # ========================================================================
    
    # Step 1a: Alice picks a random private key XA in range [1, q-1]
    # This is kept SECRET - never transmitted
    xa = random.randint(1, q-1)
    
    # Step 1b: Alice computes her public key YA = alpha^XA mod q
    # pow(base, exponent, modulus) is Python's efficient modular exponentiation
    # This uses fast exponentiation, not naive repeated multiplication
    ya = pow(alpha, xa, q)
    
    # ========================================================================
    # BOB'S SIDE - Generate private and public keys
    # ========================================================================
    
    # Step 2a: Bob picks a random private key XB in range [1, q-1]  
    # This is kept SECRET - never transmitted
    xb = random.randint(1, q-1)
    
    # Step 2b: Bob computes his public key YB = alpha^XB mod q
    yb = pow(alpha, xb, q)
    
    # ========================================================================
    # PUBLIC KEY EXCHANGE (these values are sent over insecure channel)
    # ========================================================================
    # Alice sends YA to Bob    →
    # Bob sends YB to Alice    ←
    # An eavesdropper can see: q, alpha, YA, YB
    # But CANNOT easily compute XA or XB (discrete logarithm problem)
    # ========================================================================
    
    # ========================================================================
    # SHARED SECRET COMPUTATION
    # ========================================================================
    
    # Step 3a: Alice receives YB and computes shared secret
    # S = YB^XA mod q
    # Substituting: S = (alpha^XB)^XA = alpha^(XB * XA) mod q
    s_alice = pow(yb, xa, q)
    
    # Step 3b: Bob receives YA and computes shared secret
    # S = YA^XB mod q  
    # Substituting: S = (alpha^XA)^XB = alpha^(XA * XB) mod q
    s_bob = pow(ya, xb, q)
    
    # MATHEMATICAL PROOF THEY'RE EQUAL:
    # Alice's: YB^XA = (α^XB)^XA = α^(XB*XA)
    # Bob's:   YA^XB = (α^XA)^XB = α^(XA*XB)
    # Since multiplication is commutative: XB*XA = XA*XB
    # Therefore: s_alice = s_bob ✓
    
    # ========================================================================
    # VERIFICATION & KEY DERIVATION
    # ========================================================================
    
    # Display for demonstration purposes
    print("Alice private:", xa, "public:", ya)
    print("Bob private:", xb, "public:", yb)
    print("Shared secret:", s_alice, "match:", s_alice == s_bob)
    
    # Step 4: Derive symmetric encryption key from shared secret
    # Why hash instead of using secret directly?
    # 1. Shared secret might not be uniformly distributed
    # 2. SHA-256 acts as a Key Derivation Function (KDF)
    # 3. Produces exactly 32 bytes, we take first 16 for AES-128
    # 4. Any structure in the secret is destroyed by the hash
    return hashlib.sha256(str(s_alice).encode()).digest()[:16]


def encrypt(key, msg):
    """
    Encrypt message using AES-CBC with the derived key
    
    Parameters:
        key = 16-byte AES key (from DH key exchange)
        msg = plaintext message string
        
    Returns:
        ciphertext bytes
    """
    # Fixed IV (Initialization Vector) for simplicity
    # WARNING: In production, NEVER reuse IVs! Generate random IV for each encryption.
    # We use fixed IV here only to simplify the lab demonstration.
    iv = b'0' * 16  # 16 bytes of zeros
    
    # Create AES cipher in CBC (Cipher Block Chaining) mode
    # CBC mode: each plaintext block is XORed with previous ciphertext block
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad message to multiple of 16 bytes (AES block size requirement)
    # PKCS#7 padding: if need N bytes, add N bytes each with value N
    # Example: "Hello" (5 bytes) → "Hello\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b" (16 bytes)
    return cipher.encrypt(pad(msg.encode(), 16))


def decrypt(key, ct):
    """
    Decrypt ciphertext using AES-CBC with the derived key
    
    Parameters:
        key = 16-byte AES key (same one used for encryption)
        ct  = ciphertext bytes
        
    Returns:
        plaintext message string
    """
    # Use same IV that was used for encryption
    iv = b'0' * 16
    
    # Create AES cipher with same parameters
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt and remove padding
    # unpad() validates padding and removes it
    # .decode() converts bytes back to string
    return unpad(cipher.decrypt(ct), 16).decode()


# ============================================================================
# TEST 1: Small Parameters (Toy Example)
# ============================================================================
# Purpose: Demonstrate the protocol works with simple numbers
# Security: INSECURE - an attacker can brute force XA by trying all 36 values
# ============================================================================

print("Testing q=37, alpha=5")
print("=" * 60)

# q=37: small prime modulus (only for demonstration!)
# alpha=5: generator (5 generates a large subgroup mod 37)
k1 = dh_exchange(37, 5)  # Generate shared AES key

# Encrypt a message using the derived key
c1 = encrypt(k1, "Hi Bob!")

# Decrypt to verify it works
print("Decrypts:", decrypt(k1, c1))

# WHY THIS IS INSECURE:
# - With q=37, XA can only be one of 36 values (1 through 36)
# - An attacker can try all 36: compute 5^i mod 37 for i=1..36
# - When 5^i matches the observed YA, they found XA!
# - Takes milliseconds on modern hardware
print()


# ============================================================================
# TEST 2: Real 1024-bit Parameters (IETF Standard)
# ============================================================================
# Purpose: Show that the protocol scales to cryptographically secure sizes
# Security: SECURE - discrete log with 1024-bit numbers is computationally hard
# ============================================================================

print("Testing 1024-bit parameters")
print("=" * 60)

# These are standardized parameters from IETF RFC 2409
# Used in real protocols like IPsec IKE

# q: 1024-bit prime modulus (309 decimal digits!)
# This is a "safe prime" (q = 2p + 1 where p is also prime)
q = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371

# g: 1024-bit generator
# This generates a subgroup of size (q-1)/2, which is also prime
g = 0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5

# Generate shared key with cryptographically strong parameters
k2 = dh_exchange(q, g)

# Encrypt a message
c2 = encrypt(k2, "Hi Alice!")

# Decrypt to verify
print("Decrypts:", decrypt(k2, c2))

# WHY THIS IS SECURE:
# - With 1024-bit q, there are approximately 2^1024 possible private keys
# - Brute force: would take longer than age of universe
# - Best known attack: General Number Field Sieve (GNFS)
#   - Still requires ~2^80 operations for 1024-bit modulus
#   - Considered secure against classical computers
# - Note: Quantum computers can break this (Shor's algorithm)
#   - This is why post-quantum crypto is being developed

# ============================================================================
# KEY TAKEAWAYS
# ============================================================================
# 1. Parameter size is CRITICAL for security
#    - Small (q=37): trivial to break
#    - Large (1024-bit): computationally infeasible
#
# 2. The protocol is secure against PASSIVE eavesdroppers
#    - They see: q, α, YA, YB
#    - They need: XA or XB (discrete log problem - hard!)
#
# 3. But NOT secure against ACTIVE attackers (see Task 2!)
#    - No authentication of public keys
#    - Man-in-the-middle attacks possible
#
# 4. Modern use: Combined with authentication (signatures, certificates)
#    - TLS 1.3: Signed DH exchanges
#    - Signal: Authenticated key agreement
# ============================================================================