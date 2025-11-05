# ============================================================================
# Task 3: RSA Encryption and Malleability Attacks
# ============================================================================
# Purpose: Demonstrates why "textbook" RSA (raw exponentiation) is insecure
#
# What is Textbook RSA?
#   - Encryption: C = M^e mod n
#   - Decryption: M = C^d mod n  
#   - No padding, no randomization
#
# Why is it insecure?
#   1. DETERMINISTIC: Same message always produces same ciphertext
#   2. MALLEABLE: Attacker can manipulate ciphertext to control plaintext
#   3. MULTIPLICATIVE: E(m1) * E(m2) = E(m1*m2)
#
# Real-World Use: NEVER use textbook RSA!
#   - Use RSA-OAEP for encryption (adds randomness)
#   - Use RSA-PSS for signatures (adds randomness)
# ============================================================================

from Crypto.Util.number import getPrime, inverse, GCD
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import random

def generate_rsa_keypair(bits=512):
    """
    Generate RSA key pair
    
    Parameters:
        bits = size of modulus n in bits (default 512 for fast demo)
               Production uses 2048 or 4096 bits
    
    Returns:
        (n, e, d) where:
          - n = modulus (product of two primes)
          - e = public exponent  
          - d = private exponent
          - (n, e) is the public key
          - (n, d) is the private key
    
    RSA Security:
        - Based on difficulty of factoring n = p*q
        - If you know p and q, you can compute d
        - If you only know n, factoring is hard (for large n)
    """
    
    # ========================================================================
    # STEP 1: Generate two random prime numbers
    # ========================================================================
    # We need two distinct primes p and q
    # getPrime(k) returns a random k-bit prime number
    
    p = getPrime(bits // 2)  # First prime (256 bits for 512-bit RSA)
    q = getPrime(bits // 2)  # Second prime (256 bits for 512-bit RSA)
    
    # Note: p and q must be kept SECRET!
    # Anyone who knows p and q can compute the private key d
    
    # ========================================================================
    # STEP 2: Compute RSA modulus n
    # ========================================================================
    # The modulus n is the product of the two primes
    # This will be a 512-bit number (public)
    n = p * q
    
    # Security note: Factoring n back into p and q is hard when n is large
    # Current recommendations: n ≥ 2048 bits (we use 512 for speed)
    
    # ========================================================================
    # STEP 3: Compute Euler's totient function φ(n)
    # ========================================================================
    # φ(n) counts numbers less than n that are coprime with n
    # For n = p*q where p,q are prime: φ(n) = (p-1)(q-1)
    # 
    # Why we need this: Used to compute the private exponent d
    # φ(n) must be kept SECRET (if leaked, can compute d)
    phi = (p - 1) * (q - 1)
    
    # Mathematical background:
    # Euler's theorem: a^φ(n) ≡ 1 (mod n) for any a coprime to n
    # This is why RSA works: (M^e)^d = M^(e*d) = M^1 = M
    
    # ========================================================================
    # STEP 4: Choose public exponent e
    # ========================================================================
    # Common choice: e = 65537 = 2^16 + 1
    # Why this value?
    #   - Large enough to prevent some attacks
    #   - Small enough for fast encryption (only 2 bits set to 1)
    #   - Prime (guarantees coprime with most φ(n))
    e = 65537
    
    # Verify that e and φ(n) are coprime (required for RSA)
    # GCD(e, φ(n)) = 1 means they share no common factors
    assert GCD(e, phi) == 1, "e and φ(n) must be coprime!"
    
    # Other common values for e: 3, 17, 257
    # Very small e (like 3) can have security issues
    
    # ========================================================================
    # STEP 5: Compute private exponent d
    # ========================================================================
    # d is the modular multiplicative inverse of e modulo φ(n)
    # Meaning: e * d ≡ 1 (mod φ(n))
    # 
    # Why this works: 
    #   (M^e)^d = M^(e*d) = M^(1 + k*φ(n)) for some integer k
    #           = M * M^(k*φ(n))
    #           = M * (M^φ(n))^k  
    #           = M * 1^k          (by Euler's theorem)
    #           = M                 
    d = inverse(e, phi)
    
    # The inverse() function uses the Extended Euclidean Algorithm
    # It finds d such that: e*d mod φ(n) = 1
    
    # ========================================================================
    # RETURN PUBLIC AND PRIVATE KEY COMPONENTS
    # ========================================================================
    # Public key:  (n, e) - can be shared with anyone
    # Private key: (n, d) - must be kept SECRET
    # 
    # Note: We should also keep p, q, and φ(n) secret
    #       (but we don't return them as they're not needed for enc/dec)
    
    return n, e, d


def rsa_encrypt(m, n, e):
    """
    Textbook RSA encryption: c = m^e mod n
    
    Parameters:
        m = plaintext message (as integer, must be < n)
        n = modulus (from public key)
        e = public exponent (from public key)
    
    Returns:
        c = ciphertext (integer)
    
    WARNING: This is textbook RSA - INSECURE!
             In production, use RSA-OAEP padding
    """
    # Modular exponentiation: c = m^e mod n
    # pow(base, exponent, modulus) uses fast exponentiation
    # Much faster than (m**e) % n for large numbers
    return pow(m, e, n)


def rsa_decrypt(c, n, d):
    """
    Textbook RSA decryption: m = c^d mod n
    
    Parameters:
        c = ciphertext (integer)
        n = modulus (from public key, also part of private key)
        d = private exponent (from private key, SECRET)
    
    Returns:
        m = plaintext message (integer)
    
    Why this works:
        c^d = (m^e)^d = m^(e*d) ≡ m^1 ≡ m (mod n)
        Because e*d ≡ 1 (mod φ(n)) by construction
    """
    return pow(c, d, n)


def aes_encrypt(key, msg, iv=b'0'*16):
    """
    Encrypt message with AES-CBC
    
    Used to encrypt actual messages after RSA key exchange
    (RSA is slow, AES is fast)
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(msg.encode(), 16))


def aes_decrypt(key, ct, iv=b'0'*16):
    """Decrypt ciphertext with AES-CBC"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), 16).decode()


# ============================================================================
# PART 1: Verify Textbook RSA Works
# ============================================================================
# First, let's verify that the basic encryption/decryption works correctly
# ============================================================================

print("TASK 3 PART 1: Textbook RSA")
print("=" * 60)

# Generate a 512-bit RSA keypair
# Returns: (n, e, d) where n is 512 bits
n, e, d = generate_rsa_keypair(512)
print("Generated RSA keypair")
print(f"  Modulus n: {n.bit_length()} bits")
print(f"  Public exponent e: {e}")
print(f"  Private exponent d: {d.bit_length()} bits")

# ========================================================================
# Convert string message to integer
# ========================================================================
# RSA operates on integers, not strings
# We need to convert "Hello!" to a number

message_str = "Hello!"
# int.from_bytes(bytes, byteorder) converts bytes to integer
# "big" means most significant byte first (big-endian)
m = int.from_bytes(message_str.encode(), "big")
print(f"\nOriginal message: '{message_str}'")
print(f"As integer: {m}")

# Verify message is smaller than modulus (required for RSA)
assert m < n, "Message must be less than modulus n"

# ========================================================================
# ENCRYPTION: C = M^e mod n
# ========================================================================
c = rsa_encrypt(m, n, e)
print(f"\nCiphertext: {c}")

# ========================================================================
# DECRYPTION: M = C^d mod n
# ========================================================================
m_dec = rsa_decrypt(c, n, d)
print(f"Decrypted: {m_dec}")

# ========================================================================
# VERIFICATION
# ========================================================================
# Check that decryption recovered the original message
print("\nMessage encrypts and decrypts correctly:", m == m_dec)

# This proves the mathematical correctness of RSA
# But it doesn't mean textbook RSA is secure!

print()


# ============================================================================
# PART 2: RSA Malleability Attack (Encryption)
# ============================================================================
# Attack Scenario:
#   - Alice has RSA keypair (n, e, d) where (n,e) is public
#   - Bob wants to send Alice a secret value S
#   - Bob encrypts: C = S^e mod n
#   - Mallory intercepts and replaces C with C'
#   - Alice decrypts C' and gets a value chosen by Mallory!
#   - Mallory can then derive the same AES key as Alice
#
# Key Insight: RSA is MALLEABLE - attacker can manipulate ciphertext
#              to produce predictable changes in plaintext
# ============================================================================

print("TASK 3 PART 2: RSA Malleability Attack")
print("=" * 60)

# Generate fresh keypair for this attack demonstration
n, e, d = generate_rsa_keypair(512)

print("Attack Scenario:")
print("  1. Alice has public key (n, e)")
print("  2. Bob wants to send a secret value S to Alice")
print("  3. Bob would encrypt: C = S^e mod n")
print("  4. Mallory intercepts and replaces C with C'")
print()

# ========================================================================
# *** MALLORY'S ATTACK ***
# ========================================================================
# Mallory wants Alice to decrypt to a specific value: 2
# 
# Mallory crafts: C' = 2^e mod n
#
# When Alice decrypts:
#   M' = (C')^d = (2^e)^d = 2^(e*d)
# 
# Since e*d ≡ 1 (mod φ(n)) by RSA construction:
#   2^(e*d) = 2^(1 + k*φ(n)) for some integer k
#           = 2 * 2^(k*φ(n))
#           = 2 * (2^φ(n))^k
#           = 2 * 1^k          (Euler's theorem: 2^φ(n) ≡ 1 mod n)
#           = 2
#
# So Alice will decrypt C' to exactly 2!
# ========================================================================

print("Mallory's strategy:")
print("  - Choose a value she wants Alice to decrypt: 2")
print("  - Compute C' = 2^e mod n")
print("  - Send C' to Alice pretending it's from Bob")
print()

c_prime = pow(2, e, n)  # Mallory computes this
print(f"Mallory crafts ciphertext: C' = 2^{e} mod n")

# ========================================================================
# ALICE DECRYPTS THE CRAFTED CIPHERTEXT
# ========================================================================
# Alice thinks this ciphertext came from Bob
# She doesn't know Mallory crafted it!

s_prime = rsa_decrypt(c_prime, n, d)
print(f"Alice decrypts modified ciphertext to: {s_prime}")

# As expected, Alice decrypted to 2
# This is EXACTLY what Mallory wanted!

# ========================================================================
# BOTH DERIVE THE SAME AES KEY
# ========================================================================

# Alice thinks she's using a secure random value
# She derives an AES key from it
k_alice = hashlib.sha256(str(s_prime).encode()).digest()[:16]

# Mallory knows the decrypted value is 2 (because she crafted C')
# She derives the same AES key
k_mallory = hashlib.sha256(str(2).encode()).digest()[:16]

print("\nKey derivation:")
print("  Alice:   K = SHA256({}) = {}...".format(s_prime, k_alice[:4].hex()))
print("  Mallory: K = SHA256(2) = {}...".format(k_mallory[:4].hex()))
print("  Keys match:", k_alice == k_mallory)

# ========================================================================
# MALLORY DECRYPTS ALL COMMUNICATIONS
# ========================================================================

# Alice encrypts messages using this "secure" key
# She thinks only Bob can decrypt (he has matching C)
ct = aes_encrypt(k_alice, "Hi Bob!")
print("\nAlice sends encrypted message...")

# But Mallory has the same key! She can decrypt everything.
print("Mallory decrypts:", aes_decrypt(k_mallory, ct))
print()

print("ATTACK SUCCESSFUL! ✓")
print("  - Mallory never learned Alice's private key d")
print("  - Mallory never learned the 'real' secret S")  
print("  - But Mallory can decrypt all of Alice's messages")
print()

# ========================================================================
# WHY THIS ATTACK WORKS: RSA Multiplicative Homomorphism
# ========================================================================
print("=" * 60)
print("Why RSA Malleability Works")
print("=" * 60)
print("""
RSA has a multiplicative property:
  E(m1) * E(m2) = E(m1 * m2)

Proof:
  E(m1) * E(m2) = (m1^e mod n) * (m2^e mod n)
                = (m1 * m2)^e mod n
                = E(m1 * m2)

This means:
  - If C1 = m1^e and C2 = m2^e
  - Then C1 * C2 = (m1*m2)^e is a valid encryption of m1*m2
  - Attacker can manipulate ciphertexts without knowing the private key!

In our attack:
  - Mallory chose m = 2
  - Computed C' = 2^e
  - Alice decrypted to 2
  - Mallory knew this would happen without knowing d!

This is why textbook RSA is insecure for encryption.
""")

print()


# ============================================================================
# PART 3: RSA Signature Malleability (Forgery)
# ============================================================================
# Attack Scenario:
#   - Alice signs messages by computing: sig = m^d mod n
#   - Anyone can verify: sig^e mod n = m (if signature is valid)
#   - Mallory sees signatures for two messages m1 and m2
#   - Mallory forges a signature for m3 = m1 * m2 WITHOUT the private key!
#
# Key Insight: Same multiplicative property affects signatures
# ============================================================================

print("RSA Signature Malleability")
print("=" * 60)

# Generate fresh keypair for signature demonstration
n, e, d = generate_rsa_keypair(512)

print("Signature Scenario:")
print("  - Alice signs messages using her private key d")
print("  - Signature: sig = message^d mod n")
print("  - Verification: sig^e mod n should equal message")
print()

# ========================================================================
# ALICE SIGNS TWO MESSAGES
# ========================================================================

# Alice signs message m1 = 42
m1 = 42
sig1 = pow(m1, d, n)  # Signature: sig1 = 42^d mod n
print(f"Alice signs m1={m1}")
print(f"  sig1 = {m1}^d mod n")

# Alice signs message m2 = 17
m2 = 17  
sig2 = pow(m2, d, n)  # Signature: sig2 = 17^d mod n
print(f"Alice signs m2={m2}")
print(f"  sig2 = {m2}^d mod n")
print()

# These signatures are valid and can be verified:
#   sig1^e mod n = (m1^d)^e = m1^(d*e) = m1
#   sig2^e mod n = (m2^d)^e = m2^(d*e) = m2

# ========================================================================
# *** MALLORY FORGES A SIGNATURE ***
# ========================================================================
# Mallory sees sig1 and sig2 (signatures are public)
# She wants to forge a signature for m3 = m1 * m2 = 42 * 17 = 714
#
# Mallory computes: sig3 = sig1 * sig2 mod n
#
# Why is this a valid signature?
#   sig3 = sig1 * sig2
#        = (m1^d) * (m2^d)
#        = (m1 * m2)^d          (multiplicative property)
#        = m3^d
#
# This is a valid signature for m3!
# ========================================================================

print("Mallory's forgery:")
print("  1. Observe sig1 and sig2 (public information)")
print("  2. Compute sig3 = sig1 * sig2 mod n")
print("  3. Claim sig3 is Alice's signature on m3 = m1*m2")
print()

# Mallory multiplies the two signatures
sig3 = (sig1 * sig2) % n
print(f"Forged signature: sig3 = sig1 * sig2 mod n")

# The forged signature is for message m3 = m1 * m2
m3 = (m1 * m2) % n
print(f"For message: m3 = {m1} * {m2} = {m3}")
print()

# ========================================================================
# VERIFY THE FORGED SIGNATURE
# ========================================================================
# Let's verify that sig3 is indeed a valid signature for m3

# Standard RSA signature verification:
#   Compute: sig^e mod n
#   If result equals message, signature is valid

verified = pow(sig3, e, n)
print(f"Verification: sig3^e mod n = {verified}")
print(f"Expected message m3 = {m3}")
print(f"Forged signature valid: {verified == m3}")
print()

print("FORGERY SUCCESSFUL! ✓")
print("  - Mallory never learned Alice's private key d")
print("  - Mallory never directly signed m3")
print("  - But created a valid signature by combining existing signatures")
print()

# # ========================================================================
# # WHY SIGNATURE FORGERY WORKS
# # ========================================================================
# print("=" * 60)
# print("Why RSA Signature Forgery Works")
# print("=" * 60)
# print("""
# RSA signatures are multiplicative:
#   Sign(m1) * Sign(m2) = Sign(m1 * m2)

# Proof:
#   Sign(m1) * Sign(m2) = (m1^d mod n) * (m2^d mod n)
#                       = (m1 * m2)^d mod n
#                       = Sign(m1 * m2)

# Implications:
#   - Given signatures for m1 and m2
#   - Attacker can forge signature for m1*m2
#   - Can also forge signatures for other combinations
#   - Never saw or signed m1*m2, but signature verifies!

# Real-world impact:
#   - If Alice signed "Pay Bob $10" and "Pay Carol $20"
#   - Mallory could forge "Pay Bob $10 * Pay Carol $20" 
#   - (Okay, this specific example doesn't make sense, but shows the vulnerability)
  
# Better example:
#   - System uses numeric codes: "approve=1", "deny=0"  
#   - Alice signs 2 and 3 (innocent values)
#   - Mallory forges signature for 6 (2*3)
#   - If 6 means something important, this could be exploited

# This is why textbook RSA is insecure for signatures too!
# """)

# print()


# # ============================================================================
# # FIXES FOR PRODUCTION USE
# # ============================================================================
# print("=" * 60)
# print("How to Fix These Vulnerabilities")
# print("=" * 60)
# print("""
# NEVER USE TEXTBOOK RSA IN PRODUCTION!

# Modern RSA uses padding schemes that add randomness:

# 1. RSA-OAEP (Optimal Asymmetric Encryption Padding)
#    - For ENCRYPTION
#    - Adds random padding before encryption
#    - Same message encrypts differently each time
#    - Padding must verify correctly during decryption
#    - Prevents chosen ciphertext attacks
#    - Prevents malleability (modified ciphertext won't decrypt)
   
#    Example in Python:
#      from Crypto.Cipher import PKCS1_OAEP
#      cipher = PKCS1_OAEP.new(RSA_key)
#      ciphertext = cipher.encrypt(message)

# 2. RSA-PSS (Probabilistic Signature Scheme)  
#    - For SIGNATURES
#    - Adds random salt to message before signing
#    - Same message produces different signatures each time
#    - Prevents forgery attacks
#    - Salt is included in verification
   
#    Example in Python:
#      from Crypto.Signature import pss
#      signer = pss.new(RSA_key)
#      signature = signer.sign(message_hash)

# 3. HYBRID ENCRYPTION (RSA + AES)
#    - Use RSA only for key exchange (encrypt AES key)
#    - Use AES for actual data encryption (much faster)
#    - Combine RSA-OAEP + AES-GCM for best security
   
#    Example flow:
#      1. Generate random AES key
#      2. Encrypt AES key with RSA-OAEP
#      3. Encrypt data with AES-GCM
#      4. Send both: RSA(AES_key) + AES-GCM(data)

# WHY THESE FIX THE PROBLEMS:

# Problem: Textbook RSA is deterministic
# Fix: OAEP/PSS add randomness → different every time

# Problem: Textbook RSA is malleable  
# Fix: OAEP validates padding → modified ciphertext rejected

# Problem: Multiplicative homomorphism
# Fix: Padding breaks the mathematical structure

# STANDARDS THAT USE THESE:
# - TLS/SSL: RSA-OAEP for key exchange
# - PGP/GPG: RSA-OAEP + AES for email encryption
# - SSH: RSA with SHA-256 for authentication
# - JWT: RSA-PSS for token signing
# """)


# # ============================================================================
# # KEY TAKEAWAYS FROM TASK 3
# # ============================================================================
# print("=" * 60)
# print("KEY TAKEAWAYS")
# print("=" * 60)
# print("""
# 1. TEXTBOOK RSA IS INSECURE
#    - Mathematically correct but cryptographically broken
#    - Deterministic: same message → same ciphertext
#    - Malleable: attacker can manipulate without key
#    - Never use in production!

# 2. PADDING IS ESSENTIAL
#    - RSA-OAEP for encryption
#    - RSA-PSS for signatures
#    - Adds randomness and structure validation
#    - Breaks malleability property

# 3. MATHEMATICAL PROPERTIES ≠ SECURITY
#    - RSA's multiplicative property is elegant
#    - But it's a vulnerability for encryption/signatures
#    - Security requires breaking mathematical structure (via padding)

# 4. HYBRID CRYPTOGRAPHY
#    - RSA is slow (large number operations)
#    - AES is fast (bitwise operations)
#    - Use RSA for key exchange, AES for data
#    - Best of both: asymmetric + symmetric

# 5. CRYPTOGRAPHIC ENGINEERING
#    - Textbook descriptions are for understanding
#    - Real implementations need additional security layers
#    - Always use established standards (OAEP, PSS, GCM)
#    - Don't implement crypto yourself - use tested libraries!

# 6. COMPARISON TO DIFFIE-HELLMAN (Task 2)
#    - Both have vulnerabilities without proper protections
#    - DH: needs authentication to prevent MITM
#    - RSA: needs padding to prevent malleability
#    - Common theme: basic protocols need enhancement for real-world use
# """)

# # ============================================================================
# # End of Task 3
# # ============================================================================