# ============================================================================
# Task 2: Man-in-the-Middle (MITM) Attacks on Diffie-Hellman
# ============================================================================
# Purpose: Demonstrate why unauthenticated DH is vulnerable to active attackers
#
# Key Problem: In Task 1, we showed DH is secure against eavesdroppers.
#              But what if the attacker can MODIFY messages in transit?
#              
# Answer: Without authentication, an active attacker (Mallory) can:
#         1. Intercept public keys YA and YB
#         2. Replace them with malicious values
#         3. Force both parties to use a predictable shared secret
#         4. Decrypt all communications
#
# Real-World Impact: This is why TLS uses *signed* DH exchanges!
# ============================================================================

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import random

def aes_encrypt(key, msg, iv=b'0'*16):
    """
    Encrypt message with AES-CBC
    
    Parameters:
        key = 16-byte AES key
        msg = plaintext string
        iv  = initialization vector (default: all zeros)
    """
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg.encode(), 16))

def aes_decrypt(key, ct, iv=b'0'*16):
    """
    Decrypt ciphertext with AES-CBC
    
    Parameters:
        key = 16-byte AES key
        ct  = ciphertext bytes
        iv  = initialization vector (must match encryption IV)
    """
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16).decode()

# Use small parameters for easy demonstration
q, alpha = 37, 5


# ============================================================================
# PART 1: MITM ATTACK - Replace Public Keys with q
# ============================================================================
# Attack Strategy: Replace both YA and YB with the modulus q
# Why it works: q^x mod q = 0 for any x
# Result: Both Alice and Bob compute shared secret = 0
#         Mallory also knows it's 0, so she can derive the same AES key!
# ============================================================================

print("TASK 2 PART 1: Replace YA and YB with q")
print("=" * 60)

# ========================================================================
# NORMAL PROTOCOL START (before attack)
# ========================================================================

# Alice generates her keys normally
xa = random.randint(1, q-1)     # Alice's private key (secret)
ya = pow(alpha, xa, q)          # Alice's public key (will be sent)
print("Alice: private =", xa, "public =", ya)

# Bob generates his keys normally  
xb = random.randint(1, q-1)     # Bob's private key (secret)
yb = pow(alpha, xb, q)          # Bob's public key (will be sent)
print("Bob: private =", xb, "public =", yb)

# ========================================================================
# *** ATTACK HAPPENS HERE ***
# ========================================================================
# Mallory sits in the middle and intercepts both public keys
# Instead of forwarding YA to Bob and YB to Alice, she replaces them!
# ========================================================================

print("\nMallory replaces YA and YB with q =", q)

# Mallory sends q to Bob (instead of Alice's real YA)
# Mallory sends q to Alice (instead of Bob's real YB)

# ========================================================================
# ALICE COMPUTES SHARED SECRET (with tampered value)
# ========================================================================
# Alice thinks she received YB from Bob, but actually got q from Mallory
# Alice computes: S = (received_value)^XA mod q
#               S = q^XA mod q
#               S = 0  ← Because q^x mod q is always 0!
#
# Mathematical explanation:
#   q mod q = 0 (by definition: q is divisible by q with remainder 0)
#   q^2 = q * q ≡ 0 * q ≡ 0 (mod q)
#   q^3 = q^2 * q ≡ 0 * q ≡ 0 (mod q)
#   q^x ≡ 0 (mod q) for any positive integer x
s_alice = pow(q, xa, q)
print("Alice secret:", s_alice)  # Will always be 0

# ========================================================================
# BOB COMPUTES SHARED SECRET (with tampered value)
# ========================================================================
# Bob thinks he received YA from Alice, but actually got q from Mallory
# Bob computes: S = (received_value)^XB mod q
#             S = q^XB mod q  
#             S = 0  ← Same reason as above!
s_bob = pow(q, xb, q)
print("Bob secret:", s_bob)      # Will always be 0

# ========================================================================
# MALLORY KNOWS THE SECRET!
# ========================================================================
# Mallory knows that q^anything mod q = 0
# So she knows both Alice and Bob will compute shared secret = 0
# She doesn't need to know XA or XB!
s_mallory = 0
print("Mallory knows:", s_mallory)

# ========================================================================
# KEY DERIVATION - Everyone gets the same key!
# ========================================================================

# Alice derives her AES key: k = SHA256(0)
k_alice = hashlib.sha256(str(s_alice).encode()).digest()[:16]

# Mallory derives the same key: k = SHA256(0)
k_mallory = hashlib.sha256(str(s_mallory).encode()).digest()[:16]

# They match! This is catastrophic for security.
print("Keys match:", k_alice == k_mallory)

# ========================================================================
# MALLORY DECRYPTS EVERYTHING
# ========================================================================

# Alice encrypts a message to Bob using her "secure" key
# Alice thinks only Bob can decrypt this
c = aes_encrypt(k_alice, "Hi Bob!")

# But Mallory has the same key! She can decrypt everything.
print("Mallory decrypts:", aes_decrypt(k_mallory, c))

# ATTACK SUCCESSFUL! ✓
# Alice and Bob think they're communicating securely
# But Mallory can read everything

print()


# ============================================================================
# PART 2: GENERATOR TAMPERING ATTACK
# ============================================================================
# Attack Strategy: Instead of replacing public keys, replace the generator α
# Why it works: Certain values of α produce predictable shared secrets
# Result: Mallory can predict the shared secret without knowing private keys
# ============================================================================

print("TASK 2 PART 2: Tamper with alpha")
print("=" * 60)

# We'll test three different malicious generator values
# Each produces a predictable shared secret for different reasons

for mal_alpha, name in [(1, "1"), (q, "q"), (q-1, "q-1")]:
    print(f"\n--- Setting alpha = {name} ---")
    
    # ========================================================================
    # Alice and Bob use the TAMPERED generator
    # ========================================================================
    # They don't know Mallory replaced α
    # They follow the normal protocol with the bad generator
    
    xa = random.randint(1, q-1)
    ya = pow(mal_alpha, xa, q)  # Public key using MALICIOUS generator
    
    xb = random.randint(1, q-1)
    yb = pow(mal_alpha, xb, q)  # Public key using MALICIOUS generator
    
    # ========================================================================
    # SHARED SECRET COMPUTATION (with bad generator)
    # ========================================================================
    # Let's say Alice computes the shared secret:
    s = pow(yb, xa, q)
    print("Shared secret:", s)
    
    # ========================================================================
    # WHY EACH MALICIOUS ALPHA WORKS:
    # ========================================================================
    
    if mal_alpha == 1:
        # CASE 1: α = 1
        # ----------------
        # YA = 1^XA = 1 (1 to any power is 1)
        # YB = 1^XB = 1
        # Shared secret = YB^XA = 1^XA = 1
        # Shared secret = YA^XB = 1^XB = 1
        # Result: Secret is always 1, regardless of XA or XB
        # Mallory knows secret = 1
        pass
    
    elif mal_alpha == q:
        # CASE 2: α = q
        # ----------------  
        # YA = q^XA mod q = 0 (same as Part 1 attack)
        # YB = q^XB mod q = 0
        # Shared secret = YB^XA = 0^XA = 0
        # Shared secret = YA^XB = 0^XB = 0
        # Result: Secret is always 0
        # Mallory knows secret = 0
        pass
    
    elif mal_alpha == q-1:
        # CASE 3: α = q-1
        # ----------------
        # Note: q-1 ≡ -1 (mod q)
        # 
        # If XA is odd:  YA = (-1)^XA = -1 ≡ q-1 (mod q)
        # If XA is even: YA = (-1)^XA = 1
        # 
        # If XB is odd:  YB = (-1)^XB = -1 ≡ q-1 (mod q)  
        # If XB is even: YB = (-1)^XB = 1
        #
        # Shared secret:
        #   If both odd:  S = (-1)^(odd*odd) = -1^odd = -1 ≡ q-1 (mod q)
        #   If one even:  S = (±1)^something = ±1
        #   If both even: S = 1^something = 1
        #
        # In practice, S is always 1 or q-1
        # With q=37, if S=q-1=36, then 36^XB = (q-1)^XB ≡ ±1 ≡ 1 or 36
        # Either way, very predictable!
        # 
        # In this specific case with our random XA and XB, 
        # the shared secret tends to be 1 (you can verify in output)
        pass
    
    # ========================================================================
    # MALLORY DECRYPTS MESSAGES
    # ========================================================================
    # Since Mallory knows what the shared secret will be,
    # she can derive the same AES key
    
    k = hashlib.sha256(str(s).encode()).digest()[:16]
    c = aes_encrypt(k, "Hi Bob!")
    print("Decrypts:", aes_decrypt(k, c))
    # ATTACK SUCCESSFUL! ✓

print()


# # ============================================================================
# # ROOT CAUSE ANALYSIS: Why These Attacks Work
# # ============================================================================
# print("=" * 60)
# print("ROOT CAUSE: Lack of Authentication")
# print("=" * 60)
# print("""
# The fundamental problem is that basic Diffie-Hellman has NO authentication.

# When Alice receives a public key, she has no way to verify:
#   1. Did it actually come from Bob?
#   2. Was it modified in transit?
#   3. Is she even talking to Bob, or to Mallory pretending to be Bob?

# The same applies to Bob receiving Alice's public key.

# Without authentication, an active attacker (Mallory) can:
#   - Intercept messages
#   - Modify messages  
#   - Inject messages
#   - Impersonate either party

# This is called a MAN-IN-THE-MIDDLE (MITM) attack.
# """)


# # # ============================================================================
# # # HOW TO FIX: Add Authentication
# # # ============================================================================
# # print("=" * 60)
# print("THE FIX: Authenticated Key Exchange")
# print("=" * 60)
# print("""
# Modern protocols add authentication to prevent MITM attacks:

# 1. SIGNED DIFFIE-HELLMAN
#    - Each party signs their public key with a long-term signing key
#    - Recipient verifies the signature before using the key
#    - Used in: TLS with certificates, SSH with host keys

# 2. CERTIFICATE AUTHORITIES (PKI)
#    - Trusted third party vouches for public key ownership
#    - Certificates bind identity to public key
#    - Used in: HTTPS, email encryption (S/MIME)

# 3. PRE-SHARED KEYS
#    - Parties share a secret key beforehand (out-of-band)
#    - Use PSK to authenticate the DH exchange
#    - Used in: WPA2-PSK WiFi, some VPNs

# 4. AUTHENTICATED KEY AGREEMENT PROTOCOLS
#    - Signal Protocol (X3DH): Triple Diffie-Hellman with signatures
#    - Station-to-Station protocol: DH + signatures + encryption
#    - MQV protocol: Implicit authentication using static keys

# Example in TLS 1.3:
#   Alice → ServerHello + KeyShare (YA) + Certificate + CertificateVerify (signature)
#   Bob verifies the certificate and signature before using YA
#   Now Mallory cannot substitute YA because she can't forge the signature!

# TAKEAWAY: Encryption alone ≠ Security
#           Need: Confidentiality (encryption) + Authentication (signatures/MAC)
# """)


# # # ============================================================================
# # # KEY LESSONS
# # # ============================================================================
# # print("=" * 60)
# # print("KEY LESSONS FROM TASK 2")
# # print("=" * 60)
# # print("""
# # 1. CONFIDENTIALITY ≠ AUTHENTICATION
# #    - DH provides confidential key exchange (passive attackers can't learn key)
# #    - DH does NOT provide authentication (active attackers can MITM)
# #    - Need both properties for real security!

# # 2. ACTIVE vs PASSIVE ATTACKS
# #    - Passive: Eavesdropper can only observe → DH secure
# #    - Active: Attacker can modify messages → DH vulnerable
# #    - Always assume attackers are active in real world!

# # 3. MATHEMATICAL VULNERABILITIES
# #    - Replacing with q: exploits q^x ≡ 0 (mod q)
# #    - α=1: exploits 1^x = 1  
# #    - α=q-1: exploits small subgroup (±1)
# #    - Without parameter validation, protocol is fragile

# # 4. REAL-WORLD IMPLICATIONS
# #    - Never use unauthenticated DH in production!
# #    - Always use authenticated key exchange (TLS, Signal, SSH)
# #    - Validate all protocol parameters
# #    - Defense in depth: multiple security layers

# # 5. CRYPTOGRAPHIC ENGINEERING
# #    - Simple protocols (DH) are hard to implement securely
# #    - Easy to miss authentication requirements
# #    - Use well-tested libraries and protocols
# #    - Don't roll your own crypto!
# # """)

# # # ============================================================================
# # # End of Task 2
# # # ============================================================================