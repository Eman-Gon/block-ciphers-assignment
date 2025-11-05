import hashlib
import random
import string
import time

def sha256_hash(input_string):
    """Calculate SHA256 hash of input string and return hex digest"""
    return hashlib.sha256(input_string.encode()).hexdigest()

def truncate_hash(hash_string, bits):
    """Truncate hash to specified number of bits"""
    hex_chars = (bits + 3) // 4
    truncated_hex = hash_string[:hex_chars]
    hash_int = int(truncated_hex, 16)
    bitmask = (1 << bits) - 1
    result = hash_int & bitmask
    return result

print("=" * 60)
print("TASK 1 DEMONSTRATION (Quick Test)")
print("=" * 60)

# Task 1a: Hash arbitrary inputs
print("\nTask 1a: SHA256 Hashing")
print("-" * 60)
test_inputs = ["Hello, World!", "Python", "Cryptography"]
for inp in test_inputs:
    h = sha256_hash(inp)
    print(f"'{inp}' → {h}")

# Task 1b: Hamming distance of 1
print("\n\nTask 1b: Hamming Distance = 1")
print("-" * 60)
s1 = "password"
s2 = "passwore"  # Changed last character
h1 = sha256_hash(s1)
h2 = sha256_hash(s2)
byte_diff = sum(c1 != c2 for c1, c2 in zip(h1, h2))
print(f"String 1: {s1}")
print(f"String 2: {s2}")
print(f"Hash 1:   {h1}")
print(f"Hash 2:   {h2}")
print(f"Hex chars different: {byte_diff}/64 ({byte_diff/64*100:.1f}%)")

# Task 1c: Find collision (limited test)
print("\n\nTask 1c: Collision Finding (8-12 bits demo)")
print("-" * 60)

for bits in [8, 10, 12]:
    seen = {}
    start = time.time()
    
    for attempt in range(1, 100000):
        s = ''.join(random.choices(string.ascii_letters, k=8))
        h = truncate_hash(sha256_hash(s), bits)
        
        if h in seen:
            elapsed = time.time() - start
            print(f"{bits}-bit: Collision found!")
            print(f"  Input 1: {seen[h]}")
            print(f"  Input 2: {s}")
            print(f"  Attempts: {attempt:,}")
            print(f"  Time: {elapsed:.4f}s")
            print(f"  Expected: ~{2**(bits/2):.0f} attempts")
            print()
            break
        
        seen[h] = s

print("=" * 60)
print("Test complete! See full scripts for complete implementation.")
print("=" * 60)