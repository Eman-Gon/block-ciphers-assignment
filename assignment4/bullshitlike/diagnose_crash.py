#!/usr/bin/env python3
"""
Diagnostic script to identify crash causes in the cryptographic hash assignment
"""

import sys
import os

print("=" * 70)
print("CRASH DIAGNOSTIC TOOL")
print("=" * 70)

# Check 1: Python version
print("\n1. Checking Python version...")
print(f"   Python {sys.version}")
if sys.version_info < (3, 6):
    print("   ⚠️  WARNING: Python 3.6+ required")
else:
    print("   ✓ Python version OK")

# Check 2: Required modules
print("\n2. Checking required modules...")
modules = {
    'bcrypt': 'bcrypt',
    'nltk': 'nltk',
    'matplotlib': 'matplotlib',
    'hashlib': 'hashlib (built-in)',
    'multiprocessing': 'multiprocessing (built-in)'
}

missing = []
for module, name in modules.items():
    try:
        __import__(module)
        print(f"   ✓ {name}")
    except ImportError:
        print(f"   ✗ {name} - NOT FOUND")
        missing.append(module)

if missing:
    print(f"\n   ⚠️  Install missing modules:")
    print(f"   pip install {' '.join([m for m in missing if m not in ['hashlib', 'multiprocessing']])} --break-system-packages")

# Check 3: NLTK words corpus
print("\n3. Checking NLTK words corpus...")
try:
    import nltk
    from nltk.corpus import words
    word_list = words.words()
    print(f"   ✓ NLTK words corpus loaded ({len(word_list):,} words)")
except Exception as e:
    print(f"   ✗ NLTK words corpus not available")
    print(f"   Error: {e}")
    print("   Fix: Run the following code:")
    print("   import nltk")
    print("   nltk.download('words')")

# Check 4: bcrypt functionality
print("\n4. Testing bcrypt...")
try:
    import bcrypt
    test_hash = bcrypt.hashpw(b"test", bcrypt.gensalt(rounds=4))
    result = bcrypt.checkpw(b"test", test_hash)
    if result:
        print("   ✓ bcrypt working correctly")
    else:
        print("   ✗ bcrypt checkpw failed")
except Exception as e:
    print(f"   ✗ bcrypt error: {e}")

# Check 5: Shadow file
print("\n5. Checking for shadow.txt...")
shadow_paths = [
    'shadow.txt',
    './shadow.txt',
    '/home/claude/shadow.txt',
    '../shadow.txt'
]

found = False
for path in shadow_paths:
    if os.path.exists(path):
        print(f"   ✓ Found at: {path}")
        # Check file format
        with open(path, 'r') as f:
            lines = f.readlines()
            print(f"   ✓ Contains {len(lines)} entries")
            if lines:
                print(f"   Sample: {lines[0].strip()[:60]}...")
        found = True
        break

if not found:
    print("   ✗ shadow.txt not found in common locations")
    print("   Create it or update the path in task2_password_cracking.py")

# Check 6: Memory
print("\n6. Checking available memory...")
try:
    import psutil
    mem = psutil.virtual_memory()
    print(f"   Total: {mem.total / (1024**3):.1f} GB")
    print(f"   Available: {mem.available / (1024**3):.1f} GB")
    if mem.available < 2 * (1024**3):
        print("   ⚠️  Low memory (< 2GB free). Task 1 large bits may fail.")
    else:
        print("   ✓ Sufficient memory")
except:
    print("   ⓘ  psutil not available, skipping memory check")

# Check 7: CPU cores
print("\n7. Checking CPU cores...")
try:
    import multiprocessing as mp
    cores = mp.cpu_count()
    print(f"   ✓ {cores} CPU cores available")
except Exception as e:
    print(f"   ✗ Error detecting cores: {e}")

# Check 8: Test simple hash collision
print("\n8. Testing simple collision finding (8-bit)...")
try:
    import hashlib
    import random
    import string
    
    def sha256_hash(s):
        return hashlib.sha256(s.encode()).hexdigest()
    
    def truncate_hash(h, bits):
        hex_chars = (bits + 3) // 4
        truncated_hex = h[:hex_chars]
        hash_int = int(truncated_hex, 16)
        bitmask = (1 << bits) - 1
        return hash_int & bitmask
    
    seen = {}
    for i in range(1000):
        s = ''.join(random.choices(string.ascii_letters, k=8))
        h = truncate_hash(sha256_hash(s), 8)
        if h in seen:
            print(f"   ✓ Found collision in {i+1} attempts")
            break
        seen[h] = s
    else:
        print("   ⓘ  No collision in 1000 attempts (unusual but possible)")
except Exception as e:
    print(f"   ✗ Error during collision test: {e}")
    import traceback
    traceback.print_exc()

# Summary
print("\n" + "=" * 70)
print("DIAGNOSTIC SUMMARY")
print("=" * 70)

if missing:
    print("⚠️  CRITICAL: Missing required modules")
    print(f"   Run: pip install {' '.join([m for m in missing if m not in ['hashlib', 'multiprocessing']])} --break-system-packages")
else:
    print("✓ All required modules present")

print("\nCommon crash scenarios:")
print("1. NLTK corpus not downloaded → Run: nltk.download('words')")
print("2. Out of memory on large bit sizes → Reduce max bits or add RAM")
print("3. shadow.txt not found → Update file path in script")
print("4. Windows multiprocessing → Ensure 'if __name__ == __main__' wrapper")
print("5. Old bcrypt version → Run: pip install --upgrade bcrypt")

print("\n" + "=" * 70)
print("Run this diagnostic output when asking for help!")
print("=" * 70)