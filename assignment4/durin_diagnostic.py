#!/usr/bin/env python3
"""
Simple Durin Diagnostic - Find out why it's not working
"""
import bcrypt
import time

print("="*70)
print("DURIN DIAGNOSTIC - IS THE CODE ACTUALLY WORKING?")
print("="*70)

durin_hash = b"$2b$13$6ypcazOOkUT/a7EwMuIjH.qbdqmHPDAC9B5c37RT9gEw18BX6FOay"

# TEST 1: Is bcrypt even working?
print("\n[TEST 1] Basic bcrypt test")
test_word = "testpassword"
start = time.time()
result = bcrypt.checkpw(test_word.encode(), durin_hash)
elapsed = time.time() - start

print(f"Testing '{test_word}': {result}")
print(f"Time: {elapsed*1000:.0f}ms")

if elapsed < 0.3:
    print("⚠️  WARNING: Too fast! Something might be cached")
elif elapsed > 2.0:
    print("⚠️  WARNING: Very slow! This will take forever")
else:
    print("✓ Normal speed for workfactor 13")

# TEST 2: Test the exact words that DID work for others
print("\n[TEST 2] Testing passwords that worked for other users")
known_working = ["welcome", "wizard", "diamond", "desire", "ossify"]

for pwd in known_working:
    start = time.time()
    result = bcrypt.checkpw(pwd.encode(), durin_hash)
    elapsed = time.time() - start
    
    if result:
        print(f"🎉 FOUND: '{pwd}' - {elapsed*1000:.0f}ms")
        break
    else:
        print(f"✗ '{pwd}': No match - {elapsed*1000:.0f}ms")

# TEST 3: Can we load NLTK?
print("\n[TEST 3] NLTK loading test")
try:
    from nltk.corpus import words
    wordlist = [w.lower() for w in words.words() if 6 <= len(w) <= 10]
    print(f"✓ Loaded {len(wordlist):,} words")
    
    # Show samples
    print(f"First 5: {wordlist[:5]}")
    print(f"Last 5: {wordlist[-5:]}")
    
    # Check if "durin" is even in the list
    if "durin" in wordlist:
        print("✓ 'durin' is in the dictionary")
    else:
        print("✗ 'durin' is NOT in the dictionary")
        
except Exception as e:
    print(f"✗ NLTK error: {e}")

# TEST 4: Actually test a small sample
print("\n[TEST 4] Testing first 100 words from dictionary")
try:
    from nltk.corpus import words
    wordlist = [w.lower() for w in words.words() if 6 <= len(w) <= 10]
    
    print("Testing first 100 words (will take ~50 seconds)...")
    start_time = time.time()
    
    for i, word in enumerate(wordlist[:100], 1):
        result = bcrypt.checkpw(word.encode(), durin_hash)
        
        if result:
            elapsed = time.time() - start_time
            print(f"\n🎉🎉🎉 FOUND IT: '{word}'")
            print(f"Position: {i}/100")
            print(f"Time: {elapsed:.1f}s")
            break
        
        if i % 20 == 0:
            elapsed = time.time() - start_time
            rate = i / elapsed
            print(f"  Progress: {i}/100 tested | {elapsed:.0f}s | {rate:.1f} hash/s")
    else:
        elapsed = time.time() - start_time
        print(f"\n✗ Not found in first 100 words")
        print(f"Time: {elapsed:.1f}s")
        print(f"Rate: {100/elapsed:.1f} hash/s")
        print(f"\nEstimate for all 135,145 words: {135145/(100/elapsed)/3600:.1f} hours")
        
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "="*70)
print("CONCLUSION")
print("="*70)
print("\nWhat does this tell us?")
print("1. If bcrypt is working → code is fine")
print("2. If NLTK loaded → dictionary is accessible")  
print("3. If first 100 tested → multiprocessing should work")
print("4. If nothing found → password is later in list OR not in list at all")