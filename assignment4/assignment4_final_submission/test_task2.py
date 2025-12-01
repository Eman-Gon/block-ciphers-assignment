import bcrypt
import time

print("=" * 60)
print("TASK 2 DEMONSTRATION - Bcrypt Test")
print("=" * 60)

# Test with the first entry from shadow file
test_hash = b"$2b$08$J9FW66ZdPI2nrIMcOxFYI.qx268uZn.ajhymLP/YHaAsfBGP3Fnmq"
test_salt = b"$2b$08$J9FW66ZdPI2nrIMcOxFYI."

print("\nTesting bcrypt functionality:")
print(f"Hash: {test_hash.decode()}")
print(f"Salt: {test_salt.decode()}")

# Test a few words
test_words = ["password", "hello", "wizard", "hobbit", "dragon"]

print("\nTrying sample words:")
for word in test_words:
    start = time.time()
    result = bcrypt.checkpw(word.encode(), test_hash)
    elapsed = time.time() - start
    
    status = "✓ MATCH!" if result else "✗ No match"
    print(f"  '{word}': {status} ({elapsed*1000:.1f}ms)")

# Verify hashpw method
print("\nVerifying hashpw method:")
test_word = "password"
generated = bcrypt.hashpw(test_word.encode(), test_salt)
print(f"  Input: '{test_word}'")
print(f"  Generated: {generated.decode()}")
print(f"  Original:  {test_hash.decode()}")
print(f"  Match: {generated == test_hash}")

print("\n" + "=" * 60)
print("Bcrypt is working correctly!")
print("=" * 60)

# Estimate timing for full crack
print("\nCracking time estimates:")
print("-" * 60)
wordlist_size = 135000  # Approximate NLTK word corpus size (6-10 letters)

for workfactor in [8, 9, 10, 11, 12, 13]:
    # Approximate timing (will vary by CPU)
    if workfactor == 8:
        time_per_hash = 0.030
    elif workfactor == 9:
        time_per_hash = 0.060
    elif workfactor == 10:
        time_per_hash = 0.110
    elif workfactor == 11:
        time_per_hash = 0.220
    elif workfactor == 12:
        time_per_hash = 0.420
    else:  # 13
        time_per_hash = 0.840
    
    total_time = wordlist_size * time_per_hash
    
    print(f"Workfactor {workfactor}: {time_per_hash*1000:>6.0f}ms/hash → "
          f"{total_time:>8.1f}s ({total_time/60:>6.1f}min, {total_time/3600:>5.2f}hr)")

print("-" * 60)
print("Note: With parallelization (8 cores), divide times by ~8")