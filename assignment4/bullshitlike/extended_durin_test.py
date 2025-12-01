#!/usr/bin/env python3
import bcrypt
import time
from multiprocessing import Pool, cpu_count

def test_chunk(args):
    hash_data, chunk = args
    for word in chunk:
        try:
            if bcrypt.checkpw(word.encode(), hash_data):
                return word
        except:
            pass
    return None

def main():
    durin_hash = b"$2b$13$6ypcazOOkUT/a7EwMuIjH.qbdqmHPDAC9B5c37RT9gEw18BX6FOay"
    
    # Extended candidates
    candidates = []
    
    # 1. Longer NLTK words (11-15 characters)
    try:
        from nltk.corpus import words
        longer_words = [w.lower() for w in words.words() if 11 <= len(w) <= 15]
        candidates.extend(longer_words)
        print(f"Added {len(longer_words):,} longer words (11-15 chars)")
    except:
        print("NLTK not available, skipping dictionary words")
    
    # 2. Tolkien proper nouns and variations
    tolkien_names = [
        "Durin", "DURIN", "Thorin", "THORIN",
        "Oakenshield", "Ironfoot", "Firebeard", "Longbeard",
        "Khazaddum", "Erebor", "Moria",
        "Deathless", "Immortal", "Stonehelm",
        "durin", "thorin", "oakenshield", "ironfoot",
    ]
    candidates.extend(tolkien_names)
    
    print(f"\nTotal candidates: {len(candidates):,}")
    print(f"Testing with {cpu_count()} cores...\n")
    
    # Split into chunks
    num_cores = cpu_count()
    chunk_size = (len(candidates) + num_cores - 1) // num_cores
    chunks = [candidates[i:i + chunk_size] for i in range(0, len(candidates), chunk_size)]
    
    start = time.time()
    
    with Pool(num_cores) as pool:
        results = pool.map(test_chunk, [(durin_hash, c) for c in chunks])
    
    elapsed = time.time() - start
    
    # Check results
    found = next((r for r in results if r), None)
    
    if found:
        print(f"\n✓✓✓ FOUND: {found}")
        print(f"Time: {elapsed:.1f}s")
    else:
        print(f"\n✗ Not found after testing {len(candidates):,} words")
        print(f"Time: {elapsed:.1f}s ({elapsed/60:.1f} minutes)")
        print("\nDurin's password is likely:")
        print("  - Contains special characters or numbers")
        print("  - From a custom wordlist not in NLTK")
        print("  - Intentionally uncrackable for this assignment")

if __name__ == '__main__':
    main()
