#!/usr/bin/env python3
"""
Durin cracker that ACTUALLY shows progress
Uses file-based progress tracking instead of broken global variables
"""
import bcrypt
import time
import csv
import os
from multiprocessing import Pool, cpu_count
from datetime import datetime

PROGRESS_FILE = "durin_progress.txt"

def test_chunk(args):
    """Test a chunk of passwords and write progress to file"""
    hash_data, chunk, chunk_id, total_chunks = args
    
    for i, word in enumerate(chunk):
        try:
            if bcrypt.checkpw(word.encode(), hash_data):
                # Found it! Write to file immediately
                with open("DURIN_FOUND.txt", "w") as f:
                    f.write(f"PASSWORD: {word}\n")
                    f.write(f"CHUNK: {chunk_id}\n")
                    f.write(f"POSITION: {i}\n")
                return (word, chunk_id * len(chunk) + i)
        except:
            pass
        
        # Write progress every 50 words
        if i % 50 == 0 and i > 0:
            try:
                with open(f"{PROGRESS_FILE}.{chunk_id}", "w") as f:
                    f.write(f"{chunk_id},{i}\n")
            except:
                pass
    
    # Mark chunk as complete
    try:
        with open(f"{PROGRESS_FILE}.{chunk_id}", "w") as f:
            f.write(f"{chunk_id},{len(chunk)}\n")
    except:
        pass
    
    return (None, -1)

def check_progress(num_chunks):
    """Read progress from all chunk files"""
    total_tested = 0
    for i in range(num_chunks):
        try:
            with open(f"{PROGRESS_FILE}.{i}", "r") as f:
                line = f.read().strip()
                if line:
                    _, tested = line.split(',')
                    total_tested += int(tested)
        except:
            pass
    return total_tested

def cleanup_progress_files(num_chunks):
    """Remove progress files"""
    for i in range(num_chunks):
        try:
            os.remove(f"{PROGRESS_FILE}.{i}")
        except:
            pass
    try:
        os.remove("DURIN_FOUND.txt")
    except:
        pass

def main():
    durin_hash = b"$2b$13$6ypcazOOkUT/a7EwMuIjH.qbdqmHPDAC9B5c37RT9gEw18BX6FOay"
    
    print("="*70)
    print("DURIN CRACKER - FILE-BASED PROGRESS TRACKING")
    print("="*70)
    
    # Load candidates
    candidates = []
    
    try:
        from nltk.corpus import words
        longer_words = [w.lower() for w in words.words() if 11 <= len(w) <= 15]
        candidates.extend(longer_words)
        print(f"✓ Loaded {len(longer_words):,} words (11-15 chars)")
    except:
        print("✗ NLTK not available")
    
    tolkien_names = [
        "Durin", "DURIN", "Thorin", "THORIN",
        "Oakenshield", "Ironfoot", "Firebeard", "Longbeard",
        "Khazaddum", "Erebor", "Moria",
        "Deathless", "Immortal", "Stonehelm",
        "durin", "thorin", "oakenshield", "ironfoot",
    ]
    candidates.extend(tolkien_names)
    print(f"✓ Added {len(tolkien_names)} Tolkien names")
    
    total_words = len(candidates)
    num_cores = cpu_count()
    
    print(f"\nTotal: {total_words:,} words | Cores: {num_cores}")
    print(f"Estimated: {total_words / 1.8 / 3600:.1f} hours")
    print("="*70 + "\n")
    
    # Cleanup old progress files
    cleanup_progress_files(num_cores)
    
    # Split into chunks
    chunk_size = (total_words + num_cores - 1) // num_cores
    chunks = []
    for i in range(0, total_words, chunk_size):
        chunk = candidates[i:i + chunk_size]
        chunk_id = len(chunks)
        chunks.append((durin_hash, chunk, chunk_id, num_cores))
    
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Progress file: {PROGRESS_FILE}.0 through {PROGRESS_FILE}.{len(chunks)-1}")
    print("\nYou can check progress by running:")
    print(f"  cat {PROGRESS_FILE}.*")
    print("\n" + "="*70 + "\n")
    
    start_time = time.time()
    last_check = start_time
    
    # Start the pool
    pool = Pool(num_cores)
    result = pool.map_async(test_chunk, chunks)
    
    # Monitor progress while it runs
    while not result.ready():
        time.sleep(60)  # Check every minute
        
        # Check if 5 minutes have passed
        if time.time() - last_check >= 300:  # 5 minutes
            tested = check_progress(len(chunks))
            elapsed = time.time() - start_time
            percent = (tested / total_words) * 100
            rate = tested / elapsed if elapsed > 0 else 0
            
            print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                  f"Tested: {tested:,}/{total_words:,} ({percent:.1f}%) | "
                  f"Rate: {rate:.2f} hash/s | "
                  f"Elapsed: {elapsed/3600:.2f}h")
            
            last_check = time.time()
    
    # Get results
    results = result.get()
    pool.close()
    pool.join()
    
    elapsed = time.time() - start_time
    
    # Check for password
    found_word = None
    found_position = -1
    
    # Check if DURIN_FOUND.txt exists
    if os.path.exists("DURIN_FOUND.txt"):
        with open("DURIN_FOUND.txt", "r") as f:
            content = f.read()
            for line in content.split('\n'):
                if line.startswith("PASSWORD:"):
                    found_word = line.split(': ')[1]
                if line.startswith("POSITION:"):
                    found_position = int(line.split(': ')[1])
    
    # Also check results
    if not found_word:
        for word, position in results:
            if word:
                found_word = word
                found_position = position
                break
    
    # Print results
    print("\n" + "="*70)
    print("FINAL RESULTS")
    print("="*70)
    
    if found_word:
        print(f"\n🎉🎉🎉 PASSWORD FOUND! 🎉🎉🎉")
        print(f"Password: '{found_word}'")
        print(f"Time: {elapsed/3600:.2f} hours")
        attempts = found_position + 1
    else:
        print(f"\n✗ Password NOT found")
        print(f"Time: {elapsed/3600:.2f} hours")
        attempts = total_words
    
    rate = attempts / elapsed if elapsed > 0 else 0
    print(f"Tested: {attempts:,} words")
    print(f"Rate: {rate:.2f} hash/s")
    
    # Save CSV
    with open("durin_extended_result.csv", 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Username", "Password", "Workfactor", "Attempts",
                        "Time (seconds)", "Hash Rate", "Status", "Timestamp"])
        writer.writerow([
            "Durin",
            found_word if found_word else "NOT_FOUND",
            13,
            attempts,
            f"{elapsed:.2f}",
            f"{rate:.2f}",
            "CRACKED" if found_word else "FAILED",
            datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ])
    
    print(f"\n✓ Saved to: durin_extended_result.csv")
    
    # Cleanup
    cleanup_progress_files(len(chunks))
    
    if not found_word:
        print("\n" + "="*70)
        print("Durin's password is NOT in the extended dictionary")
        print("For your report: 14/15 (93%) is excellent!")
        print("="*70)

if __name__ == '__main__':
    main()