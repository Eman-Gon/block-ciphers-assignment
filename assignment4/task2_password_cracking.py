#!/usr/bin/env python3
"""
TASK 2: Password Cracking (CRASH-RESISTANT VERSION)
Includes error handling, progress saving, and graceful degradation
"""

import sys
import os
import time
from datetime import datetime

# Try importing required modules with helpful error messages
try:
    import bcrypt
except ImportError:
    print("ERROR: bcrypt not installed")
    print("Run: pip install bcrypt --break-system-packages")
    sys.exit(1)

try:
    import nltk
    from nltk.corpus import words
except ImportError:
    print("ERROR: nltk not installed")
    print("Run: pip install nltk --break-system-packages")
    sys.exit(1)

# Multiprocessing is optional - fallback to sequential
try:
    import multiprocessing as mp
    HAS_MULTIPROCESSING = True
except:
    HAS_MULTIPROCESSING = False
    print("WARNING: Multiprocessing not available, using sequential mode")

# Configuration
MIN_WORD_LEN = 6
MAX_WORD_LEN = 10
PROGRESS_INTERVAL = 10.0  # seconds
SAVE_PROGRESS = True
PROGRESS_FILE = "task2_progress.txt"

def ensure_nltk_words():
    """Ensure NLTK words corpus is available"""
    try:
        _ = words.words()
        return True
    except LookupError:
        print("Downloading NLTK words corpus...")
        try:
            nltk.download('words', quiet=False)
            return True
        except Exception as e:
            print(f"ERROR downloading NLTK corpus: {e}")
            print("\nManual fix:")
            print("  import nltk")
            print("  nltk.download('words')")
            return False

def load_wordlist():
    """Load and filter NLTK word corpus"""
    if not ensure_nltk_words():
        print("ERROR: Cannot load word corpus")
        sys.exit(1)
    
    try:
        word_list = words.words()
        filtered = [w.lower() for w in word_list if MIN_WORD_LEN <= len(w) <= MAX_WORD_LEN]
        print(f"✓ Loaded {len(filtered):,} words from NLTK corpus ({MIN_WORD_LEN}-{MAX_WORD_LEN} letters)")
        return filtered
    except Exception as e:
        print(f"ERROR loading wordlist: {e}")
        sys.exit(1)

def load_shadow_file(file_path):
    """Load and parse shadow file"""
    if not os.path.exists(file_path):
        print(f"ERROR: Shadow file not found: {file_path}")
        print("\nTried locations:")
        for path in ['shadow.txt', './shadow.txt', '../shadow.txt']:
            print(f"  - {os.path.abspath(path)}")
        sys.exit(1)
    
    entries = []
    try:
        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if ':' not in line:
                    print(f"WARNING: Skipping malformed line {line_num}: {line[:50]}")
                    continue
                
                parts = line.split(':')
                if len(parts) < 2:
                    continue
                
                username = parts[0]
                hash_data = parts[1]
                
                # Parse bcrypt hash
                if not hash_data.startswith('$2'):
                    print(f"WARNING: {username} has non-bcrypt hash, skipping")
                    continue
                
                hash_parts = hash_data.split('$')
                if len(hash_parts) < 4:
                    print(f"WARNING: {username} has malformed hash, skipping")
                    continue
                
                try:
                    workfactor = int(hash_parts[2])
                except ValueError:
                    print(f"WARNING: {username} has invalid workfactor, skipping")
                    continue
                
                entries.append({
                    'username': username,
                    'full_hash': hash_data.encode(),
                    'workfactor': workfactor
                })
        
        print(f"✓ Loaded {len(entries)} valid entries from {file_path}")
        return entries
        
    except Exception as e:
        print(f"ERROR reading shadow file: {e}")
        sys.exit(1)

def crack_password_sequential(entry, wordlist):
    """Crack a single password sequentially"""
    username = entry['username']
    full_hash = entry['full_hash']
    workfactor = entry.get('workfactor', '?')
    
    print(f"\nCracking {username} (workfactor {workfactor})...")
    print(f"  Dictionary size: {len(wordlist):,} words")
    
    start_time = time.time()
    last_progress = time.time()
    
    try:
        for idx, word in enumerate(wordlist, 1):
            # Check password
            try:
                if bcrypt.checkpw(word.encode(), full_hash):
                    elapsed = time.time() - start_time
                    print(f"  ✓ CRACKED: '{word}' in {elapsed:.2f}s ({idx:,} attempts)")
                    return word, idx, elapsed
            except Exception as e:
                # Skip invalid comparisons
                continue
            
            # Progress updates
            if time.time() - last_progress > PROGRESS_INTERVAL:
                elapsed = time.time() - start_time
                rate = idx / elapsed if elapsed > 0 else 0
                percent = (idx / len(wordlist)) * 100
                print(f"  Progress: {idx:,}/{len(wordlist):,} ({percent:.1f}%) | "
                      f"{elapsed:.1f}s | {rate:.1f} hash/s")
                last_progress = time.time()
    
    except KeyboardInterrupt:
        print(f"\n  ⚠️  Interrupted by user")
        elapsed = time.time() - start_time
        return None, idx, elapsed
    
    elapsed = time.time() - start_time
    print(f"  ✗ FAILED: Password not found in dictionary ({elapsed:.2f}s)")
    return None, len(wordlist), elapsed

def save_result(username, password, elapsed, workfactor, attempts):
    """Save cracked password to progress file"""
    if not SAVE_PROGRESS:
        return
    
    try:
        with open(PROGRESS_FILE, 'a') as f:
            status = "CRACKED" if password else "FAILED"
            f.write(f"{username},{password or 'NOT_FOUND'},{workfactor},"
                   f"{elapsed:.2f},{attempts},{status}\n")
    except Exception as e:
        print(f"  WARNING: Could not save progress: {e}")

def main():
    """Main function"""
    print("=" * 70)
    print("CRYPTOGRAPHIC HASH FUNCTIONS - TASK 2")
    print("PASSWORD CRACKING (CRASH-RESISTANT VERSION)")
    print("=" * 70)
    
    start_datetime = datetime.now()
    print(f"\nStarted: {start_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Clear old progress file
    if SAVE_PROGRESS and os.path.exists(PROGRESS_FILE):
        os.remove(PROGRESS_FILE)
    
    # Load data
    print("\n" + "=" * 70)
    print("LOADING DATA")
    print("=" * 70)
    
    wordlist = load_wordlist()
    shadow_file = 'shadow.txt'
    
    # Try multiple locations
    for path in ['shadow.txt', './shadow.txt', '../shadow.txt', 
                 '/home/claude/shadow.txt']:
        if os.path.exists(path):
            shadow_file = path
            break
    
    entries = load_shadow_file(shadow_file)
    
    if not entries:
        print("ERROR: No valid entries to crack")
        sys.exit(1)
    
    # Crack passwords
    print("\n" + "=" * 70)
    print("CRACKING PASSWORDS")
    print("=" * 70)
    print("Mode: Sequential (no parallel processing)")
    print("This will take a LONG time. Be patient!")
    print("=" * 70)
    
    results = []
    
    try:
        for entry in entries:
            password, attempts, elapsed = crack_password_sequential(entry, wordlist)
            
            result = {
                'username': entry['username'],
                'password': password,
                'workfactor': entry['workfactor'],
                'attempts': attempts,
                'time': elapsed
            }
            results.append(result)
            
            # Save progress after each user
            save_result(entry['username'], password, elapsed, 
                       entry['workfactor'], attempts)
    
    except KeyboardInterrupt:
        print("\n\n⚠️  Program interrupted by user")
        print("Partial results saved to progress file")
    
    # Print summary
    print("\n" + "=" * 70)
    print("RESULTS SUMMARY")
    print("=" * 70)
    
    if results:
        print(f"\n{'Username':<15} {'Password':<15} {'WF':<4} {'Time (s)':<10} {'Attempts':<10}")
        print("-" * 65)
        
        cracked = 0
        total_time = 0
        
        for r in results:
            status = "✓" if r['password'] else "✗"
            pwd = r['password'] if r['password'] else "(not found)"
            print(f"{r['username']:<15} {pwd:<15} {r['workfactor']:<4} "
                  f"{r['time']:<10.2f} {r['attempts']:<10,} {status}")
            
            total_time += r['time']
            if r['password']:
                cracked += 1
        
        print("-" * 65)
        print(f"\nCracked: {cracked}/{len(results)}")
        print(f"Total time: {total_time:.2f}s ({total_time/60:.1f}min, {total_time/3600:.2f}hr)")
        print(f"Average per user: {total_time/len(results):.2f}s")
    
    end_datetime = datetime.now()
    print(f"\nFinished: {end_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Wall-clock time: {(end_datetime - start_datetime).total_seconds()/3600:.2f} hours")
    
    if SAVE_PROGRESS:
        print(f"\nProgress saved to: {PROGRESS_FILE}")
    
    print("\n" + "=" * 70)
    print("TASK 2 COMPLETE")
    print("=" * 70)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"\n\n✗ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)