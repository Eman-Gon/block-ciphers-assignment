#!/usr/bin/env python3
"""
TASK 2: Password Cracking - FAST PARALLEL VERSION (macOS Fixed)
Uses all CPU cores to crack passwords much faster (6-8x speedup!)
"""

import sys
import os
import time
import csv
from datetime import datetime
import multiprocessing as mp
from multiprocessing import Pool
import threading

# Import required modules with error handling
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

# Configuration
MIN_WORD_LEN = 6
MAX_WORD_LEN = 10
PROGRESS_INTERVAL = 10.0
CSV_OUTPUT_FILE = "task2_cracked_passwords.csv"
PROGRESS_CSV_FILE = "task2_progress_log.csv"
SUMMARY_CSV_FILE = "task2_summary.csv"

# Global progress tracking (simpler approach for macOS)
total_attempts = 0
attempts_lock = threading.Lock()

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
        sys.exit(1)
    
    entries = []
    try:
        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if ':' not in line:
                    continue
                
                parts = line.split(':')
                if len(parts) < 2:
                    continue
                
                username = parts[0]
                hash_data = parts[1]
                
                if not hash_data.startswith('$2'):
                    continue
                
                hash_parts = hash_data.split('$')
                if len(hash_parts) < 4:
                    continue
                
                try:
                    workfactor = int(hash_parts[2])
                except ValueError:
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

def initialize_csv_files():
    """Initialize CSV files with headers"""
    with open(CSV_OUTPUT_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Username', 'Password', 'Workfactor', 'Attempts', 
            'Time (seconds)', 'Hash Rate (hash/s)', 'Position in Dictionary',
            'Dictionary Size', 'Percent Through Dictionary',
            'Start Time', 'End Time', 'Status'
        ])
    
    with open(PROGRESS_CSV_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Username', 'Workfactor', 'Progress Update Time',
            'Attempts So Far', 'Elapsed Time (s)', 'Hash Rate (hash/s)',
            'Percent Complete'
        ])
    
    print(f"✓ CSV files initialized")

def crack_chunk(args):
    """
    Worker function: tries to crack password with a chunk of the wordlist
    Returns (password, position, attempts_made)
    """
    full_hash, wordlist_chunk, start_idx = args
    
    attempts = 0
    for idx, word in enumerate(wordlist_chunk):
        try:
            if bcrypt.checkpw(word.encode(), full_hash):
                # Password found!
                return (word, start_idx + idx, attempts + 1)
        except:
            pass
        
        attempts += 1
    
    # Chunk completed, no password found
    return (None, -1, attempts)

def progress_reporter(username, workfactor, total_words, stop_event, start_time):
    """Background thread to report progress"""
    global total_attempts
    last_count = 0
    
    while not stop_event.is_set():
        time.sleep(PROGRESS_INTERVAL)
        
        with attempts_lock:
            count = total_attempts
        
        elapsed = time.time() - start_time
        rate = count / elapsed if elapsed > 0 else 0
        percent = (count / total_words) * 100 if total_words > 0 else 0
        
        # Only print if progress changed
        if count > last_count:
            print(f"  [{datetime.now().strftime('%H:%M:%S')}] "
                  f"{count:,}/{total_words:,} ({percent:.1f}%) | "
                  f"{elapsed:.0f}s | {rate:.1f} hash/s")
            
            # Log to CSV
            try:
                with open(PROGRESS_CSV_FILE, 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        username, workfactor,
                        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        count, f"{elapsed:.2f}", f"{rate:.2f}", f"{percent:.2f}"
                    ])
            except:
                pass
            
            last_count = count

def crack_password_parallel(entry, wordlist, num_cores):
    """Crack password using parallel processing"""
    global total_attempts
    
    username = entry['username']
    full_hash = entry['full_hash']
    workfactor = entry['workfactor']
    
    print(f"\n{'='*70}")
    print(f"Cracking {username} (workfactor {workfactor})")
    print(f"Dictionary: {len(wordlist):,} words | Using {num_cores} CPU cores")
    print('='*70)
    
    start_time = time.time()
    start_dt = datetime.now()
    start_dt_str = start_dt.strftime('%Y-%m-%d %H:%M:%S')
    
    # Reset global counter
    with attempts_lock:
        total_attempts = 0
    
    # Split wordlist into chunks for parallel processing
    chunk_size = (len(wordlist) + num_cores - 1) // num_cores
    chunks = []
    
    for i in range(0, len(wordlist), chunk_size):
        chunk = wordlist[i:i + chunk_size]
        chunks.append((full_hash, chunk, i))
    
    # Start progress reporter thread
    stop_reporter = threading.Event()
    reporter_thread = threading.Thread(
        target=progress_reporter,
        args=(username, workfactor, len(wordlist), stop_reporter, start_time),
        daemon=True
    )
    reporter_thread.start()
    
    # Run parallel cracking
    password_found = None
    position = 0
    attempts_made = 0
    
    try:
        with Pool(processes=num_cores) as pool:
            results = pool.map(crack_chunk, chunks)
        
        # Collect results
        for pwd, pos, attempts in results:
            attempts_made += attempts
            with attempts_lock:
                total_attempts += attempts
            
            if pwd and not password_found:
                password_found = pwd
                position = pos
    
    except KeyboardInterrupt:
        print(f"\n⚠️  Interrupted by user")
    finally:
        stop_reporter.set()
        reporter_thread.join(timeout=1)
    
    elapsed = time.time() - start_time
    end_dt = datetime.now()
    end_dt_str = end_dt.strftime('%Y-%m-%d %H:%M:%S')
    
    if password_found:
        print(f"\n{'='*70}")
        print(f"✓✓✓ PASSWORD CRACKED! ✓✓✓")
        print(f"User: {username}")
        print(f"Password: '{password_found}'")
        print(f"Time: {elapsed:.2f}s ({elapsed/60:.2f} min)")
        print(f"Position: {position:,}/{len(wordlist):,}")
        print('='*70)
    else:
        print(f"\n✗ Password not found in dictionary")
        print(f"Time: {elapsed:.2f}s ({elapsed/60:.2f} min)")
        attempts_made = len(wordlist)
    
    # Save to CSV
    save_result(username, password_found, workfactor, attempts_made, elapsed,
                len(wordlist), start_dt_str, end_dt_str)
    
    return password_found, attempts_made, elapsed

def save_result(username, password, workfactor, attempts, elapsed, dict_size, start_time, end_time):
    """Save result to CSV"""
    try:
        with open(CSV_OUTPUT_FILE, 'a', newline='') as f:
            writer = csv.writer(f)
            
            rate = attempts / elapsed if elapsed > 0 else 0
            percent = (attempts / dict_size) * 100 if dict_size > 0 else 0
            status = "CRACKED" if password else "FAILED"
            
            writer.writerow([
                username,
                password if password else "NOT_FOUND",
                workfactor,
                attempts,
                f"{elapsed:.2f}",
                f"{rate:.2f}",
                attempts if password else "N/A",
                dict_size,
                f"{percent:.2f}" if password else "100.00",
                start_time,
                end_time,
                status
            ])
        
        print(f"✓ Saved to {CSV_OUTPUT_FILE}")
        
    except Exception as e:
        print(f"⚠️  Error saving to CSV: {e}")

def create_summary_csv(results, total_time, start_dt, end_dt):
    """Create summary CSV"""
    with open(SUMMARY_CSV_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        
        writer.writerow(['TASK 2: PASSWORD CRACKING SUMMARY (PARALLEL MODE)'])
        writer.writerow([''])
        
        writer.writerow(['OVERALL STATISTICS'])
        writer.writerow(['Metric', 'Value'])
        writer.writerow(['Start Time', start_dt.strftime('%Y-%m-%d %H:%M:%S')])
        writer.writerow(['End Time', end_dt.strftime('%Y-%m-%d %H:%M:%S')])
        writer.writerow(['Total Wall-Clock Time', f"{(end_dt - start_dt).total_seconds() / 3600:.2f} hours"])
        writer.writerow(['Total Users', len(results)])
        writer.writerow(['Passwords Cracked', sum(1 for r in results if r['password'])])
        writer.writerow(['Total Processing Time', f"{total_time:.2f} seconds ({total_time/3600:.2f} hours)"])
        writer.writerow(['Average Time per User', f"{total_time/len(results):.2f} seconds"])
        writer.writerow([''])
        
        writer.writerow(['WORKFACTOR BREAKDOWN'])
        writer.writerow(['Workfactor', 'Users', 'Cracked', 'Avg Time (s)', 'Total Time (s)'])
        
        workfactors = sorted(set(r['workfactor'] for r in results))
        for wf in workfactors:
            wf_results = [r for r in results if r['workfactor'] == wf]
            cracked = sum(1 for r in wf_results if r['password'])
            avg_time = sum(r['time'] for r in wf_results) / len(wf_results)
            total_wf_time = sum(r['time'] for r in wf_results)
            
            writer.writerow([wf, len(wf_results), cracked, f"{avg_time:.2f}", f"{total_wf_time:.2f}"])
        
        writer.writerow([''])
        writer.writerow(['INDIVIDUAL RESULTS'])
        writer.writerow(['Username', 'Password', 'Workfactor', 'Time (s)', 'Attempts', 'Status'])
        
        for r in results:
            writer.writerow([
                r['username'],
                r['password'] if r['password'] else 'NOT_FOUND',
                r['workfactor'],
                f"{r['time']:.2f}",
                r['attempts'],
                'CRACKED' if r['password'] else 'FAILED'
            ])
    
    print(f"✓ Summary saved to {SUMMARY_CSV_FILE}")

def main():
    """Main function"""
    print("=" * 70)
    print("TASK 2: PASSWORD CRACKING - FAST PARALLEL MODE 🚀")
    print("=" * 70)
    
    # Get number of CPU cores
    num_cores = mp.cpu_count()
    print(f"\n✓ Using {num_cores} CPU cores for parallel processing")
    print(f"✓ Expected speedup: ~{num_cores}x faster than sequential")
    
    start_datetime = datetime.now()
    print(f"\nStarted: {start_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Initialize CSV files
    initialize_csv_files()
    
    # Load data
    print("\n" + "=" * 70)
    print("LOADING DATA")
    print("=" * 70)
    
    wordlist = load_wordlist()
    
    # Find shadow file
    shadow_file = 'shadow.txt'
    for path in ['shadow.txt', './shadow.txt', '../shadow.txt', '/home/claude/shadow.txt']:
        if os.path.exists(path):
            shadow_file = path
            break
    
    entries = load_shadow_file(shadow_file)
    
    if not entries:
        print("ERROR: No valid entries to crack")
        sys.exit(1)
    
    # Crack passwords
    print("\n" + "=" * 70)
    print("CRACKING PASSWORDS (PARALLEL MODE)")
    print("=" * 70)
    print(f"Users to crack: {len(entries)}")
    print(f"Dictionary size: {len(wordlist):,} words")
    print(f"CPU cores: {num_cores}")
    print("=" * 70)
    
    results = []
    
    try:
        for entry in entries:
            password, attempts, elapsed = crack_password_parallel(entry, wordlist, num_cores)
            
            result = {
                'username': entry['username'],
                'password': password,
                'workfactor': entry['workfactor'],
                'attempts': attempts,
                'time': elapsed
            }
            results.append(result)
    
    except KeyboardInterrupt:
        print("\n\n⚠️  Program interrupted by user")
        print("Partial results saved to CSV files")
    
    # Create summary
    end_datetime = datetime.now()
    total_time = sum(r['time'] for r in results)
    
    if results:
        create_summary_csv(results, total_time, start_datetime, end_datetime)
    
    # Print final summary
    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    
    if results:
        cracked = sum(1 for r in results if r['password'])
        print(f"\n✓ Passwords cracked: {cracked}/{len(results)}")
        print(f"✓ Total time: {total_time:.2f}s ({total_time/3600:.2f} hours)")
        print(f"✓ Wall-clock time: {(end_datetime - start_datetime).total_seconds()/3600:.2f} hours")
        print(f"✓ Speedup vs sequential: ~{num_cores}x")
        
        print("\n✓ Results saved to:")
        print(f"  1. {CSV_OUTPUT_FILE}")
        print(f"  2. {PROGRESS_CSV_FILE}")
        print(f"  3. {SUMMARY_CSV_FILE}")
    
    print("\n" + "=" * 70)
    print("TASK 2 COMPLETE! 🎉")
    print("=" * 70)

if __name__ == '__main__':
    # Required for multiprocessing on Windows/macOS
    mp.freeze_support()
    
    try:
        main()
    except Exception as e:
        print(f"\n\n✗ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)