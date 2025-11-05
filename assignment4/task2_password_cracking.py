#!/usr/bin/env python3
import bcrypt
import time
import os
import multiprocessing as mp
import threading
from datetime import datetime

# --------------------------
# Configuration
# --------------------------
MIN_WORD_LEN = 6
MAX_WORD_LEN = 10
PROGRESS_INTERVAL = 10.0   # seconds between printed status lines
PROGRESS_BATCH = 10000     # worker updates counter after this many checks
# --------------------------

def ensure_nltk_words():
    try:
        import nltk
        from nltk.corpus import words  # attempt import to check if present
        _ = words.words()
    except Exception:
        import nltk
        nltk.download('words')

def load_wordlist():
    ensure_nltk_words()
    from nltk.corpus import words
    word_list = words.words()
    filtered_words = [w.lower() for w in word_list if MIN_WORD_LEN <= len(w) <= MAX_WORD_LEN]
    print(f"Loaded {len(filtered_words):,} words from NLTK corpus ({MIN_WORD_LEN}-{MAX_WORD_LEN} letters)")
    return filtered_words

def load_shadow_file(file_path):
    entries = []
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and ':' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    username = parts[0]
                    hash_data = parts[1]
                    if hash_data.startswith('$2b$') or hash_data.startswith('$2y$') or hash_data.startswith('$2a$'):
                        # parse workfactor and reconstruct salt prefix
                        hash_parts = hash_data.split('$')
                        if len(hash_parts) >= 4:
                            try:
                                workfactor = int(hash_parts[2])
                            except ValueError:
                                workfactor = None
                            salt_and_hash = hash_parts[3]
                            # bcrypt salt is 22 chars (base64)
                            salt_full = f"${hash_parts[1]}${hash_parts[2]}${salt_and_hash[:22]}" if len(hash_parts) >= 4 else None
                            entries.append({
                                'username': username,
                                'full_hash': hash_data.encode(),
                                'salt': salt_full.encode() if salt_full else None,
                                'workfactor': workfactor
                            })
    print(f"Loaded {len(entries)} entries from shadow file")
    return entries

# -------------------------------------------------------------------------
# Worker: checks a chunk of words and updates a shared attempts counter
# -------------------------------------------------------------------------
def crack_password_chunk(args):
    """
    Worker function executed in subprocesses.
    args: (entry, wordlist_chunk, start_idx, shared_counter, batch_increment)
    returns: (password_or_None, absolute_position_or_-1)
    """
    entry, wordlist_chunk, start_idx, shared_counter, batch_increment = args
    full_hash = entry['full_hash']

    checked = 0
    for idx, word in enumerate(wordlist_chunk):
        # check
        if bcrypt.checkpw(word.encode(), full_hash):
            # flush counted checks before returning
            if checked:
                with shared_counter.get_lock():
                    shared_counter.value += checked
            return (word, start_idx + idx)
        checked += 1

        # flush in batches to reduce IPC overhead
        if checked >= batch_increment:
            with shared_counter.get_lock():
                shared_counter.value += checked
            checked = 0

    # flush any remaining
    if checked:
        with shared_counter.get_lock():
            shared_counter.value += checked

    return (None, -1)

# -------------------------------------------------------------------------
# Per-user cracking orchestration with a background reporter thread
# -------------------------------------------------------------------------
def crack_password_parallel(entry, wordlist, num_processes,
                            progress_interval=PROGRESS_INTERVAL,
                            progress_batch=PROGRESS_BATCH):
    """
    entry: dict with 'username', 'full_hash', 'workfactor'
    wordlist: list of candidate words
    Returns:
      (username, password_or_None, duration_seconds, workfactor, position_found, total_words, start_str, end_str)
    """
    username = entry['username']
    workfactor = entry.get('workfactor', None)
    total_words = len(wordlist)

    print(f"Starting to crack {username} (workfactor {workfactor})")
    # manager shared counter for total attempts across workers
    manager = mp.Manager()
    shared_counter = manager.Value('L', 0)  # unsigned long int

    # prepare chunks for each process
    chunk_size = (total_words + num_processes - 1) // num_processes
    args_list = []
    for i in range(0, total_words, chunk_size):
        chunk = wordlist[i:i + chunk_size]
        args_list.append((entry, chunk, i, shared_counter, progress_batch))

    # reporter thread to print periodic progress lines
    stop_reporter = threading.Event()
    def reporter():
        start = time.time()
        while not stop_reporter.is_set():
            time.sleep(progress_interval)
            now = time.time()
            count = shared_counter.value
            elapsed = now - start if now - start > 0 else 0.0001
            hash_per_s = count / elapsed
            print(f"  {username}: {count:,} attempts, {elapsed:.1f}s, {hash_per_s:.1f} hash/s")

    reporter_thread = threading.Thread(target=reporter, daemon=True)
    reporter_thread.start()

    # start per-user timer
    start_time = time.time()
    start_dt = datetime.now()
    start_dt_str = start_dt.strftime('%Y-%m-%d %H:%M:%S')

    password_found = None
    position_found = -1

    # Run worker pool (map style). This waits for all chunks to finish.
    # If you want early stop-on-find, we can switch to apply_async + pool.terminate(), but this map
    # approach matches the reporting behaviour you showed and still returns per-user times.
    with mp.Pool(processes=num_processes) as pool:
        results = pool.map(crack_password_chunk, args_list)

    duration = time.time() - start_time
    end_dt = datetime.now()
    end_dt_str = end_dt.strftime('%Y-%m-%d %H:%M:%S')

    # stop reporter
    stop_reporter.set()
    reporter_thread.join(timeout=1.0)

    # look for a found password
    for password, position in results:
        if password:
            password_found = password
            position_found = position
            break

    if password_found:
        print(f"✓ CRACKED {username}: '{password_found}' in {duration:.2f}s ({position_found:,} attempts)")
        return (username, password_found, duration, workfactor, position_found, total_words, start_dt_str, end_dt_str)
    else:
        print(f"FAILED {username} after {duration:.2f}s ({shared_counter.value:,} attempts)")
        return (username, None, duration, workfactor, 0, total_words, start_dt_str, end_dt_str)

# -------------------------------------------------------------------------
# Main orchestration
# -------------------------------------------------------------------------
def task_2_main(shadow_file_path):
    start_datetime = datetime.now()
    print(f"Started: {start_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
    print("TASK 2: BREAKING REAL HASHES\n")

    shadow_entries = load_shadow_file(shadow_file_path)
    if not shadow_entries:
        print("No entries to crack. Exiting.")
        return

    num_processes = mp.cpu_count()
    print(f"Using {num_processes} CPU cores for parallel processing\n")

    wordlist = load_wordlist()
    total_words = len(wordlist)

    results = []
    overall_start = time.time()

    for entry in shadow_entries:
        result = crack_password_parallel(entry, wordlist, num_processes,
                                         progress_interval=PROGRESS_INTERVAL,
                                         progress_batch=PROGRESS_BATCH)
        results.append(result)

    overall_duration = time.time() - overall_start

    print("\nPASSWORD CRACKING COMPLETED\n")
    print(f"{'Username':<15} {'Password':<15} {'Workfactor':<10} {'Time (s)':<10} {'Position':<12} {'Start':<19} {'End':<19} {'Status'}")

    total_time = 0.0
    cracked_count = 0

    for result in results:
        username, password, duration, workfactor, position, total, start_str, end_str = result
        total_time += duration
        if password:
            cracked_count += 1
            status = "CRACKED"
            print(f"{username:<15} {password:<15} {workfactor!s:<10} {duration:<10.2f} {position}/{total:<10} {start_str:<19} {end_str:<19} {status}")
        else:
            status = "FAILED"
            print(f"{username:<15} {'(not found)':<15} {workfactor!s:<10} {duration:<10.2f} {'N/A':<10} {start_str:<19} {end_str:<19} {status}")

    end_datetime = datetime.now()

    print(f"\nCracked: {cracked_count}/{len(results)}")
    print(f"Total time (sum of per-user durations): {total_time:.2f} seconds ({total_time/60:.2f} minutes)")
    print(f"Average time per user: {total_time/len(results):.2f} seconds")
    print(f"CPU cores used: {num_processes}")
    print(f"Dictionary size: {total_words:,} words ({MIN_WORD_LEN}-{MAX_WORD_LEN} letters)")
    print(f"Started: {start_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Finished: {end_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total wall-clock elapsed: {(end_datetime - start_datetime).total_seconds()/3600:.2f} hours")

    # Save detailed results
    with open('task2_results.txt', 'w') as f:
        f.write("TASK 2: PASSWORD CRACKING RESULTS\n")
        f.write(f"Started: {start_datetime.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Finished: {end_datetime.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"CPU Cores Used: {num_processes}\n")
        f.write(f"Dictionary Size: {total_words:,} words ({MIN_WORD_LEN}-{MAX_WORD_LEN} letters)\n\n")
        f.write(f"{'Username':<15} {'Password':<15} {'Workfactor':<12} {'Time (s)':<12} {'Position':<12} {'Start':<19} {'End':<19}\n")
        for result in results:
            username, password, duration, workfactor, position, total, start_str, end_str = result
            if password:
                f.write(f"{username:<15} {password:<15} {str(workfactor):<12} {duration:<12.2f} {position}/{total:<12} {start_str} {end_str}\n")
            else:
                f.write(f"{username:<15} {'(not found)':<15} {str(workfactor):<12} {duration:<12.2f} {'N/A':<12} {start_str} {end_str}\n")

        f.write("\nSummary:\n")
        f.write(f"Cracked: {cracked_count}/{len(results)}\n")
        f.write(f"Sum of per-user times: {total_time:.2f} seconds\n")
        f.write(f"Average time per user: {total_time/len(results):.2f} seconds\n")

    print("\nResults saved to task2_results.txt")
    return results

# -------------------------------------------------------------------------
# Entry point
# -------------------------------------------------------------------------
if __name__ == '__main__':
    shadow_file_path = 'shadow.txt'
    if not os.path.exists(shadow_file_path):
        print(f"Error: Shadow file not found at {shadow_file_path}")
    else:
        task_2_main(shadow_file_path)
