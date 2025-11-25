# # import bcrypt, time
# # from multiprocessing import Pool, cpu_count
# # from nltk.corpus import words

# # durin = b"$2b$13$6ypcazOOkUT/a7EwMuIjH.qbdqmHPDAC9B5c37RT9gEw18BX6FOay"
# # wordlist = [w.lower() for w in words.words() if 6 <= len(w) <= 10]

# # def check(args):
# #     h, chunk = args
# #     for w in chunk:
# #         if bcrypt.checkpw(w.encode(), h): return w

# # start = time.time()
# # chunks = [wordlist[i::cpu_count()] for i in range(cpu_count())]
# # with Pool() as p:
# #     results = p.map(check, [(durin, c) for c in chunks])
# # password = [r for r in results if r][0]
# # print(f"Durin: {password} ({time.time()-start:.0f}s)")



# #!/usr/bin/env python3
# import bcrypt
# import time
# import csv
# from multiprocessing import Pool, cpu_count
# from datetime import datetime
# from nltk.corpus import words

# # ----------------------------
# # CONFIG
# # ----------------------------
# USERNAME = "Durin"
# HASH = b"$2b$13$6ypcazOOkUT/a7EwMuIjH.qbdqmHPDAC9B5c37RT9gEw18BX6FOay"
# OUTPUT_FILE = "durin_result.csv"

# # ----------------------------
# # WORDLIST LOADING
# # ----------------------------
# def load_wordlist():
#     wordlist = [w.lower() for w in words.words() if 6 <= len(w) <= 10]
#     print(f"Loaded {len(wordlist):,} candidate words (6–10 letters)")
#     return wordlist

# # ----------------------------
# # WORKER FUNCTION
# # ----------------------------
# def crack_chunk(args):
#     hash_data, chunk = args
#     for word in chunk:
#         if bcrypt.checkpw(word.encode(), hash_data):
#             return word
#     return None

# # ----------------------------
# # MAIN
# # ----------------------------
# def main():
#     wordlist = load_wordlist()
#     total = len(wordlist)
#     num_cores = cpu_count()
#     chunk_size = total // num_cores
#     chunks = [wordlist[i:i + chunk_size] for i in range(0, total, chunk_size)]

#     print(f"Cracking {USERNAME} (workfactor 13) using {num_cores} cores...")
#     start_time = datetime.now()
#     start_secs = time.time()

#     with Pool(num_cores) as pool:
#         results = pool.map(crack_chunk, [(HASH, c) for c in chunks])

#     end_secs = time.time()
#     end_time = datetime.now()
#     duration = end_secs - start_secs

#     # Find password if any chunk found it
#     password = next((r for r in results if r), None)
#     status = "CRACKED" if password else "FAILED"

#     # Compute simple metrics
#     attempts = total if not password else wordlist.index(password) + 1
#     hash_rate = attempts / duration if duration > 0 else 0
#     percent = (attempts / total) * 100

#     # Print summary
#     print("\n===== RESULT =====")
#     print(f"Username : {USERNAME}")
#     print(f"Password : {password or 'NOT_FOUND'}")
#     print(f"Workfactor: 13")
#     print(f"Attempts : {attempts:,}")
#     print(f"Time (s) : {duration:.2f}")
#     print(f"Hash Rate: {hash_rate:.2f} hash/s")
#     print(f"Progress : {percent:.2f}%")
#     print(f"Start    : {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
#     print(f"End      : {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
#     print(f"Status   : {status}")

#     # Save to CSV (same format as your main file)
#     with open(OUTPUT_FILE, "w", newline="") as f:
#         writer = csv.writer(f)
#         writer.writerow([
#             "Username", "Password", "Workfactor", "Attempts",
#             "Time (seconds)", "Hash Rate (hash/s)",
#             "Position in Dictionary", "Dictionary Size",
#             "Percent Through Dictionary", "Start Time", "End Time", "Status"
#         ])
#         writer.writerow([
#             USERNAME, password or "NOT_FOUND", 13, attempts,
#             f"{duration:.2f}", f"{hash_rate:.2f}",
#             attempts if password else "N/A", total,
#             f"{percent:.2f}", start_time.strftime("%Y-%m-%d %H:%M:%S"),
#             end_time.strftime("%Y-%m-%d %H:%M:%S"), status
#         ])

#     print(f"\nResult saved to: {OUTPUT_FILE}")

# if __name__ == "__main__":
#     main()

#!/usr/bin/env python3
"""
crack_durin_only.py
Crack ONLY Durin's bcrypt hash using NLTK words corpus.

Now includes:
    • Background progress reporter
    • Prints progress every 20 minutes
"""

import os
import time
import csv
import multiprocessing as mp
import threading
from datetime import datetime

import bcrypt
import nltk
from nltk.corpus import words

# ----------------- CONFIG -----------------
MIN_WORD_LEN = 6
MAX_WORD_LEN = 10
CSV_OUTPUT_FILE = "task2_cracked_passwords.csv"
PROGRESS_INTERVAL_MINUTES = 20      # <-- PRINT EVERY 20 MINUTES
# ------------------------------------------

# Durin’s shadow entry
DURIN_USER = "Durin"
DURIN_HASH = b"$2b$13$6ypcazOOkUT/a7EwMuIjH.qbdqmHPDAC9B5c37RT9gEw18BX6FOay"
DURIN_WORKFACTOR = 13

# shared progress counter
total_attempts = 0
attempts_lock = threading.Lock()


# ---------------------------------------------------
#                    WORDLIST
# ---------------------------------------------------
def ensure_nltk_words():
    """Ensure NLTK words corpus is available."""
    try:
        _ = words.words()
    except LookupError:
        print("Downloading NLTK words corpus...")
        nltk.download("words")


def load_wordlist():
    """Load 6–10 letter words."""
    ensure_nltk_words()
    wl = words.words()
    filtered = [w.lower() for w in wl if MIN_WORD_LEN <= len(w) <= MAX_WORD_LEN]
    print(f"✓ Loaded {len(filtered):,} words from NLTK ({MIN_WORD_LEN}-{MAX_WORD_LEN} letters)")
    return filtered


# ---------------------------------------------------
#                  PARALLEL WORKER
# ---------------------------------------------------
def crack_chunk(args):
    """
    Worker: tries a chunk of the dictionary.
    Returns (pwd, index, attempts_in_chunk)
    """
    full_hash, chunk, start_index = args
    attempts = 0

    for i, word in enumerate(chunk):
        attempts += 1
        try:
            if bcrypt.checkpw(word.encode(), full_hash):
                return word, start_index + i, attempts
        except Exception:
            continue

    return None, -1, attempts


# ---------------------------------------------------
#              PROGRESS REPORT THREAD
# ---------------------------------------------------
def progress_reporter(start_time, total_words, stop_event):
    """Print progress every X minutes."""
    interval = PROGRESS_INTERVAL_MINUTES * 60

    while not stop_event.is_set():
        time.sleep(interval)

        with attempts_lock:
            count = total_attempts

        elapsed = time.time() - start_time
        percent = (count / total_words) * 100

        print("\n--- Durin cracking progress update ---")
        print(f"Time elapsed: {elapsed/3600:.2f} hours")
        print(f"Attempts: {count:,} / {total_words:,}")
        print(f"Percent complete: {percent:.2f}%")
        print("--------------------------------------\n")


# ---------------------------------------------------
#                  MAIN CRACKER
# ---------------------------------------------------
def crack_durin_parallel(wordlist, num_cores):
    global total_attempts

    print("="*70)
    print(f"Cracking {DURIN_USER} (workfactor {DURIN_WORKFACTOR})")
    print(f"Dictionary size: {len(wordlist):,} | CPU cores: {num_cores}")
    print("="*70)

    start_time = time.time()
    start_dt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # reset attempts
    with attempts_lock:
        total_attempts = 0

    # create chunks
    chunk_size = (len(wordlist) + num_cores - 1) // num_cores
    chunks = [
        (DURIN_HASH, wordlist[i:i + chunk_size], i)
        for i in range(0, len(wordlist), chunk_size)
    ]

    # start progress reporter thread
    stop_event = threading.Event()
    reporter_thread = threading.Thread(
        target=progress_reporter,
        args=(start_time, len(wordlist), stop_event),
        daemon=True
    )
    reporter_thread.start()

    password_found = None
    position = -1
    total_local_attempts = 0

    # run multiprocessing
    with mp.Pool(processes=num_cores) as pool:
        results = pool.map(crack_chunk, chunks)

    # collect results
    for pwd, pos, attempts in results:
        total_local_attempts += attempts

        with attempts_lock:
            total_attempts += attempts

        if pwd and password_found is None:
            password_found = pwd
            position = pos

    elapsed = time.time() - start_time
    stop_event.set()
    reporter_thread.join(timeout=1)

    end_dt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if password_found:
        print("\n✓✓✓ PASSWORD CRACKED ✓✓✓")
        print(f"Password: {password_found}")
    else:
        print("\n✗ Password not found")

    print(f"Time: {elapsed:.2f} seconds")
    print(f"Attempts: {total_local_attempts:,}")

    save_result(password_found, total_local_attempts, elapsed, position,
                len(wordlist), start_dt, end_dt)

    return password_found


# ---------------------------------------------------
#                  SAVE TO CSV
# ---------------------------------------------------
def save_result(password, attempts, elapsed, position, dict_size, start, end):
    """Append row to task2_cracked_passwords.csv"""
    file_exists = os.path.exists(CSV_OUTPUT_FILE)

    with open(CSV_OUTPUT_FILE, "a", newline="") as f:
        w = csv.writer(f)

        if not file_exists:
            w.writerow([
                "Username", "Password", "Workfactor", "Attempts",
                "Time (seconds)", "Hash Rate (hash/s)", "Position in Dictionary",
                "Dictionary Size", "Percent Through Dictionary",
                "Start Time", "End Time", "Status"
            ])

        percent = (position/dict_size * 100) if position >= 0 else 100.0
        rate = attempts / elapsed if elapsed > 0 else 0
        status = "CRACKED" if password else "FAILED"

        w.writerow([
            DURIN_USER,
            password if password else "NOT_FOUND",
            DURIN_WORKFACTOR,
            attempts,
            f"{elapsed:.2f}",
            f"{rate:.2f}",
            position if position >= 0 else "N/A",
            dict_size,
            f"{percent:.2f}",
            start,
            end,
            status
        ])

    print(f"✓ Saved result to {CSV_OUTPUT_FILE}")


# ---------------------------------------------------
#                      ENTRY
# ---------------------------------------------------
def main():
    wl = load_wordlist()
    cores = mp.cpu_count()
    print(f"Using {cores} CPU cores\n")
    crack_durin_parallel(wl, cores)


if __name__ == "__main__":
    mp.freeze_support()
    main()
