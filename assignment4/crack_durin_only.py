# import bcrypt, time
# from multiprocessing import Pool, cpu_count
# from nltk.corpus import words

# durin = b"$2b$13$6ypcazOOkUT/a7EwMuIjH.qbdqmHPDAC9B5c37RT9gEw18BX6FOay"
# wordlist = [w.lower() for w in words.words() if 6 <= len(w) <= 10]

# def check(args):
#     h, chunk = args
#     for w in chunk:
#         if bcrypt.checkpw(w.encode(), h): return w

# start = time.time()
# chunks = [wordlist[i::cpu_count()] for i in range(cpu_count())]
# with Pool() as p:
#     results = p.map(check, [(durin, c) for c in chunks])
# password = [r for r in results if r][0]
# print(f"Durin: {password} ({time.time()-start:.0f}s)")



#!/usr/bin/env python3
import bcrypt
import time
import csv
from multiprocessing import Pool, cpu_count
from datetime import datetime
from nltk.corpus import words

# ----------------------------
# CONFIG
# ----------------------------
USERNAME = "Durin"
HASH = b"$2b$13$6ypcazOOkUT/a7EwMuIjH.qbdqmHPDAC9B5c37RT9gEw18BX6FOay"
OUTPUT_FILE = "durin_result.csv"

# ----------------------------
# WORDLIST LOADING
# ----------------------------
def load_wordlist():
    wordlist = [w.lower() for w in words.words() if 6 <= len(w) <= 10]
    print(f"Loaded {len(wordlist):,} candidate words (6–10 letters)")
    return wordlist

# ----------------------------
# WORKER FUNCTION
# ----------------------------
def crack_chunk(args):
    hash_data, chunk = args
    for word in chunk:
        if bcrypt.checkpw(word.encode(), hash_data):
            return word
    return None

# ----------------------------
# MAIN
# ----------------------------
def main():
    wordlist = load_wordlist()
    total = len(wordlist)
    num_cores = cpu_count()
    chunk_size = total // num_cores
    chunks = [wordlist[i:i + chunk_size] for i in range(0, total, chunk_size)]

    print(f"Cracking {USERNAME} (workfactor 13) using {num_cores} cores...")
    start_time = datetime.now()
    start_secs = time.time()

    with Pool(num_cores) as pool:
        results = pool.map(crack_chunk, [(HASH, c) for c in chunks])

    end_secs = time.time()
    end_time = datetime.now()
    duration = end_secs - start_secs

    # Find password if any chunk found it
    password = next((r for r in results if r), None)
    status = "CRACKED" if password else "FAILED"

    # Compute simple metrics
    attempts = total if not password else wordlist.index(password) + 1
    hash_rate = attempts / duration if duration > 0 else 0
    percent = (attempts / total) * 100

    # Print summary
    print("\n===== RESULT =====")
    print(f"Username : {USERNAME}")
    print(f"Password : {password or 'NOT_FOUND'}")
    print(f"Workfactor: 13")
    print(f"Attempts : {attempts:,}")
    print(f"Time (s) : {duration:.2f}")
    print(f"Hash Rate: {hash_rate:.2f} hash/s")
    print(f"Progress : {percent:.2f}%")
    print(f"Start    : {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"End      : {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Status   : {status}")

    # Save to CSV (same format as your main file)
    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Username", "Password", "Workfactor", "Attempts",
            "Time (seconds)", "Hash Rate (hash/s)",
            "Position in Dictionary", "Dictionary Size",
            "Percent Through Dictionary", "Start Time", "End Time", "Status"
        ])
        writer.writerow([
            USERNAME, password or "NOT_FOUND", 13, attempts,
            f"{duration:.2f}", f"{hash_rate:.2f}",
            attempts if password else "N/A", total,
            f"{percent:.2f}", start_time.strftime("%Y-%m-%d %H:%M:%S"),
            end_time.strftime("%Y-%m-%d %H:%M:%S"), status
        ])

    print(f"\nResult saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
