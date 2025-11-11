import bcrypt
import time
from multiprocessing import Pool, cpu_count

def load_wordlist():
    from nltk.corpus import words
    return [w.lower() for w in words.words() if 6 <= len(w) <= 10]

def crack_chunk(args):
    hash_data, chunk = args
    for word in chunk:
        if bcrypt.checkpw(word.encode(), hash_data):
            return word
    return None

# Durin's hash
durin_hash = b"$2b$13$6ypcazOOkUT/a7EwMuIjH.qbdqmHPDAC9B5c37RT9gEw18BX6FOay"

wordlist = load_wordlist()
num_cores = cpu_count()

# Split into chunks
chunk_size = len(wordlist) // num_cores
chunks = [wordlist[i:i+chunk_size] for i in range(0, len(wordlist), chunk_size)]

print(f"Cracking Durin with {num_cores} cores...")
start = time.time()

with Pool(num_cores) as pool:
    results = pool.map(crack_chunk, [(durin_hash, c) for c in chunks])

for password in results:
    if password:
        duration = time.time() - start
        print(f"CRACKED Durin: {password} in {duration:.2f}s")
        break