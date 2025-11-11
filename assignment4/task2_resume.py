#!/usr/bin/env python3
import bcrypt
import time
import os
import multiprocessing as mp
import csv
from datetime import datetime

# Copy all your functions from task2.py here
# (load_wordlist, load_shadow_file, crack_password_chunk, crack_password_parallel)
# ... [paste all the functions] ...

def get_already_cracked():
    """Read CSV to see which users are already done"""
    cracked = set()
    try:
        with open('task2_cracked_passwords.csv', 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['Status'] == 'CRACKED':
                    cracked.add(row['Username'])
    except FileNotFoundError:
        pass
    return cracked

def task_2_main(shadow_file_path):
    start_datetime = datetime.now()
    print(f"Resuming: {start_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
    
    shadow_entries = load_shadow_file(shadow_file_path)
    
    # Check which are already done
    already_cracked = get_already_cracked()
    print(f"Already cracked: {len(already_cracked)} users")
    print(f"Remaining: {len(shadow_entries) - len(already_cracked)} users")
    
    # Filter to only crack remaining users
    remaining_entries = [e for e in shadow_entries if e['username'] not in already_cracked]
    
    if not remaining_entries:
        print("All passwords already cracked!")
        return
    
    num_processes = mp.cpu_count()
    print(f"Using {num_processes} CPU cores\n")
    
    wordlist = load_wordlist()
    
    results = []
    
    for entry in remaining_entries:
        result = crack_password_parallel(entry, wordlist, num_processes)
        results.append(result)
    
    print("\nRESUMED SESSION COMPLETE")
    return results

if __name__ == '__main__':
    task_2_main('shadow.txt')