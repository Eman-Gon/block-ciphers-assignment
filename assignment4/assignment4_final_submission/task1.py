#!/usr/bin/env python3
"""
TASK 1: SHA256 Collision Finding with CSV Output
Saves all results to CSV files for easy analysis and report creation
"""

import hashlib
import random
import string
import time
import csv
import sys
from datetime import datetime

# Try to import matplotlib, but make it optional
try:
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    print("WARNING: matplotlib not found. Graphs will not be generated.")
    HAS_MATPLOTLIB = False

# Configuration
MAX_BITS = 50
CSV_OUTPUT_FILE = "task1_collision_results.csv"
HAMMING_CSV_FILE = "task1_hamming_distance.csv"

def sha256_hash(input_string):
    """Calculate SHA256 hash of input string and return hex digest"""
    return hashlib.sha256(input_string.encode()).hexdigest()

def truncate_hash(hash_string, bits):
    """Truncate hash to specified number of bits"""
    hex_chars = (bits + 3) // 4
    truncated_hex = hash_string[:hex_chars]
    hash_int = int(truncated_hex, 16)
    bitmask = (1 << bits) - 1
    result = hash_int & bitmask
    return result

def find_collision_safe(bits, max_attempts=None):
    """Find collision with progress tracking and memory management"""
    if max_attempts is None:
        expected = 2 ** (bits / 2)
        max_attempts = int(expected * 20)
    
    seen = {}
    start_time = time.time()
    last_progress = time.time()
    
    print(f"\nFinding collision for {bits}-bit digest...")
    print(f"  Expected attempts: ~{2**(bits/2):,.0f}")
    
    try:
        for attempt in range(1, max_attempts + 1):
            s = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
            full_hash = sha256_hash(s)
            truncated = truncate_hash(full_hash, bits)
            
            if truncated in seen:
                elapsed = time.time() - start_time
                print(f"  ✓ Collision found! Attempts: {attempt:,}, Time: {elapsed:.2f}s")
                return {
                    'success': True,
                    'input1': seen[truncated],
                    'input2': s,
                    'attempts': attempt,
                    'time': elapsed,
                    'hash1': sha256_hash(seen[truncated]),
                    'hash2': sha256_hash(s),
                    'truncated_hash': truncated
                }
            
            seen[truncated] = s
            
            # Progress updates
            if time.time() - last_progress > 10:
                elapsed = time.time() - start_time
                rate = attempt / elapsed if elapsed > 0 else 0
                print(f"  Progress: {attempt:,} attempts, {rate:.0f}/s")
                last_progress = time.time()
            
            # Memory check for large bit sizes
            if bits >= 40 and attempt % 1000000 == 0:
                dict_size_mb = sys.getsizeof(seen) / (1024 * 1024)
                if dict_size_mb > 1500:
                    print(f"  ⚠️  Memory limit reached")
                    break
    
    except KeyboardInterrupt:
        print(f"\n  ⚠️  Interrupted by user")
    except MemoryError:
        print(f"\n  ✗ OUT OF MEMORY")
    
    elapsed = time.time() - start_time
    return {
        'success': False,
        'input1': None,
        'input2': None,
        'attempts': attempt,
        'time': elapsed,
        'hash1': None,
        'hash2': None,
        'truncated_hash': None
    }

def save_collision_to_csv(bits, result, csv_file):
    """Save collision result to CSV file"""
    try:
        # Check if file exists to determine if we need headers
        file_exists = False
        try:
            with open(csv_file, 'r'):
                file_exists = True
        except FileNotFoundError:
            pass
        
        with open(csv_file, 'a', newline='') as f:
            writer = csv.writer(f)
            
            # Write header if new file
            if not file_exists:
                writer.writerow([
                    'Bits', 'Success', 'Attempts', 'Time (seconds)', 
                    'Expected Attempts (2^(n/2))', 'Input 1', 'Input 2',
                    'Hash 1', 'Hash 2', 'Truncated Hash Value',
                    'Timestamp'
                ])
            
            # Write data
            expected = 2 ** (bits / 2)
            writer.writerow([
                bits,
                'Yes' if result['success'] else 'No',
                result['attempts'],
                f"{result['time']:.4f}",
                f"{expected:.0f}",
                result['input1'] or 'N/A',
                result['input2'] or 'N/A',
                result['hash1'] or 'N/A',
                result['hash2'] or 'N/A',
                result['truncated_hash'] if result['truncated_hash'] is not None else 'N/A',
                datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ])
        
        print(f"  ✓ Saved to {csv_file}")
        
    except Exception as e:
        print(f"  ⚠️  Error saving to CSV: {e}")

def save_hamming_to_csv(pair_num, s1, s2, h1, h2, csv_file):
    """Save hamming distance pair to CSV"""
    try:
        # Check if file exists
        file_exists = False
        try:
            with open(csv_file, 'r'):
                file_exists = True
        except FileNotFoundError:
            pass
        
        with open(csv_file, 'a', newline='') as f:
            writer = csv.writer(f)
            
            if not file_exists:
                writer.writerow([
                    'Pair Number', 'String 1', 'String 2', 
                    'Hamming Distance', 'Hash 1', 'Hash 2',
                    'Hex Chars Different', 'Percent Different',
                    'Timestamp'
                ])
            
            # Calculate differences
            byte_diff = sum(c1 != c2 for c1, c2 in zip(h1, h2))
            percent_diff = (byte_diff / 64) * 100
            hamming_dist = sum(c1 != c2 for c1, c2 in zip(s1, s2))
            
            writer.writerow([
                pair_num,
                s1,
                s2,
                hamming_dist,
                h1,
                h2,
                byte_diff,
                f"{percent_diff:.1f}",
                datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ])
    
    except Exception as e:
        print(f"  ⚠️  Error saving hamming data: {e}")

def task_1a_with_csv():
    """Task 1a: Hash arbitrary inputs with SHA256 and save to CSV"""
    print("=" * 70)
    print("Task 1a: SHA256 hashes of arbitrary inputs")
    print("=" * 70)
    
    test_inputs = ["Hello, World!", "Python", "Cryptography", "CPE-321"]
    
    # Save to CSV
    csv_file = "task1a_sha256_hashes.csv"
    with open(csv_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Input', 'SHA256 Hash', 'Timestamp'])
        
        for input_str in test_inputs:
            hash_result = sha256_hash(input_str)
            writer.writerow([
                input_str, 
                hash_result,
                datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ])
            
            print(f"Input: '{input_str}'")
            print(f"SHA256: {hash_result}\n")
    
    print(f"✓ Results saved to {csv_file}\n")

def task_1b_with_csv():
    """Task 1b: Hash strings with Hamming distance of 1"""
    print("=" * 70)
    print("Task 1b: Strings with Hamming distance of 1")
    print("=" * 70)
    
    for i in range(3):
        # Simple approach: change one character
        base = ''.join(random.choices(string.ascii_lowercase, k=10))
        modified = list(base)
        pos = random.randint(0, len(modified) - 1)
        original_char = modified[pos]
        new_char = random.choice([c for c in string.ascii_lowercase if c != original_char])
        modified[pos] = new_char
        modified_str = ''.join(modified)
        
        h1 = sha256_hash(base)
        h2 = sha256_hash(modified_str)
        
        byte_diff = sum(c1 != c2 for c1, c2 in zip(h1, h2))
        
        print(f"\nPair {i+1}:")
        print(f"String 1: {base}")
        print(f"String 2: {modified_str}")
        print(f"Hash 1: {h1}")
        print(f"Hash 2: {h2}")
        print(f"Hex characters different: {byte_diff}/64 ({byte_diff/64*100:.1f}%)")
        
        # Save to CSV
        save_hamming_to_csv(i+1, base, modified_str, h1, h2, HAMMING_CSV_FILE)
    
    print(f"\n✓ Hamming distance results saved to {HAMMING_CSV_FILE}\n")

def task_1c_with_csv():
    """Task 1c: Find collisions for truncated hashes"""
    print("=" * 70)
    print("Task 1c: Finding collisions for truncated hashes")
    print("=" * 70)
    
    results = []
    
    for bits in range(8, MAX_BITS + 1, 2):
        print(f"\n{'='*70}")
        result = find_collision_safe(bits)
        result['bits'] = bits
        results.append(result)
        
        # Save to CSV immediately
        save_collision_to_csv(bits, result, CSV_OUTPUT_FILE)
    
    # Generate graphs if matplotlib available
    if HAS_MATPLOTLIB:
        try:
            generate_graphs(results)
        except Exception as e:
            print(f"\n⚠️  Error generating graphs: {e}")
    
    print(f"\n{'='*70}")
    print(f"✓ All collision results saved to {CSV_OUTPUT_FILE}")
    print("='*70")
    
    return results

def generate_graphs(results):
    """Generate collision analysis graphs"""
    successful = [r for r in results if r['success']]
    
    if not successful:
        print("\n⚠️  No successful collisions to graph")
        return
    
    bits_list = [r['bits'] for r in successful]
    time_list = [r['time'] for r in successful]
    inputs_list = [r['attempts'] for r in successful]
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
    
    # Graph 1: Time vs Bits
    ax1.plot(bits_list, time_list, 'b-o', linewidth=2, markersize=6)
    ax1.set_xlabel('Digest Size (bits)', fontsize=12)
    ax1.set_ylabel('Time to Find Collision (seconds)', fontsize=12)
    ax1.set_title('Collision Time vs Digest Size', fontsize=14, fontweight='bold')
    ax1.grid(True, alpha=0.3)
    ax1.set_yscale('log')
    
    # Graph 2: Inputs vs Bits
    ax2.plot(bits_list, inputs_list, 'r-o', linewidth=2, markersize=6, label='Actual')
    
    # Theoretical line
    theoretical_bits = range(min(bits_list), max(bits_list) + 1, 2)
    theoretical_inputs = [2 ** (b / 2) for b in theoretical_bits]
    ax2.plot(theoretical_bits, theoretical_inputs, 'g--', 
            linewidth=1.5, alpha=0.7, label='Theoretical (2^(n/2))')
    
    ax2.set_xlabel('Digest Size (bits)', fontsize=12)
    ax2.set_ylabel('Number of Inputs Tried', fontsize=12)
    ax2.set_title('Number of Inputs vs Digest Size', fontsize=14, fontweight='bold')
    ax2.grid(True, alpha=0.3)
    ax2.set_yscale('log')
    ax2.legend()
    
    plt.tight_layout()
    output_path = '/mnt/user-data/outputs/collision_analysis.png'
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"\n✓ Graphs saved to {output_path}")
    plt.close()

def create_summary_csv(results):
    """Create a summary CSV with statistics"""
    summary_file = "task1_summary.csv"
    
    successful = [r for r in results if r['success']]
    
    with open(summary_file, 'w', newline='') as f:
        writer = csv.writer(f)
        
        # Overall statistics
        writer.writerow(['TASK 1 SUMMARY STATISTICS'])
        writer.writerow(['Metric', 'Value'])
        writer.writerow(['Total collisions attempted', len(results)])
        writer.writerow(['Successful collisions', len(successful)])
        writer.writerow(['Failed collisions', len(results) - len(successful)])
        writer.writerow(['Bit range tested', f'{8}-{MAX_BITS}'])
        writer.writerow(['Total time (seconds)', f"{sum(r['time'] for r in results):.2f}"])
        writer.writerow([''])
        
        # Per-bit-size summary
        writer.writerow(['BIT SIZE BREAKDOWN'])
        writer.writerow(['Bits', 'Success', 'Attempts', 'Time (s)', 'Expected Attempts', 'Ratio (Actual/Expected)'])
        
        for r in results:
            if r['success']:
                expected = 2 ** (r['bits'] / 2)
                ratio = r['attempts'] / expected if expected > 0 else 0
                writer.writerow([
                    r['bits'],
                    'Yes',
                    r['attempts'],
                    f"{r['time']:.4f}",
                    f"{expected:.0f}",
                    f"{ratio:.2f}"
                ])
            else:
                writer.writerow([
                    r['bits'],
                    'No',
                    r['attempts'],
                    f"{r['time']:.4f}",
                    'N/A',
                    'N/A'
                ])
    
    print(f"✓ Summary statistics saved to {summary_file}")

def main():
    """Main function"""
    print("\n" + "=" * 70)
    print("CRYPTOGRAPHIC HASH FUNCTIONS - TASK 1")
    print("WITH CSV OUTPUT FOR EASY ANALYSIS")
    print("=" * 70)
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    try:
        # Run all tasks
        task_1a_with_csv()
        task_1b_with_csv()
        results = task_1c_with_csv()
        
        # Create summary
        create_summary_csv(results)
        
        print("\n" + "=" * 70)
        print("TASK 1 COMPLETE!")
        print("=" * 70)
        
        # Print summary
        successful = [r for r in results if r['success']]
        print(f"\nSuccessful collisions: {len(successful)}/{len(results)}")
        
        if successful:
            total_time = sum(r['time'] for r in successful)
            print(f"Total time: {total_time:.2f} seconds ({total_time/60:.1f} minutes)")
        
        print("\nOutput files created:")
        print(f"  1. {CSV_OUTPUT_FILE} - All collision results")
        print(f"  2. {HAMMING_CSV_FILE} - Hamming distance pairs")
        print(f"  3. task1a_sha256_hashes.csv - SHA256 test hashes")
        print(f"  4. task1_summary.csv - Summary statistics")
        if HAS_MATPLOTLIB:
            print(f"  5. collision_analysis.png - Graphs")
        
        print("\n✓ All results saved and ready for your report!")
        print("=" * 70)
        
        return results
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Program interrupted by user")
        print("Partial results have been saved to CSV files")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n✗ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()