import hashlib
import random
import string
import time
import matplotlib.pyplot as plt

def sha256_hash(input_string):
    """Calculate SHA256 hash of input string and return hex digest"""
    return hashlib.sha256(input_string.encode()).hexdigest()

def truncate_hash(hash_string, bits):
    """Truncate hash to specified number of bits"""
    # Take first (bits / 4) hex characters
    hex_chars = (bits + 3) // 4  # Round up
    truncated_hex = hash_string[:hex_chars]
    
    # Convert to integer and apply bitmask
    hash_int = int(truncated_hex, 16)
    bitmask = (1 << bits) - 1  # Create mask with 'bits' number of 1s
    result = hash_int & bitmask
    
    return result

def hamming_distance(s1, s2):
    """Calculate Hamming distance between two strings"""
    if len(s1) != len(s2):
        return -1
    return sum(c1 != c2 for c1, c2 in zip(s1, s2))

def flip_bit(s, bit_pos):
    """Flip a specific bit in a string"""
    byte_array = bytearray(s.encode())
    byte_index = bit_pos // 8
    bit_index = bit_pos % 8
    
    if byte_index < len(byte_array):
        byte_array[byte_index] ^= (1 << bit_index)
    
    return byte_array.decode('latin-1')

def find_hamming_distance_1():
    """Find two strings with Hamming distance of exactly 1"""
    # Generate random string
    base = ''.join(random.choices(string.ascii_letters, k=10))
    
    # Try flipping each bit
    for bit_pos in range(len(base) * 8):
        try:
            modified = flip_bit(base, bit_pos)
            # Verify hamming distance at byte level
            if sum(c1 != c2 for c1, c2 in zip(base, modified)) == 1:
                return base, modified
        except:
            continue
    
    # Alternative: just change one character
    base = ''.join(random.choices(string.ascii_lowercase, k=10))
    modified = list(base)
    pos = random.randint(0, len(modified) - 1)
    original_char = modified[pos]
    # Change to a different character
    new_char = random.choice([c for c in string.ascii_lowercase if c != original_char])
    modified[pos] = new_char
    
    return base, ''.join(modified)

def find_collision(bits, max_attempts=10000000):
    """
    Find collision using birthday paradox approach.
    Returns: (input1, input2, attempts, elapsed_time)
    """
    seen = {}  # Dictionary to store hash -> input mapping
    start_time = time.time()
    
    for attempt in range(1, max_attempts + 1):
        # Generate random string
        s = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        
        # Calculate truncated hash
        full_hash = sha256_hash(s)
        truncated = truncate_hash(full_hash, bits)
        
        # Check if we've seen this hash before
        if truncated in seen:
            elapsed = time.time() - start_time
            return seen[truncated], s, attempt, elapsed
        
        # Store this hash
        seen[truncated] = s
        
        # Progress indicator for larger bit sizes
        if attempt % 100000 == 0:
            print(f"  Bits={bits}: {attempt:,} attempts so far...")
    
    elapsed = time.time() - start_time
    return None, None, max_attempts, elapsed

def task_1a():
    """Task 1a: Hash arbitrary inputs with SHA256"""
    print("=" * 60)
    print("Task 1a: SHA256 hashes of arbitrary inputs")
    print("=" * 60)
    
    test_inputs = ["Hello, World!", "Python", "Cryptography"]
    
    for input_str in test_inputs:
        hash_result = sha256_hash(input_str)
        print(f"Input: '{input_str}'")
        print(f"SHA256: {hash_result}")
        print()

def task_1b():
    """Task 1b: Hash strings with Hamming distance of 1"""
    print("=" * 60)
    print("Task 1b: Strings with Hamming distance of 1")
    print("=" * 60)
    
    for i in range(3):
        s1, s2 = find_hamming_distance_1()
        h1 = sha256_hash(s1)
        h2 = sha256_hash(s2)
        
        # Calculate byte difference in hashes
        byte_diff = sum(c1 != c2 for c1, c2 in zip(h1, h2))
        
        print(f"\nPair {i+1}:")
        print(f"String 1: {s1}")
        print(f"String 2: {s2}")
        print(f"Hamming distance: {hamming_distance(s1, s2)}")
        print(f"Hash 1: {h1}")
        print(f"Hash 2: {h2}")
        print(f"Hex characters different in hashes: {byte_diff}")

def task_1c():
    """Task 1c: Find collisions for truncated hashes"""
    print("\n" + "=" * 60)
    print("Task 1c: Finding collisions for truncated hashes")
    print("=" * 60)
    
    results = []
    bits_list = []
    time_list = []
    inputs_list = []
    
    print(f"\n{'Bits':<6} {'Input 1':<15} {'Input 2':<15} {'Attempts':<10} {'Time (s)':<10}")
    print("-" * 70)
    
    for bits in range(8, 51, 2):
        print(f"\nFinding collision for {bits}-bit digest...")
        
        # Adjust max attempts based on expected collision count
        expected = 2 ** (bits / 2)
        max_attempts = int(expected * 10)  # 10x expected for safety
        
        s1, s2, attempts, elapsed = find_collision(bits, max_attempts)
        
        if s1 and s2:
            results.append({
                'bits': bits,
                's1': s1,
                's2': s2,
                'attempts': attempts,
                'time': elapsed
            })
            
            bits_list.append(bits)
            time_list.append(elapsed)
            inputs_list.append(attempts)
            
            print(f"{bits:<6} {s1:<15} {s2:<15} {attempts:<10,} {elapsed:<10.4f}")
        else:
            print(f"{bits:<6} TIMEOUT (>{max_attempts:,} attempts in {elapsed:.2f}s)")
    
    # Create graphs
    if bits_list:
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
        
        # Graph 1: Digest Size vs Collision Time
        ax1.plot(bits_list, time_list, 'b-o', linewidth=2, markersize=6)
        ax1.set_xlabel('Digest Size (bits)', fontsize=12)
        ax1.set_ylabel('Time to Find Collision (seconds)', fontsize=12)
        ax1.set_title('Collision Time vs Digest Size', fontsize=14, fontweight='bold')
        ax1.grid(True, alpha=0.3)
        ax1.set_yscale('log')
        
        # Graph 2: Digest Size vs Number of Inputs
        ax2.plot(bits_list, inputs_list, 'r-o', linewidth=2, markersize=6)
        ax2.set_xlabel('Digest Size (bits)', fontsize=12)
        ax2.set_ylabel('Number of Inputs Tried', fontsize=12)
        ax2.set_title('Number of Inputs vs Digest Size', fontsize=14, fontweight='bold')
        ax2.grid(True, alpha=0.3)
        ax2.set_yscale('log')
        
        # Add theoretical line (birthday bound: 2^(n/2))
        theoretical_bits = range(8, max(bits_list) + 1, 2)
        theoretical_inputs = [2 ** (b / 2) for b in theoretical_bits]
        ax2.plot(theoretical_bits, theoretical_inputs, 'g--', 
                linewidth=1.5, alpha=0.7, label='Theoretical (2^(n/2))')
        ax2.legend()
        
        plt.tight_layout()
        plt.savefig('/mnt/user-data/outputs/collision_analysis.png', dpi=300, bbox_inches='tight')
        print(f"\nGraphs saved to collision_analysis.png")
        plt.close()
    
    return results

def main():
    """Main function to run all tasks"""
    print("\n" + "=" * 60)
    print("CRYPTOGRAPHIC HASH FUNCTIONS ASSIGNMENT - TASK 1")
    print("=" * 60)
    
    # Run all tasks
    task_1a()
    task_1b()
    results = task_1c()
    
    print("\n" + "=" * 60)
    print("Task 1 Complete!")
    print("=" * 60)
    
    return results

if __name__ == "__main__":
    main()