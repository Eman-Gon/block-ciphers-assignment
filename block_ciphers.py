# block_ciphers.py
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import math
from pathlib import Path

# --- config: image dir used earlier in your repo ---
IMAGEDIR = Path("images")
IMAGEDIR.mkdir(exist_ok=True)

BLOCK_SIZE = 16

# --- PKCS#7 padding ---
def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if len(data) == 0 or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Bad padding bytes")
    return data[:-pad_len]

# --- AES single-block ECB primitives (we use AES.MODE_ECB to get block encrypt/decrypt) ---
def aes_block_encrypt(key: bytes, block: bytes) -> bytes:
    assert len(block) == BLOCK_SIZE
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(block)

def aes_block_decrypt(key: bytes, block: bytes) -> bytes:
    assert len(block) == BLOCK_SIZE
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(block)

# --- Manual AES-CBC implementation using single-block ECB primitive ---
def aes_cbc_encrypt_manual(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    plaintext_p = pkcs7_pad(plaintext, BLOCK_SIZE)
    ct_blocks = []
    prev = iv
    for i in range(0, len(plaintext_p), BLOCK_SIZE):
        block = plaintext_p[i:i+BLOCK_SIZE]
        # XOR with prev
        xored = bytes(a ^ b for a, b in zip(block, prev))
        c = aes_block_encrypt(key, xored)
        ct_blocks.append(c)
        prev = c
    return b"".join(ct_blocks)

def aes_cbc_decrypt_manual(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext not full blocks")
    plain_blocks = []
    prev = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        c = ciphertext[i:i+BLOCK_SIZE]
        x = aes_block_decrypt(key, c)
        p = bytes(a ^ b for a, b in zip(x, prev))
        plain_blocks.append(p)
        prev = c
    full = b"".join(plain_blocks)
    return pkcs7_unpad(full, BLOCK_SIZE)

# -----------------------------
# Task 2: submit() and verify()
# -----------------------------
# We will generate a single key and IV and keep them global for the program run.
GLOBAL_KEY = get_random_bytes(16)
GLOBAL_IV  = get_random_bytes(16)

import urllib.parse

def submit(userdata: str) -> bytes:
    """
    Build: userid=456;userdata=<urlencoded userdata>;session-id=31337
    PKCS#7 pad and AES-CBC encrypt using the global key/iv.
    Returns raw ciphertext bytes (no header).
    """
    # URL-encode any ';' or '=' characters in the user-controlled input
    # The spec says "URL encode any ';' and '='" — we'll url-quote everything,
    # but at least ensure those are encoded.
    safe_ud = userdata.replace(";", "%3B").replace("=", "%3D")
    full = "userid=456;userdata=" + safe_ud + ";session-id=31337"
    plaintext = full.encode("utf-8")
    ct = aes_cbc_encrypt_manual(GLOBAL_KEY, GLOBAL_IV, plaintext)
    return ct

def verify(ciphertext: bytes) -> bool:
    """
    Decrypts ciphertext with the global key/iv and returns True if the
    plaintext contains the substring ';admin=true;'
    """
    try:
        pt = aes_cbc_decrypt_manual(GLOBAL_KEY, GLOBAL_IV, ciphertext)
    except Exception as e:
        print("Decryption/padding error in verify():", e)
        return False
    try:
        s = pt.decode("utf-8", errors="ignore")
    except:
        s = str(pt)
    # Look for ;admin=true;
    return ";admin=true;" in s

# -----------------------------
# Bit-flipping exploit function
# -----------------------------
def cbc_bitflip_attack_make_admin(ciphertext: bytes, prefix_len: int, desired: bytes) -> bytes:
    """
    Given a ciphertext produced by submit(), where 'desired' is the byte string we want
    to appear at the start of some block, and prefix_len is the number of plaintext bytes
    before the user-controlled block (i.e., length of "userid=456;userdata="),
    produce a modified ciphertext by flipping bits in the previous block.

    Strategy:
      - Compute pad_len so that our chosen userdata contains a full block of 'A's
        that will be aligned to a block boundary (so we can flip them to desired).
      - The caller should have chosen userdata accordingly (see exploit demo).
    """
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("ciphertext length not multiple of block size")

    blocks = [bytearray(ciphertext[i:i+BLOCK_SIZE]) for i in range(0, len(ciphertext), BLOCK_SIZE)]

    # find the block index where the user-controlled "target" block starts
    target_block_index = (prefix_len + 0) // BLOCK_SIZE  # integer division
    # in our demo we'll create userdata so that the block we want to edit is block (target_block_index + 1)
    target_block_index += 1
    prev_index = target_block_index - 1
    if prev_index < 0 or target_block_index >= len(blocks):
        raise IndexError("target block indices out of range; check prefix_len and ciphertext length")

    prev_block = blocks[prev_index]
    # We assume the plaintext of the target block currently contains known bytes (e.g., 'A'*16).
    # Let orig_byte = ord('A') (or whatever known filler was). We'll flip prev_block so that after decryption,
    # target_plain[i] = orig_plain[i] ^ prev_block[i] ^ new_prev_block[i] => we need new_prev_block[i] = prev_block[i] ^ orig ^ desired
    # Therefore delta = orig_byte ^ desired_byte; set prev_block[i] ^= delta
    # For generality, we assume orig is 0x41 ('A') for the positions we change.

    orig_fill = ord('A')
    for i in range(len(desired)):
        d = orig_fill ^ desired[i]
        prev_block[i] ^= d

    # write modified previous block back
    blocks[prev_index] = prev_block
    return b"".join(bytes(b) for b in blocks)

# -----------------------------
# Demo: show exploit end-to-end
# -----------------------------
def demo_cbc_bitflip_attack():
    # prefix length exactly as in submit() before userdata: len("userid=456;userdata=")
    prefix = "userid=456;userdata="
    prefix_len = len(prefix.encode("utf-8"))  # should be 20 per spec

    # To align the block containing our controllable bytes at a block boundary,
    # supply userdata that pads the remainder of the current block with 'A' and then
    # includes an entire block of 'A's which we will flip.
    pad_len = (BLOCK_SIZE - (prefix_len % BLOCK_SIZE)) % BLOCK_SIZE
    # ensure pad_len > 0 so we can align the next block (if pad_len == 0, we still add a full block)
    if pad_len == 0:
        pad_len = BLOCK_SIZE

    userdata = "A" * (pad_len + BLOCK_SIZE)  # first partial fill, then a full block of 'A's we can flip
    print(f"Using userdata length {len(userdata)} (pad_len {pad_len}) to align a full block for flipping.")

    ct = submit(userdata)
    print(f"Original verify(ct) => {verify(ct)} (expected False)")

    # our target string we want to appear at the start of the second block of 'A's:
    target = b";admin=true;"  # 12 bytes; remaining bytes in the block remain whatever
    new_ct = cbc_bitflip_attack_make_admin(ct, prefix_len, target)

    ok = verify(new_ct)
    print(f"After bitflip verify(new_ct) => {ok}")
    if ok:
        print("SUCCESS: verify() returned True (we injected ;admin=true;)")
    else:
        print("Failed to make verify() true. Make sure padding and alignment are correct.")

# Run demo if executed directly
if __name__ == "__main__":
    print("Running CBC bitflip demo (Task 2 exploit).")
    demo_cbc_bitflip_attack()
