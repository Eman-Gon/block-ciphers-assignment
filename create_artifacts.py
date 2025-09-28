from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from pathlib import Path
from PIL import Image
import numpy as np
import matplotlib.pyplot as plt

IMAGEDIR = Path("images")
IMAGEDIR.mkdir(exist_ok=True)

BLOCK_SIZE = 16

def aes_ecb_encrypt_full(key: bytes, data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data, BLOCK_SIZE))

def demo_ecb_pattern_leak():
    W, H = 256, 256
    tile = 16
    img = Image.new("L", (W, H))
    for y in range(H):
        for x in range(W):
            val = 255 if ((x // tile) + (y // tile)) % 2 == 0 else 0
            img.putpixel((x, y), val)
    plain_path = IMAGEDIR / "plain_checker.png"
    img.save(plain_path)
    print("Saved", plain_path)

    raw = img.tobytes()
    key = get_random_bytes(16)
    ct = aes_ecb_encrypt_full(key, raw)
    # truncate to original length so image remains same dimensions (visual demo)
    ct_trunc = ct[:len(raw)]
    try:
        enc_img = Image.frombytes("L", (W, H), ct_trunc)
        enc_path = IMAGEDIR / "ecb_encrypted.png"
        enc_img.save(enc_path)
        print("Saved", enc_path)
    except Exception as e:
        print("Failed to create ECB encrypted image:", e)

def demo_avalanche_effect(trials: int = 256):
    key = get_random_bytes(16)
    base = b"A" * 64  # 4 blocks of 16 bytes
    # base ciphertext for comparison
    cipher = AES.new(key, AES.MODE_ECB)
    base_ct = cipher.encrypt(pad(base, BLOCK_SIZE))

    diffs = []
    for _ in range(trials):
        mutated = bytearray(base)
        byte_i = np.random.randint(0, len(mutated))
        bit_i = np.random.randint(0, 8)
        mutated[byte_i] ^= (1 << bit_i)
        mut_ct = cipher.encrypt(pad(bytes(mutated), BLOCK_SIZE))
        # count differing bits (compare only up to length of base_ct)
        x = np.frombuffer(base_ct, dtype=np.uint8) ^ np.frombuffer(mut_ct, dtype=np.uint8)
        bit_diff = np.unpackbits(x).sum()
        diffs.append(bit_diff / (len(base_ct) * 8))

    plt.figure()
    plt.hist(diffs, bins=20)
    plt.title("AES Avalanche Effect (fraction of bits flipped)")
    plt.xlabel("Fraction")
    plt.ylabel("Count")
    out = IMAGEDIR / "avalanche_hist.png"
    plt.savefig(out, bbox_inches="tight")
    plt.close()
    print("Saved", out)

if __name__ == "__main__":
    demo_ecb_pattern_leak()
    demo_avalanche_effect()
