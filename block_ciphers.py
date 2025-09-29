from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16

def pkcs7_pad(data):
    pad_length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    padding = bytes([pad_length]) * pad_length
    return data + padding

def pkcs7_unpad(data):
    pad_length = data[-1]
    return data[:-pad_length]

def encrypt_one_block(key, block):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(block)

def decrypt_one_block(key, block):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(block)

def ecb_encrypt(key, plaintext):
    padded = pkcs7_pad(plaintext)
    result = b""
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i+BLOCK_SIZE]
        encrypted_block = encrypt_one_block(key, block)
        result += encrypted_block
    return result

def ecb_decrypt(key, ciphertext):
    result = b""
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i+BLOCK_SIZE]
        decrypted_block = decrypt_one_block(key, block)
        result += decrypted_block
    return pkcs7_unpad(result)

def cbc_encrypt(key, iv, plaintext):
    padded = pkcs7_pad(plaintext)
    result = b""
    previous = iv
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i+BLOCK_SIZE]
        xored = bytes(a ^ b for a, b in zip(block, previous))
        encrypted = encrypt_one_block(key, xored)
        result += encrypted
        previous = encrypted
    return result

def cbc_decrypt(key, iv, ciphertext):
    result = b""
    previous = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i+BLOCK_SIZE]
        decrypted = decrypt_one_block(key, block)
        plaintext_block = bytes(a ^ b for a, b in zip(decrypted, previous))
        result += plaintext_block
        previous = block
    return pkcs7_unpad(result)

SERVER_KEY = get_random_bytes(16)
SERVER_IV = get_random_bytes(16)

def submit(userdata):
    safe_input = userdata.replace(";", "%3B").replace("=", "%3D")
    full_string = "userid=456;userdata=" + safe_input + ";session-id=31337"
    return cbc_encrypt(SERVER_KEY, SERVER_IV, full_string.encode())

def verify(ciphertext):
    try:
        plaintext = cbc_decrypt(SERVER_KEY, SERVER_IV, ciphertext)
        text = plaintext.decode('utf-8', errors='ignore')
        return ";admin=true;" in text
    except:
        return False

def bitflip_attack():
    prefix = "userid=456;userdata="
    prefix_len = len(prefix)
    padding_needed = BLOCK_SIZE - (prefix_len % BLOCK_SIZE)
    userdata = "A" * (padding_needed + BLOCK_SIZE)
    original_ct = submit(userdata)
    
    print("Before attack: verify() =", verify(original_ct))
    
    ct_list = list(original_ct)
    target_block_num = (prefix_len + padding_needed) // BLOCK_SIZE
    previous_block_start = (target_block_num - 1) * BLOCK_SIZE
    injection = b";admin=true;"
    
    for i in range(len(injection)):
        ct_list[previous_block_start + i] ^= ord('A') ^ injection[i]
    
    modified_ct = bytes(ct_list)
    print("After attack:  verify() =", verify(modified_ct))
    return verify(modified_ct)

def encrypt_image(image_filename):
    with open(image_filename, 'rb') as f:
        data = f.read()
    
    header = data[:54]
    image_data = data[54:]
    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    
    ecb_result = ecb_encrypt(key, image_data)
    with open('ecb_encrypted.bmp', 'wb') as f:
        f.write(header + ecb_result[:len(image_data)])
    
    cbc_result = cbc_encrypt(key, iv, image_data)
    with open('cbc_encrypted.bmp', 'wb') as f:
        f.write(header + cbc_result[:len(image_data)])
    
    print("Saved: ecb_encrypted.bmp and cbc_encrypted.bmp")
if __name__ == "__main__":
    encrypt_image('mustang.bmp')
    
    print("\n" + "=" * 50)
    print("Task 2: CBC Bit-Flipping Attack Demo")
    print("=" * 50)
    success = bitflip_attack()
    if success:
        print("\n✓ Attack worked! Got admin access.")
    else:
        print("\n✗ Attack failed.")