"""
Standard DES (Data Encryption Standard) Implementation
No external libraries used.
Block Size: 64 bits
Key Size: 64 bits (56 effective)
"""
import base64

# Initial Permutation Table
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# Final Permutation Table (Inverse of IP)
FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# Expansion Table (32 -> 48 bits)
E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

# Permutation Table P (32 -> 32 bits after S-boxes)
P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
]

# S-boxes (Substitution boxes)
S_BOX = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

# Key Schedule Tables
PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

# Number of left shifts per round for key schedule
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

def hex2bin(s):
    """Hex string to binary string"""
    mapping = {
        '0': '0000', '1': '0001', '2': '0010', '3': '0011',
        '4': '0100', '5': '0101', '6': '0110', '7': '0111',
        '8': '1000', '9': '1001', 'A': '1010', 'B': '1011',
        'C': '1100', 'D': '1101', 'E': '1110', 'F': '1111'
    }
    binary = []
    for char in s:
        binary.append(mapping[char])
    return ''.join(binary)

def bin2hex(s):
    """Binary string to hex string"""
    mapping = {
        '0000': '0', '0001': '1', '0010': '2', '0011': '3',
        '0100': '4', '0101': '5', '0110': '6', '0111': '7',
        '1000': '8', '1001': '9', '1010': 'A', '1011': 'B',
        '1100': 'C', '1101': 'D', '1110': 'E', '1111': 'F'
    }
    hex_str = []
    for i in range(0, len(s), 4):
        ch = s[i:i+4]
        hex_str.append(mapping[ch])
    return ''.join(hex_str)

def bin2int(s):
    """Binary string to integer"""
    return int(s, 2)

def int2bin(val, bits):
    """Integer to binary string of specific length"""
    s = bin(val)[2:]
    return s.zfill(bits)

def permute(k, arr, n):
    """General permutation function"""
    permutation = ""
    for i in range(n):
        permutation += k[arr[i] - 1]
    return permutation

def shift_left(k, nth_shifts):
    """Rotate Left Shift"""
    s = ""
    for i in range(nth_shifts):
        for j in range(1, len(k)):
            s += k[j]
        s += k[0]
        k = s
        s = ""
    return k

def xor(a, b):
    """XOR two binary strings"""
    ans = ""
    for i in range(len(a)):
        if a[i] == b[i]:
            ans += "0"
        else:
            ans += "1"
    return ans

def generate_keys(key_hex):
    """Generate 16 subkeys from 64-bit key"""
    # Convert hex key to binary
    # key_hex expects 16 hex chars (64 bits)
    # If using string key, convert to hex first
    
    key_bin = hex2bin(key_hex)
    
    # 1. Parity Drop (PC-1) 64 -> 56 bits
    key_bin = permute(key_bin, PC1, 56)
    
    # Split into Left and Right
    left = key_bin[0:28]
    right = key_bin[28:56]
    
    round_keys = []
    
    for i in range(16):
        # 2. Left Shift
        left = shift_left(left, SHIFTS[i])
        right = shift_left(right, SHIFTS[i])
        
        # Combine
        combined_key = left + right
        
        # 3. Compression (PC-2) 56 -> 48 bits
        round_key = permute(combined_key, PC2, 48)
        round_keys.append(round_key)
        
    return round_keys

def des_round(left, right, round_key):
    """One round of DES"""
    # Expansion 32 -> 48
    right_expanded = permute(right, E, 48)
    
    # XOR with round key
    xor_res = xor(right_expanded, round_key)
    
    # S-Box Substitution
    res = ""
    for i in range(8):
        row_bin = xor_res[i*6] + xor_res[i*6 + 5]
        col_bin = xor_res[i*6 + 1 : i*6 + 5]
        
        row = bin2int(row_bin)
        col = bin2int(col_bin)
        
        val = S_BOX[i][row][col]
        res += int2bin(val, 4)
        
    # Permutation P
    res_permuted = permute(res, P, 32)
    
    # XOR with Left
    new_right = xor(left, res_permuted)
    
    return right, new_right # New Left is Old Right

def process_block(block_bin, round_keys):
    """Encrypt/Decrypt a single 64-bit block"""
    # Initial Permutation
    block_bin = permute(block_bin, IP, 64)
    
    # Split
    left = block_bin[0:32]
    right = block_bin[32:64]
    
    # 16 Rounds
    for i in range(16):
        left, right = des_round(left, right, round_keys[i])
        
    # Swap after last round (Left became Old Right, Right became New Right calculated from Old Left)
    # The standard says: R16 L16
    combined = right + left
    
    # Final Permutation
    ciphertext = permute(combined, FP, 64)
    return ciphertext

def str_to_hex(s):
    """Convert string to hex string"""
    return "".join("{:02X}".format(ord(c)) for c in s)

def hex_to_str(h):
    """Convert hex string to string"""
    return bytes.fromhex(h).decode("utf-8")

def pkcs7_pad(data):
    """PKCS7 Padding"""
    block_size = 8 # 64 bits = 8 bytes
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data):
    """PKCS7 Unpadding"""
    pad_len = data[-1]
    if pad_len > 8 or pad_len == 0:
         return data # Error or no padding
    return data[:-pad_len]

def des_encrypt(plaintext, key):
    """
    DES Encryption
    plaintext: str
    key: str (8 chars)
    """
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes long")
        
    # Prepare Key
    key_bytes = key.encode('utf-8')
    key_hex = "".join("{:02X}".format(b) for b in key_bytes)
    round_keys = generate_keys(key_hex)
    
    # Prepare Data
    data_bytes = plaintext.encode('utf-8')
    data_bytes = pkcs7_pad(data_bytes)
    
    ciphertext_bin_all = ""
    
    # Process Blocks
    for i in range(0, len(data_bytes), 8):
        block = data_bytes[i:i+8]
        block_hex = "".join("{:02X}".format(b) for b in block)
        block_bin = hex2bin(block_hex)
        
        cipher_block_bin = process_block(block_bin, round_keys)
        ciphertext_bin_all += cipher_block_bin
        
    # Convert binary result to bytes then Base64
    # Ensure binary length is multiple of 8
    ciphertext_int = int(ciphertext_bin_all, 2)
    ciphertext_bytes_len = len(ciphertext_bin_all) // 8
    ciphertext_bytes = ciphertext_int.to_bytes(ciphertext_bytes_len, byteorder='big')
    
    return base64.b64encode(ciphertext_bytes).decode('utf-8')

def des_decrypt(ciphertext_b64, key):
    """
    DES Decryption
    ciphertext_b64: str (Base64)
    key: str (8 chars)
    """
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes long")
        
    # Prepare Key
    key_bytes = key.encode('utf-8')
    key_hex = "".join("{:02X}".format(b) for b in key_bytes)
    
    # For decryption, reverse round keys
    round_keys = generate_keys(key_hex)
    round_keys = round_keys[::-1]
    
    try:
        # Decode Base64
        encrypted_bytes = base64.b64decode(ciphertext_b64)
        
        # Process Blocks
        decrypted_bytes = b""
        
        for i in range(0, len(encrypted_bytes), 8):
            block = encrypted_bytes[i:i+8]
            block_hex = "".join("{:02X}".format(b) for b in block)
            block_bin = hex2bin(block_hex)
            
            # Decrypt block
            plain_block_bin = process_block(block_bin, round_keys)
            
            # Convert bin to bytes
            val = int(plain_block_bin, 2)
            decrypted_bytes += val.to_bytes(8, byteorder='big')
            
        # Unpad
        decrypted_bytes = pkcs7_unpad(decrypted_bytes)
        
        return decrypted_bytes.decode('utf-8')
        
    except Exception as e:
        raise ValueError(f"Decryption error: {str(e)}")
