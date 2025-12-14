"""
RSA Implementation
NO external libraries.
Takes two primes (p, q) as input Key.
"""
import random

def gcd(a, b):
    """Compute the greatest common divisor of a and b"""
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    """Extended Euclidean Algorithm"""
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = extended_gcd(b % a, a)
        return g, x - (b // a) * y, y

def modinv(a, m):
    """Compute modular inverse of a modulo m"""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def is_prime(n):
    """Check if a number is prime (basic check)"""
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0 or n % 3 == 0: return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def generate_keypair(p, q):
    """Generate public and private keys from primes p and q"""
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("Both numbers must be prime.")
    elif p == q:
        raise ValueError("p and q cannot be equal.")
    
    # n = pq
    n = p * q
    
    # phi = (p-1)(q-1)
    phi = (p - 1) * (q - 1)
    
    # Choose an integer e such that e and phi(n) are coprime
    e = 65537
    if gcd(e, phi) != 1:
        # If 65537 is not coprime (rare), find another one
        # Start from 3
        e = 3
        while gcd(e, phi) != 1:
            e += 2
            
    # Determine d such that d*e = 1 (mod phi)
    d = modinv(e, phi)
    
    # Public key (e, n), Private key (d, n)
    return ((e, n), (d, n))

def rsa_encrypt(message, key_str):
    """
    RSA Encrypt
    key_str: "p, q" (comma separated primes)
    Output: Space separated integers (e.g., "123 456 789")
    """
    try:
        parts = [int(x.strip()) for x in key_str.split(',')]
        if len(parts) != 2:
            raise ValueError("Key must be two comma-separated numbers (p,q)")
        p, q = parts
    except ValueError:
        raise ValueError("Invalid key format. Use: p,q (e.g: 61,53)")

    try:
        public_key, private_key = generate_keypair(p, q)
    except ValueError as e:
        raise ValueError(f"Key error: {str(e)}")
        
    e, n = public_key
    
    # Check if modulus is large enough for characters
    # Max char code in standard ASCII is 127, extended 255
    # Unicode chars can be much larger.
    # Simple block encryption: encrypt each character code
    
    encrypted_blocks = []
    for char in message:
        m = ord(char)
        if m >= n:
            raise ValueError(f"Prime numbers are too small for this message character '{char}' (code {m}). n={n}. Choose larger primes.")
        
        c = pow(m, e, n)
        encrypted_blocks.append(str(c))
        
    return " ".join(encrypted_blocks)

def rsa_decrypt(encrypted_msg, key_str):
    """
    RSA Decrypt
    encrypted_msg: Space separated integers
    key_str: "p, q" (comma separated primes)
    """
    try:
        parts = [int(x.strip()) for x in key_str.split(',')]
        if len(parts) != 2:
            raise ValueError("Key must be two comma-separated numbers (p,q)")
        p, q = parts
    except ValueError:
        raise ValueError("Invalid key format. Use: p,q (e.g: 61,53)")

    try:
        public_key, private_key = generate_keypair(p, q)
    except ValueError as e:
        raise ValueError(f"Key error: {str(e)}")
        
    d, n = private_key
    
    try:
        blocks = encrypted_msg.strip().split(' ')
        decrypted_chars = []
        for block in blocks:
            if not block: continue
            c = int(block)
            m = pow(c, d, n)
            decrypted_chars.append(chr(m))
            
        return "".join(decrypted_chars)
    except Exception as e:
         raise ValueError(f"Decryption failed: {str(e)}")
