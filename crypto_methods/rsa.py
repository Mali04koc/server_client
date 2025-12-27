from random import randint

def generate_prime_candidate(length):
    p = randint(2**(length-1), 2**length - 1)
    p |= (1 << (length - 1)) | 1
    return p

def is_prime(n, k=5):
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime_number(length=8):
    p = 4
    while not is_prime(p):
        p = generate_prime_candidate(length)
    return p

def generate_keypair(p=None, q=None):
    """Basit RSA Anahtar Üretimi"""
    # Rastgele asal üretimi (Eğer parametre verilmediyse)
    if not p: p = generate_prime_number(8)
    if not q: q = generate_prime_number(8)
    while p == q: 
        q = generate_prime_number(8)
    
    # 1. Modül n hesapla
    n = p * q
    
    # 2. Totient hesapla
    phi = (p - 1) * (q - 1)
    
    # 3. Public exponent e seç (genelde 65537)
    e = 65537
    
    # 4. Private exponent d hesapla (d * e = 1 mod phi)
    # Genişletilmiş Öklid (Extended Euclidean)
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        else:
            gcd, x, y = extended_gcd(b % a, a)
            return gcd, y - (b // a) * x, x

    gcd, x, y = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    else:
        d = x % phi
        
    return ((e, n), (d, n))

import ast

def parse_rsa_key(key_str, key_type='public'):
    """String anahtarı parse et: Public: (e, n), Private: (d, n)"""
    try:
        # Eğer direkt tuple geldiyse (iç kullanım)
        if isinstance(key_str, tuple):
            return key_str
            
        # String temizliği
        key_str = str(key_str).strip()
        
        # Format: "Public: (e, n), Private: (d, n)"
        if key_type == 'public':
            if "Public:" in key_str:
                start = key_str.find("Public:") + len("Public:")
                end = key_str.find("Private:") if "Private:" in key_str else len(key_str)
                tuple_str = key_str[start:end].strip()
                # Sondaki virgülü temizle
                if tuple_str.endswith(','): tuple_str = tuple_str[:-1]
                return ast.literal_eval(tuple_str)
            elif key_str.startswith("(") and "," in key_str:
                 return ast.literal_eval(key_str)
                 
        elif key_type == 'private':
            if "Private:" in key_str:
                start = key_str.find("Private:") + len("Private:")
                tuple_str = key_str[start:].strip()
                return ast.literal_eval(tuple_str)
            elif key_str.startswith("(") and "," in key_str:
                 return ast.literal_eval(key_str)

    except Exception as e:
        raise ValueError(f"RSA Anahtar formatı hatalı: {e}")
    
    raise ValueError(f"Uygun {key_type} anahtar bulunamadı.")

def rsa_encrypt(msg, public_key_str):
    try:
        e, n = parse_rsa_key(public_key_str, 'public')
        # Mesajı int'e çevir (basit ascii)
        # Karakter bazlı şifreleme (Basit yöntem)
        cipher = [pow(ord(char), e, n) for char in msg]
        # Listeyi string olarak döndür (virgülle ayrılmış)
        return str(cipher)
    except Exception as e:
        raise ValueError(f"RSA Encrypt Hatası: {e}")

def rsa_decrypt(cipher_str, private_key_str):
    try:
        d, n = parse_rsa_key(private_key_str, 'private')
        # cipher_str string listesi "[123, 456, ...]" formatında gelir
        cipher = ast.literal_eval(cipher_str)
        
        plain = [chr(pow(char, d, n)) for char in cipher]
        return ''.join(plain)
    except Exception as e:
         # Belki liste değil direkt int listesidir
         if isinstance(cipher_str, list):
             plain = [chr(pow(char, d, n)) for char in cipher_str]
             return ''.join(plain)
         raise ValueError(f"RSA Decrypt Hatası: {e}")
