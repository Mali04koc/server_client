"""
Affine Şifresi
Key: a,b değerleri (örn: 5,8)
Formül: E(x) = (ax + b) mod 26
"""
import math
import re


def _gcd(a: int, b: int) -> int:
    """En büyük ortak bölen"""
    while b:
        a, b = b, a % b
    return a


def _mod_inverse(a: int, m: int) -> int:
    """Modüler ters"""
    if _gcd(a, m) != 1:
        raise ValueError(f"a={a} ve m={m} aralarında asal değil")
    
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def affine_encrypt(text: str, key: str = None) -> str:
    """Affine şifresi ile şifrele"""
    if not key:
        raise ValueError("Affine şifresi için key (a,b değerleri) gereklidir")
    
    # Key'i parse et
    try:
        parts = key.split(',')
        if len(parts) != 2:
            raise ValueError("Key formatı: a,b (örn: 5,8)")
        a = int(parts[0].strip())
        b = int(parts[1].strip())
    except ValueError as e:
        raise ValueError(f"Key parse hatası: {str(e)}")
    
    # a ve 26 aralarında asal olmalı
    if _gcd(a, 26) != 1:
        raise ValueError(f"a={a} ve 26 aralarında asal olmalıdır")
    
    # Şifrele
    encrypted = ""
    for char in text:
        if char.isalpha():
            if char.isupper():
                x = ord(char) - ord('A')
                encrypted_char = chr((a * x + b) % 26 + ord('A'))
                encrypted += encrypted_char
            else:
                x = ord(char) - ord('a')
                encrypted_char = chr((a * x + b) % 26 + ord('a'))
                encrypted += encrypted_char
        else:
            encrypted += char
    
    return encrypted


def affine_decrypt(encrypted_text: str, key: str = None) -> str:
    """Affine şifresi ile çöz"""
    if not key:
        raise ValueError("Affine şifresi için key (a,b değerleri) gereklidir")
    
    # Key'i parse et
    try:
        parts = key.split(',')
        if len(parts) != 2:
            raise ValueError("Key formatı: a,b (örn: 5,8)")
        a = int(parts[0].strip())
        b = int(parts[1].strip())
    except ValueError as e:
        raise ValueError(f"Key parse hatası: {str(e)}")
    
    # a ve 26 aralarında asal olmalı
    if _gcd(a, 26) != 1:
        raise ValueError(f"a={a} ve 26 aralarında asal olmalıdır")
    
    # a'nın modüler tersini bul
    a_inv = _mod_inverse(a, 26)
    
    # Çöz
    decrypted = ""
    for char in encrypted_text:
        if char.isalpha():
            if char.isupper():
                y = ord(char) - ord('A')
                x = (a_inv * (y - b)) % 26
                decrypted_char = chr(x + ord('A'))
                decrypted += decrypted_char
            else:
                y = ord(char) - ord('a')
                x = (a_inv * (y - b)) % 26
                decrypted_char = chr(x + ord('a'))
                decrypted += decrypted_char
        else:
            decrypted += char
    
    return decrypted

