"""
GCD Şifresi (En Büyük Ortak Bölen tabanlı)
Key: GCD değeri (örn: 5)
"""
import re
import math


def _gcd(a: int, b: int) -> int:
    """En büyük ortak bölen"""
    while b:
        a, b = b, a % b
    return a


def gcd_encrypt(text: str, key: str = None) -> str:
    """GCD şifresi ile şifrele"""
    if not key:
        raise ValueError("GCD şifresi için key (GCD değeri) gereklidir")
    
    try:
        gcd_value = int(key)
        if gcd_value < 1:
            raise ValueError("GCD değeri pozitif olmalıdır")
    except ValueError:
        raise ValueError("Key bir sayı olmalıdır")
    
    # Şifrele
    encrypted = ""
    for i, char in enumerate(text):
        if char.isalpha():
            char_code = ord(char.upper()) - ord('A')
            # GCD ile şifrele
            encrypted_code = (char_code + gcd_value + i) % 26
            encrypted_char = chr(encrypted_code + ord('A'))
            
            if char.isupper():
                encrypted += encrypted_char
            else:
                encrypted += encrypted_char.lower()
        else:
            encrypted += char
    
    return encrypted


def gcd_decrypt(encrypted_text: str, key: str = None) -> str:
    """GCD şifresi ile çöz"""
    if not key:
        raise ValueError("GCD şifresi için key (GCD değeri) gereklidir")
    
    try:
        gcd_value = int(key)
        if gcd_value < 1:
            raise ValueError("GCD değeri pozitif olmalıdır")
    except ValueError:
        raise ValueError("Key bir sayı olmalıdır")
    
    # Çöz
    decrypted = ""
    for i, char in enumerate(encrypted_text):
        if char.isalpha():
            char_code = ord(char.upper()) - ord('A')
            # GCD ile çöz
            decrypted_code = (char_code - gcd_value - i) % 26
            decrypted_char = chr(decrypted_code + ord('A'))
            
            if char.isupper():
                decrypted += decrypted_char
            else:
                decrypted += decrypted_char.lower()
        else:
            decrypted += char
    
    return decrypted

