"""
Rotate Şifresi (Döndürme)
Key: Döndürme miktarı (örn: 13)
"""
import re


def rotate_encrypt(text: str, key: str = None) -> str:
    """Rotate şifresi ile şifrele"""
    if not key:
        raise ValueError("Rotate şifresi için key (döndürme miktarı) gereklidir")
    
    try:
        rotation = int(key)
    except ValueError:
        raise ValueError("Key bir sayı olmalıdır")
    
    # Şifrele
    encrypted = ""
    for char in text:
        if char.isalpha():
            if char.isupper():
                base = ord('A')
                encrypted += chr((ord(char) - base + rotation) % 26 + base)
            else:
                base = ord('a')
                encrypted += chr((ord(char) - base + rotation) % 26 + base)
        else:
            encrypted += char
    
    return encrypted


def rotate_decrypt(encrypted_text: str, key: str = None) -> str:
    """Rotate şifresi ile çöz"""
    if not key:
        raise ValueError("Rotate şifresi için key (döndürme miktarı) gereklidir")
    
    try:
        rotation = int(key)
    except ValueError:
        raise ValueError("Key bir sayı olmalıdır")
    
    # Çöz (ters yönde döndür)
    rotation = -rotation
    
    decrypted = ""
    for char in encrypted_text:
        if char.isalpha():
            if char.isupper():
                base = ord('A')
                decrypted += chr((ord(char) - base + rotation) % 26 + base)
            else:
                base = ord('a')
                decrypted += chr((ord(char) - base + rotation) % 26 + base)
        else:
            decrypted += char
    
    return decrypted

