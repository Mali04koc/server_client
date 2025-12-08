"""
Sezar Şifresi (Caesar Cipher)
Key: Kaydırma sayısı (örn: 3)
"""
import re


def caesar_encrypt(text: str, key: str = None) -> str:
    """Sezar şifresi ile şifrele"""
    if not key:
        raise ValueError("Sezar şifresi için key (kaydırma sayısı) gereklidir")
    
    try:
        shift = int(key) % 26
    except ValueError:
        raise ValueError("Key bir sayı olmalıdır")
    
    encrypted = ""
    for char in text:
        if char.isalpha():
            if char.isupper():
                encrypted += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                encrypted += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
        else:
            encrypted += char
    
    return encrypted


def caesar_decrypt(encrypted_text: str, key: str = None) -> str:
    """Sezar şifresi ile çöz"""
    if not key:
        raise ValueError("Sezar şifresi için key (kaydırma sayısı) gereklidir")
    
    try:
        shift = int(key) % 26
    except ValueError:
        raise ValueError("Key bir sayı olmalıdır")
    
    # Çözme için ters yönde kaydır
    shift = -shift % 26
    
    decrypted = ""
    for char in encrypted_text:
        if char.isalpha():
            if char.isupper():
                decrypted += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                decrypted += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
        else:
            decrypted += char
    
    return decrypted
