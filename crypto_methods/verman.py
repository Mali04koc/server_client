"""
Verman Şifresi (One-time pad benzeri)
Key: Anahtar (mesajla aynı uzunlukta olmalı)
"""
import re


def verman_encrypt(text: str, key: str = None) -> str:
    """Verman şifresi ile şifrele"""
    if not key:
        raise ValueError("Verman şifresi için key gereklidir")
    
    # Metni temizle
    text_clean = re.sub(r'[^A-Za-z]', '', text)
    if not text_clean:
        return text
    
    # Key'i temizle ve uzat
    key_clean = re.sub(r'[^A-Za-z]', '', key.upper())
    if not key_clean:
        raise ValueError("Key en az bir harf içermelidir")
    
    # Key'i mesaj uzunluğuna kadar uzat
    key_extended = (key_clean * ((len(text_clean) // len(key_clean)) + 1))[:len(text_clean)]
    
    # Şifrele (XOR benzeri)
    encrypted = ""
    original_positions = []
    for i, char in enumerate(text):
        if char.isalpha():
            original_positions.append((i, char.isupper()))
    
    text_upper = text_clean.upper()
    
    for i, char in enumerate(text_upper):
        if char.isalpha():
            char_code = ord(char) - ord('A')
            key_code = ord(key_extended[i]) - ord('A')
            encrypted_code = (char_code + key_code) % 26
            encrypted += chr(encrypted_code + ord('A'))
    
    # Orijinal formatı koru
    result = list(text)
    encrypted_index = 0
    for i, char in enumerate(text):
        if char.isalpha():
            if original_positions[encrypted_index][1]:  # Büyük harf
                result[i] = encrypted[encrypted_index]
            else:  # Küçük harf
                result[i] = encrypted[encrypted_index].lower()
            encrypted_index += 1
    
    return ''.join(result)


def verman_decrypt(encrypted_text: str, key: str = None) -> str:
    """Verman şifresi ile çöz"""
    if not key:
        raise ValueError("Verman şifresi için key gereklidir")
    
    # Metni temizle
    text_clean = re.sub(r'[^A-Za-z]', '', encrypted_text)
    if not text_clean:
        return encrypted_text
    
    # Key'i temizle ve uzat
    key_clean = re.sub(r'[^A-Za-z]', '', key.upper())
    if not key_clean:
        raise ValueError("Key en az bir harf içermelidir")
    
    # Key'i mesaj uzunluğuna kadar uzat
    key_extended = (key_clean * ((len(text_clean) // len(key_clean)) + 1))[:len(text_clean)]
    
    # Çöz
    decrypted = ""
    original_positions = []
    for i, char in enumerate(encrypted_text):
        if char.isalpha():
            original_positions.append((i, char.isupper()))
    
    text_upper = text_clean.upper()
    
    for i, char in enumerate(text_upper):
        if char.isalpha():
            char_code = ord(char) - ord('A')
            key_code = ord(key_extended[i]) - ord('A')
            decrypted_code = (char_code - key_code) % 26
            decrypted += chr(decrypted_code + ord('A'))
    
    # Orijinal formatı koru
    result = list(encrypted_text)
    decrypted_index = 0
    for i, char in enumerate(encrypted_text):
        if char.isalpha():
            if original_positions[decrypted_index][1]:  # Büyük harf
                result[i] = decrypted[decrypted_index]
            else:  # Küçük harf
                result[i] = decrypted[decrypted_index].lower()
            decrypted_index += 1
    
    return ''.join(result)

