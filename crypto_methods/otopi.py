"""
Otopi Şifresi (Özel anahtar tabanlı)
Key: Özel anahtar kelime
"""
import re


def otopi_encrypt(text: str, key: str = None) -> str:
    """Otopi şifresi ile şifrele"""
    if not key:
        raise ValueError("Otopi şifresi için key (özel anahtar) gereklidir")
    
    # Key'i temizle
    key = re.sub(r'[^A-Za-z]', '', key.upper())
    if not key:
        raise ValueError("Key en az bir harf içermelidir")
    
    # Key'in karakterlerini sıralı indekslere çevir
    key_chars = list(key)
    key_indices = {}
    for i, char in enumerate(key_chars):
        if char not in key_indices:
            key_indices[char] = i
    
    # Metni temizle
    text_clean = re.sub(r'[^A-Za-z]', '', text)
    if not text_clean:
        return text
    
    # Şifrele
    encrypted = ""
    original_positions = []
    for i, char in enumerate(text):
        if char.isalpha():
            original_positions.append((i, char.isupper()))
    
    text_upper = text_clean.upper()
    
    for i, char in enumerate(text_upper):
        if char.isalpha():
            char_code = ord(char) - ord('A')
            # Key'in karakterlerini kullanarak şifrele
            key_char = key[i % len(key)]
            key_code = ord(key_char) - ord('A')
            encrypted_code = (char_code + key_code + i) % 26
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


def otopi_decrypt(encrypted_text: str, key: str = None) -> str:
    """Otopi şifresi ile çöz"""
    if not key:
        raise ValueError("Otopi şifresi için key (özel anahtar) gereklidir")
    
    # Key'i temizle
    key = re.sub(r'[^A-Za-z]', '', key.upper())
    if not key:
        raise ValueError("Key en az bir harf içermelidir")
    
    # Metni temizle
    text_clean = re.sub(r'[^A-Za-z]', '', encrypted_text)
    if not text_clean:
        return encrypted_text
    
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
            # Key'in karakterlerini kullanarak çöz
            key_char = key[i % len(key)]
            key_code = ord(key_char) - ord('A')
            decrypted_code = (char_code - key_code - i) % 26
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

