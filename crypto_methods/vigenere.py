"""
Vigenere Şifresi
Key: Anahtar kelime (örn: KEY)
"""
import re


def vigenere_encrypt(text: str, key: str = None) -> str:
    """Vigenere şifresi ile şifrele"""
    if not key:
        raise ValueError("Vigenere şifresi için key (anahtar kelime) gereklidir")
    
    # Key'i temizle ve büyük harfe çevir
    key = re.sub(r'[^A-Za-z]', '', key.upper())
    if not key:
        raise ValueError("Key en az bir harf içermelidir")
    
    # Metni temizle
    text_clean = re.sub(r'[^A-Za-z]', '', text)
    original_positions = []
    for i, char in enumerate(text):
        if char.isalpha():
            original_positions.append((i, char.isupper()))
    
    text_upper = text_clean.upper()
    
    # Şifrele
    encrypted = ""
    key_index = 0
    
    for char in text_upper:
        if char.isalpha():
            key_char = key[key_index % len(key)]
            shift = ord(key_char) - ord('A')
            encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            encrypted += encrypted_char
            key_index += 1
    
    # Orijinal formatı koru (büyük/küçük harf ve özel karakterler)
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


def vigenere_decrypt(encrypted_text: str, key: str = None) -> str:
    """Vigenere şifresi ile çöz"""
    if not key:
        raise ValueError("Vigenere şifresi için key (anahtar kelime) gereklidir")
    
    # Key'i temizle ve büyük harfe çevir
    key = re.sub(r'[^A-Za-z]', '', key.upper())
    if not key:
        raise ValueError("Key en az bir harf içermelidir")
    
    # Metni temizle
    text_clean = re.sub(r'[^A-Za-z]', '', encrypted_text)
    original_positions = []
    for i, char in enumerate(encrypted_text):
        if char.isalpha():
            original_positions.append((i, char.isupper()))
    
    text_upper = text_clean.upper()
    
    # Çöz
    decrypted = ""
    key_index = 0
    
    for char in text_upper:
        if char.isalpha():
            key_char = key[key_index % len(key)]
            shift = ord(key_char) - ord('A')
            decrypted_char = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            decrypted += decrypted_char
            key_index += 1
    
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

