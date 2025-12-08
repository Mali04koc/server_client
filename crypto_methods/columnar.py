"""
Columnar Transposition Şifresi
Key: Anahtar kelime (örn: KEYWORD)
"""
import re
import math


def columnar_encrypt(text: str, key: str = None) -> str:
    """Columnar Transposition şifresi ile şifrele"""
    if not key:
        raise ValueError("Columnar Transposition şifresi için key (anahtar kelime) gereklidir")
    
    # Key'i temizle
    key = re.sub(r'[^A-Za-z]', '', key.upper())
    if not key:
        raise ValueError("Key en az bir harf içermelidir")
    
    # Metni temizle
    text_clean = re.sub(r'[^A-Za-z]', '', text.upper())
    if not text_clean:
        return text
    
    # Key'in sıralı indekslerini bul
    key_sorted = sorted(key)
    key_order = []
    used_indices = set()
    
    for char in key:
        for i, sorted_char in enumerate(key_sorted):
            if sorted_char == char and i not in used_indices:
                key_order.append(i)
                used_indices.add(i)
                break
    
    # Matris oluştur
    num_cols = len(key)
    num_rows = math.ceil(len(text_clean) / num_cols)
    
    # Eksik karakterleri X ile doldur
    text_padded = text_clean + 'X' * (num_rows * num_cols - len(text_clean))
    
    # Matrisi doldur
    matrix = []
    for i in range(num_rows):
        row = []
        for j in range(num_cols):
            row.append(text_padded[i * num_cols + j])
        matrix.append(row)
    
    # Key sırasına göre sütunları oku
    encrypted = ""
    for order in key_order:
        for row in matrix:
            encrypted += row[order]
    
    return encrypted


def columnar_decrypt(encrypted_text: str, key: str = None) -> str:
    """Columnar Transposition şifresi ile çöz"""
    if not key:
        raise ValueError("Columnar Transposition şifresi için key (anahtar kelime) gereklidir")
    
    # Key'i temizle
    key = re.sub(r'[^A-Za-z]', '', key.upper())
    if not key:
        raise ValueError("Key en az bir harf içermelidir")
    
    # Metni temizle
    text_clean = re.sub(r'[^A-Za-z]', '', encrypted_text.upper())
    if not text_clean:
        return encrypted_text
    
    # Key'in sıralı indekslerini bul
    key_sorted = sorted(key)
    key_order = []
    used_indices = set()
    
    for char in key:
        for i, sorted_char in enumerate(key_sorted):
            if sorted_char == char and i not in used_indices:
                key_order.append(i)
                used_indices.add(i)
                break
    
    # Matris boyutlarını hesapla
    num_cols = len(key)
    num_rows = math.ceil(len(text_clean) / num_cols)
    
    # Matrisi oluştur
    matrix = [[''] * num_cols for _ in range(num_rows)]
    
    # Şifreli metni key sırasına göre matrise yerleştir
    text_index = 0
    for order in key_order:
        for row in range(num_rows):
            if text_index < len(text_clean):
                matrix[row][order] = text_clean[text_index]
                text_index += 1
    
    # Matrisi satır satır oku
    decrypted = ""
    for row in matrix:
        decrypted += ''.join(row)
    
    # Son X'leri kaldır (eklenmişse)
    decrypted = decrypted.rstrip('X')
    
    return decrypted

