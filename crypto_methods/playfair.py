"""
Playfair Şifresi
Key: Anahtar kelime (örn: MONARCHY)
"""
import re


def _create_playfair_matrix(key: str) -> list:
    """Playfair matrisi oluştur"""
    # Key'i temizle ve J'yi I ile değiştir
    key = key.upper().replace('J', 'I')
    key = re.sub(r'[^A-Z]', '', key)
    
    # Tekrarları kaldır
    seen = set()
    key_clean = ""
    for char in key:
        if char not in seen:
            key_clean += char
            seen.add(char)
    
    # Alfabeyi oluştur (J hariç)
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    
    # Matrisi doldur
    matrix = []
    used_chars = set(key_clean)
    
    # Key karakterlerini ekle
    for char in key_clean:
        if char not in matrix:
            matrix.append(char)
    
    # Kalan karakterleri ekle
    for char in alphabet:
        if char not in used_chars:
            matrix.append(char)
    
    # 5x5 matris oluştur
    return [matrix[i:i+5] for i in range(0, 25, 5)]


def _find_position(matrix: list, char: str) -> tuple:
    """Karakterin matristeki pozisyonunu bul"""
    for i, row in enumerate(matrix):
        if char in row:
            return (i, row.index(char))
    return None


def _playfair_encrypt_pair(matrix: list, pair: str) -> str:
    """Bir çift karakteri şifrele"""
    pos1 = _find_position(matrix, pair[0])
    pos2 = _find_position(matrix, pair[1])
    
    if pos1 is None or pos2 is None:
        return pair
    
    row1, col1 = pos1
    row2, col2 = pos2
    
    if row1 == row2:
        # Aynı satırda
        return matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
    elif col1 == col2:
        # Aynı sütunda
        return matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
    else:
        # Dikdörtgen
        return matrix[row1][col2] + matrix[row2][col1]


def playfair_encrypt(text: str, key: str = None) -> str:
    """Playfair şifresi ile şifrele"""
    if not key:
        raise ValueError("Playfair şifresi için key (anahtar kelime) gereklidir")
    
    # Metni temizle
    text = re.sub(r'[^A-Za-z]', '', text.upper())
    text = text.replace('J', 'I')
    
    # Tek karakter ekle
    if len(text) % 2 == 1:
        text += 'X'
    
    # Çiftler oluştur
    pairs = [text[i:i+2] for i in range(0, len(text), 2)]
    
    # Aynı karakter çiftlerini ayır
    processed_pairs = []
    for pair in pairs:
        if pair[0] == pair[1]:
            processed_pairs.append(pair[0] + 'X')
            processed_pairs.append(pair[1] + 'X')
        else:
            processed_pairs.append(pair)
    
    # Matris oluştur
    matrix = _create_playfair_matrix(key)
    
    # Şifrele
    encrypted = ""
    for pair in processed_pairs:
        encrypted += _playfair_encrypt_pair(matrix, pair)
    
    return encrypted


def _playfair_decrypt_pair(matrix: list, pair: str) -> str:
    """Bir çift karakteri çöz"""
    pos1 = _find_position(matrix, pair[0])
    pos2 = _find_position(matrix, pair[1])
    
    if pos1 is None or pos2 is None:
        return pair
    
    row1, col1 = pos1
    row2, col2 = pos2
    
    if row1 == row2:
        # Aynı satırda
        return matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
    elif col1 == col2:
        # Aynı sütunda
        return matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
    else:
        # Dikdörtgen
        return matrix[row1][col2] + matrix[row2][col1]


def playfair_decrypt(encrypted_text: str, key: str = None) -> str:
    """Playfair şifresi ile çöz"""
    if not key:
        raise ValueError("Playfair şifresi için key (anahtar kelime) gereklidir")
    
    # Metni temizle
    encrypted_text = re.sub(r'[^A-Z]', '', encrypted_text.upper())
    
    # Çiftler oluştur
    pairs = [encrypted_text[i:i+2] for i in range(0, len(encrypted_text), 2)]
    
    # Matris oluştur
    matrix = _create_playfair_matrix(key)
    
    # Çöz
    decrypted = ""
    for pair in pairs:
        decrypted += _playfair_decrypt_pair(matrix, pair)
    
    # Son X'i kaldır (eklenmişse)
    if len(decrypted) > 0 and decrypted[-1] == 'X':
        decrypted = decrypted[:-1]
    
    return decrypted

