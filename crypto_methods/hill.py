"""
Hill Şifresi (Matris tabanlı)
Key: 2x2 veya 3x3 matris (örn: 2x2 için: 5,17,8,3)
"""
import re
import math


def _gcd(a: int, b: int) -> int:
    """En büyük ortak bölen"""
    while b:
        a, b = b, a % b
    return a


def _determinant_2x2(matrix: list) -> int:
    """2x2 matris determinantı"""
    return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]


def _determinant_3x3(matrix: list) -> int:
    """3x3 matris determinantı"""
    a, b, c = matrix[0]
    d, e, f = matrix[1]
    g, h, i = matrix[2]
    return a*(e*i - f*h) - b*(d*i - f*g) + c*(d*h - e*g)


def _adjoint_2x2(matrix: list) -> list:
    """2x2 matris adjoint"""
    return [[matrix[1][1], -matrix[0][1]],
            [-matrix[1][0], matrix[0][0]]]


def _adjoint_3x3(matrix: list) -> list:
    """3x3 matris adjoint"""
    a, b, c = matrix[0]
    d, e, f = matrix[1]
    g, h, i = matrix[2]
    
    return [
        [e*i - f*h, -(b*i - c*h), b*f - c*e],
        [-(d*i - f*g), a*i - c*g, -(a*f - c*d)],
        [d*h - e*g, -(a*h - b*g), a*e - b*d]
    ]


def _mod_inverse_matrix(matrix: list, mod: int = 26) -> list:
    """Matrisin modüler tersini bul"""
    size = len(matrix)
    
    # Determinant hesapla
    if size == 2:
        det = _determinant_2x2(matrix) % mod
    elif size == 3:
        det = _determinant_3x3(matrix) % mod
    else:
        raise ValueError("Sadece 2x2 ve 3x3 matrisler destekleniyor")
    
    # Determinant ve mod aralarında asal olmalı
    if _gcd(det, mod) != 1:
        raise ValueError("Matris determinantı mod ile aralarında asal değil")
    
    # Determinantın modüler tersi
    det_inv = None
    for x in range(1, mod):
        if (det * x) % mod == 1:
            det_inv = x
            break
    
    if det_inv is None:
        raise ValueError("Determinantın modüler tersi bulunamadı")
    
    # Adjoint matris
    if size == 2:
        adj = _adjoint_2x2(matrix)
    else:
        adj = _adjoint_3x3(matrix)
    
    # Modüler ters
    inv_matrix = []
    for row in adj:
        inv_row = [(det_inv * val) % mod for val in row]
        inv_matrix.append(inv_row)
    
    return inv_matrix


def hill_encrypt(text: str, key: str = None) -> str:
    """Hill şifresi ile şifrele"""
    if not key:
        raise ValueError("Hill şifresi için key (matris) gereklidir")
    
    # Key'i parse et
    try:
        parts = [int(x.strip()) for x in key.split(',')]
        if len(parts) not in [4, 9]:
            raise ValueError("Key 2x2 (4 değer) veya 3x3 (9 değer) matris olmalıdır")
        
        if len(parts) == 4:
            # 2x2 matris
            matrix = np.array([[parts[0], parts[1]], 
                              [parts[2], parts[3]]], dtype=int)
            block_size = 2
        else:
            # 3x3 matris
            matrix = np.array([[parts[0], parts[1], parts[2]],
                              [parts[3], parts[4], parts[5]],
                              [parts[6], parts[7], parts[8]]], dtype=int)
            block_size = 3
    except ValueError as e:
        raise ValueError(f"Key parse hatası: {str(e)}")
    
    # Metni temizle
    text_clean = re.sub(r'[^A-Za-z]', '', text.upper())
    if not text_clean:
        return text
    
    # Eksik karakterleri X ile doldur
    while len(text_clean) % block_size != 0:
        text_clean += 'X'
    
    # Şifrele
    encrypted = ""
    for i in range(0, len(text_clean), block_size):
        block = text_clean[i:i+block_size]
        vector = [ord(c) - ord('A') for c in block]
        
        # Matris çarpımı
        result = []
        for row in matrix:
            val = sum(row[j] * vector[j] for j in range(block_size)) % 26
            result.append(val)
        
        # Karakterlere çevir
        for val in result:
            encrypted += chr(val + ord('A'))
    
    return encrypted


def hill_decrypt(encrypted_text: str, key: str = None) -> str:
    """Hill şifresi ile çöz"""
    if not key:
        raise ValueError("Hill şifresi için key (matris) gereklidir")
    
    # Key'i parse et
    try:
        parts = [int(x.strip()) for x in key.split(',')]
        if len(parts) not in [4, 9]:
            raise ValueError("Key 2x2 (4 değer) veya 3x3 (9 değer) matris olmalıdır")
        
        if len(parts) == 4:
            # 2x2 matris
            matrix = [[parts[0], parts[1]], 
                     [parts[2], parts[3]]]
            block_size = 2
        else:
            # 3x3 matris
            matrix = [[parts[0], parts[1], parts[2]],
                     [parts[3], parts[4], parts[5]],
                     [parts[6], parts[7], parts[8]]]
            block_size = 3
    except ValueError as e:
        raise ValueError(f"Key parse hatası: {str(e)}")
    
    # Matrisin modüler tersini bul
    try:
        inv_matrix = _mod_inverse_matrix(matrix, 26)
    except ValueError as e:
        raise ValueError(f"Matris hatası: {str(e)}")
    
    # Metni temizle
    text_clean = re.sub(r'[^A-Za-z]', '', encrypted_text.upper())
    if not text_clean:
        return encrypted_text
    
    # Çöz
    decrypted = ""
    for i in range(0, len(text_clean), block_size):
        block = text_clean[i:i+block_size]
        vector = [ord(c) - ord('A') for c in block]
        
        # Ters matris çarpımı
        result = []
        for row in inv_matrix:
            val = sum(row[j] * vector[j] for j in range(block_size)) % 26
            result.append(val)
        
        # Karakterlere çevir
        for val in result:
            decrypted += chr(val + ord('A'))
    
    # Son X'leri kaldır (eklenmişse)
    decrypted = decrypted.rstrip('X')
    
    return decrypted

