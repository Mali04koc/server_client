""" 
Hill Şifresi (Matris tabanlı)
Key: NxN matris (örn: 2x2 için: 5,17,8,3 | 3x3 için 9 değer)

Notlar:
- Matris boyutu, key içindeki eleman sayısının karekökü olmalı (4, 9, 16, ...).
- Determinant 26 ile aralarında asal olmalı; aksi halde mod 26'da ters alınamaz.
"""
import re
import math


def _gcd(a: int, b: int) -> int:
    """En büyük ortak bölen"""
    while b:
        a, b = b, a % b
    return a


def _is_square(n: int) -> bool:
    """n mükemmel kare mi?"""
    root = int(math.isqrt(n))
    return root * root == n


def _minor(matrix: list, i: int, j: int) -> list:
    """Kofaktör için minor matrisini döndür"""
    return [row[:j] + row[j + 1 :] for idx, row in enumerate(matrix) if idx != i]


def _determinant_bareiss(matrix: list, mod: int = None) -> int:
    """
    Tam sayılı determinant (Bareiss algoritması).
    Mod verilirse ara sonuçlar mod ile sınırlandırılır.
    """
    n = len(matrix)
    if n == 1:
        return matrix[0][0]
    # Derin kopya
    a = [row[:] for row in matrix]
    denom = 1
    for k in range(n - 1):
        pivot = a[k][k]
        if pivot == 0:
            # Alt satırlardan pivot bul
            for r in range(k + 1, n):
                if a[r][k] != 0:
                    a[k], a[r] = a[r], a[k]
                    pivot = a[k][k]
                    break
            else:
                return 0
        for i in range(k + 1, n):
            for j in range(k + 1, n):
                num = a[k][k] * a[i][j] - a[i][k] * a[k][j]
                if denom != 1:
                    num //= denom
                if mod:
                    num %= mod
                a[i][j] = num
        denom = pivot if pivot != 0 else 1
    det = a[-1][-1]
    if mod:
        det %= mod
    return det


def _adjugate(matrix: list) -> list:
    """Genel NxN adjugate (kofaktörlerin transpozu)"""
    n = len(matrix)
    if n == 1:
        return [[1]]
    cofactors = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            minor = _minor(matrix, i, j)
            # Küçük determinantı hesapla (mod kullanılmaz burada)
            cof_det = _determinant_bareiss(minor)
            sign = -1 if (i + j) % 2 else 1
            cofactors[i][j] = sign * cof_det
    # Transpoz
    adj = [[cofactors[j][i] for j in range(n)] for i in range(n)]
    return adj


def _mod_inverse_matrix(matrix: list, mod: int = 26) -> list:
    """Matrisin modüler tersini bul (NxN)"""
    size = len(matrix)
    det = _determinant_bareiss(matrix, mod) % mod
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
    adj = _adjugate(matrix)
    inv_matrix = []
    for row in adj:
        inv_row = [(det_inv * val) % mod for val in row]
        inv_matrix.append(inv_row)
    return inv_matrix


def _parse_key_to_matrix(key: str) -> list:
    """Key'i NxN tam sayı matrise dönüştür"""
    raw = (key or "").strip()
    if not raw:
        raise ValueError("Key boş olamaz")
    # Yalnızca sayı, boşluk ve virgül olmalı
    if not re.fullmatch(r"[-0-9,\s]+", raw):
        raise ValueError("Key yalnızca tam sayı ve virgül içermelidir (örn: 6,24,1,13,16,10,20,17,15)")
    try:
        parts = [int(x.strip()) for x in raw.split(',') if x.strip() != ""]
    except ValueError:
        raise ValueError("Key parse hatası. Virgülle ayrılmış tam sayılar girin (örn: 6,24,1,13,16,10,20,17,15)")
    if not parts:
        raise ValueError("Key boş olamaz")
    if not _is_square(len(parts)):
        raise ValueError("Key uzunluğu mükemmel kare olmalı (4, 9, 16, ...)")
    size = int(math.isqrt(len(parts)))
    matrix = []
    idx = 0
    for _ in range(size):
        row = parts[idx : idx + size]
        matrix.append(row)
        idx += size
    return matrix


def hill_encrypt(text: str, key: str = None) -> str:
    """Hill şifresi ile şifrele (NxN)"""
    if not key:
        raise ValueError("Hill şifresi için key (matris) gereklidir")
    matrix = _parse_key_to_matrix(key)
    block_size = len(matrix)
    # Metni temizle
    text_clean = re.sub(r'[^A-Za-z]', '', text.upper())
    if not text_clean:
        return text
    # Eksik karakterleri X ile doldur
    while len(text_clean) % block_size != 0:
        text_clean += 'X'
    encrypted = ""
    for i in range(0, len(text_clean), block_size):
        block = text_clean[i : i + block_size]
        vector = [ord(c) - ord('A') for c in block]
        result = []
        for row in matrix:
            val = sum(row[j] * vector[j] for j in range(block_size)) % 26
            result.append(val)
        for val in result:
            encrypted += chr(val + ord('A'))
    return encrypted


def hill_decrypt(encrypted_text: str, key: str = None) -> str:
    """Hill şifresi ile çöz (NxN)"""
    if not key:
        raise ValueError("Hill şifresi için key (matris) gereklidir")
    matrix = _parse_key_to_matrix(key)
    block_size = len(matrix)
    # Matrisin modüler tersini bul
    try:
        inv_matrix = _mod_inverse_matrix(matrix, 26)
    except ValueError as e:
        raise ValueError(f"Matris hatası: {str(e)}")
    # Metni temizle
    text_clean = re.sub(r'[^A-Za-z]', '', encrypted_text.upper())
    if not text_clean:
        return encrypted_text
    decrypted = ""
    for i in range(0, len(text_clean), block_size):
        block = text_clean[i : i + block_size]
        vector = [ord(c) - ord('A') for c in block]
        result = []
        for row in inv_matrix:
            val = sum(row[j] * vector[j] for j in range(block_size)) % 26
            result.append(val)
        for val in result:
            decrypted += chr(val + ord('A'))
    decrypted = decrypted.rstrip('X')
    return decrypted

