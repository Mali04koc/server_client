"""
Substitution Şifresi (Yer Değiştirme)
Key: 26 karakterlik alfabe permütasyonu (örn: ZYXWVUTSRQPONMLKJIHGFEDCBA)
"""
import string


def substitution_encrypt(text: str, key: str = None) -> str:
    """Substitution şifresi ile şifrele"""
    if not key:
        raise ValueError("Substitution şifresi için key (26 karakterlik alfabe) gereklidir")
    
    # Key'i temizle
    key = key.upper().replace(' ', '')
    if len(key) != 26:
        raise ValueError("Key tam olarak 26 karakter olmalıdır")
    
    # Key'in geçerli olup olmadığını kontrol et
    if set(key) != set(string.ascii_uppercase):
        raise ValueError("Key tüm harfleri içermelidir (A-Z)")
    
    # Şifreleme tablosu oluştur
    encrypt_table = str.maketrans(string.ascii_uppercase, key)
    encrypt_table_lower = str.maketrans(string.ascii_lowercase, key.lower())
    
    # Şifrele
    encrypted = ""
    for char in text:
        if char.isupper():
            encrypted += char.translate(encrypt_table)
        elif char.islower():
            encrypted += char.translate(encrypt_table_lower)
        else:
            encrypted += char
    
    return encrypted


def substitution_decrypt(encrypted_text: str, key: str = None) -> str:
    """Substitution şifresi ile çöz"""
    if not key:
        raise ValueError("Substitution şifresi için key (26 karakterlik alfabe) gereklidir")
    
    # Key'i temizle
    key = key.upper().replace(' ', '')
    if len(key) != 26:
        raise ValueError("Key tam olarak 26 karakter olmalıdır")
    
    # Key'in geçerli olup olmadığını kontrol et
    if set(key) != set(string.ascii_uppercase):
        raise ValueError("Key tüm harfleri içermelidir (A-Z)")
    
    # Çözme tablosu oluştur (ters mapping)
    decrypt_table = str.maketrans(key, string.ascii_uppercase)
    decrypt_table_lower = str.maketrans(key.lower(), string.ascii_lowercase)
    
    # Çöz
    decrypted = ""
    for char in encrypted_text:
        if char.isupper():
            decrypted += char.translate(decrypt_table)
        elif char.islower():
            decrypted += char.translate(decrypt_table_lower)
        else:
            decrypted += char
    
    return decrypted

