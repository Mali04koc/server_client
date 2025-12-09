"""
Şifreleme Yöntemleri Paketi
Her şifreleme yöntemi için encrypt ve decrypt fonksiyonları
"""
from .caesar import caesar_encrypt, caesar_decrypt
from .playfair import playfair_encrypt, playfair_decrypt
from .vigenere import vigenere_encrypt, vigenere_decrypt
from .substitution import substitution_encrypt, substitution_decrypt
from .affine import affine_encrypt, affine_decrypt
from .rail_fence import rail_fence_encrypt, rail_fence_decrypt
from .rotate import rotate_encrypt, rotate_decrypt
from .columnar import columnar_encrypt, columnar_decrypt
from .hill import hill_encrypt, hill_decrypt
from .gcd import gcd_encrypt, gcd_decrypt
from .verman import verman_encrypt, verman_decrypt
from .otopi import otopi_encrypt, otopi_decrypt
from .aes import aes_encrypt, aes_decrypt

# Şifreleme yöntemleri mapping
ENCRYPT_FUNCTIONS = {
    "Sezar Şifresi": caesar_encrypt,
    "Playfair Şifresi": playfair_encrypt,
    "Vigenere Şifresi": vigenere_encrypt,
    "Substitution Şifresi": substitution_encrypt,
    "Affine Şifresi": affine_encrypt,
    "Rail Fence Şifresi": rail_fence_encrypt,
    "Rotate Şifresi": rotate_encrypt,
    "Columnar Transposition": columnar_encrypt,
    "Hill Şifresi": hill_encrypt,
    "GCD Şifresi": gcd_encrypt,
    "Verman Şifresi": verman_encrypt,
    "Otopi Şifresi": otopi_encrypt,
    "AES": aes_encrypt,
}

DECRYPT_FUNCTIONS = {
    "Sezar Şifresi": caesar_decrypt,
    "Playfair Şifresi": playfair_decrypt,
    "Vigenere Şifresi": vigenere_decrypt,
    "Substitution Şifresi": substitution_decrypt,
    "Affine Şifresi": affine_decrypt,
    "Rail Fence Şifresi": rail_fence_decrypt,
    "Rotate Şifresi": rotate_decrypt,
    "Columnar Transposition": columnar_decrypt,
    "Hill Şifresi": hill_decrypt,
    "GCD Şifresi": gcd_decrypt,
    "Verman Şifresi": verman_decrypt,
    "Otopi Şifresi": otopi_decrypt,
    "AES": aes_decrypt,
}

def encrypt_message(message: str, method: str, key: str = None) -> str:
    """Mesajı şifrele"""
    if method not in ENCRYPT_FUNCTIONS:
        return message  # Bilinmeyen yöntem için orijinal mesajı döndür
    
    encrypt_func = ENCRYPT_FUNCTIONS[method]
    try:
        return encrypt_func(message, key)
    except Exception as e:
        raise ValueError(f"Şifreleme hatası ({method}): {str(e)}")

def decrypt_message(encrypted_message: str, method: str, key: str = None) -> str:
    """Şifreli mesajı çöz"""
    if method not in DECRYPT_FUNCTIONS:
        return encrypted_message  # Bilinmeyen yöntem için orijinal mesajı döndür
    
    decrypt_func = DECRYPT_FUNCTIONS[method]
    try:
        return decrypt_func(encrypted_message, key)
    except Exception as e:
        raise ValueError(f"Şifre çözme hatası ({method}): {str(e)}")

__all__ = [
    'encrypt_message',
    'decrypt_message',
    'ENCRYPT_FUNCTIONS',
    'DECRYPT_FUNCTIONS',
]
