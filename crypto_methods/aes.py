"""
Basit AES-128 (ECB) implementasyonu - harici kütüphane yok.
Metin/anahtar UTF-8 alınır, PKCS7 ile pad edilir, çıktı Base64 döner.
ECB yalnızca demo içindir; gerçek güvenlik için IV ve CBC/GCM gerekir.
"""
import base64
from typing import List

# Kütüphane İmplementasyonu için
try:
    from Crypto.Cipher import AES as LibAES
    from Crypto.Util.Padding import pad as lib_pad, unpad as lib_unpad
    HAS_LIB = True
except ImportError:
    HAS_LIB = False


Nb = 4  # blok sütunu (her zaman 4)
Nk = 4  # 4 word = 16 byte key (AES-128)
Nr = 10 # tur sayısı

# S-box ve Ters S-box tablosu
# S-Box ve Ters S-Box tablosu (REFERANS İÇİN SAKLANDI)
# Hocanın isteği üzerine bunları kullanmayıp anlık hesaplayacağız.
# S_BOX = [...]
# INV_S_BOX = [...]

# Matematiksel S-Box Hesaplamaları İçin Yardımcı Fonksiyonlar

def _rotl8(x: int, shift: int) -> int:
    """8-bit sola döndürme"""
    return ((x << shift) | (x >> (8 - shift))) & 0xFF

def _gf_inverse(a: int) -> int:
    """Galois Field (2^8) içinde çarpımsal ters bulma.
    a * x = 1 olan x'i bulur.
    Brute-force yöntemi eğitim amaçlıdır ve byte seviyesinde yeterince hızlıdır.
    """
    if a == 0:
        return 0
    for i in range(1, 256):
        if _gmul(a, i) == 1:
            return i
    return 0

def _sbox_math(byte: int) -> int:
    """Matematiksel S-Box Dönüşümü (Encryption)
    1. GF(2^8)'de tersini al.
    2. Affine Transformation uygula.
    """
    # 1. Ters alma
    inv = _gf_inverse(byte)
    
    # 2. Affine Transformation
    # s = b ^ rotl(b,1) ^ rotl(b,2) ^ rotl(b,3) ^ rotl(b,4) ^ 0x63
    s = inv
    res = s ^ _rotl8(s, 1) ^ _rotl8(s, 2) ^ _rotl8(s, 3) ^ _rotl8(s, 4) ^ 0x63
    return res

def _inv_sbox_math(byte: int) -> int:
    """Matematiksel Ters S-Box Dönüşümü (Decryption)
    1. Ters Affine Transformation uygula.
    2. GF(2^8)'de tersini al.
    """
    # 1. Ters Affine Transformation
    # Formula: rotl(y, 1) ^ rotl(y, 3) ^ rotl(y, 6) ^ 0x05
    y = byte
    res = _rotl8(y, 1) ^ _rotl8(y, 3) ^ _rotl8(y, 6) ^ 0x05
    
    # 2. Ters alma (Tersin tersi kendisidir ama işlem sırası önemli)
    # Decrypt işleminde önce affine tersi alınır, sonra GF tersi alınır.
    return _gf_inverse(res)


RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]

def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1) & 0xFF

def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p

def _sub_bytes(state: List[int]) -> None:
    for i in range(16):
        # state[i] = S_BOX[state[i]]
        state[i] = _sbox_math(state[i])


def _inv_sub_bytes(state: List[int]) -> None:
    for i in range(16):
        # state[i] = INV_S_BOX[state[i]]
        state[i] = _inv_sbox_math(state[i])


def _shift_rows(state: List[int]) -> None:
    state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]

def _inv_shift_rows(state: List[int]) -> None:
    state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]

def _mix_columns(state: List[int]) -> None:
    for c in range(4):
        i = 4*c
        a0,a1,a2,a3 = state[i:i+4]
        state[i]   = _gmul(a0,2) ^ _gmul(a1,3) ^ a2 ^ a3
        state[i+1] = a0 ^ _gmul(a1,2) ^ _gmul(a2,3) ^ a3
        state[i+2] = a0 ^ a1 ^ _gmul(a2,2) ^ _gmul(a3,3)
        state[i+3] = _gmul(a0,3) ^ a1 ^ a2 ^ _gmul(a3,2)

def _inv_mix_columns(state: List[int]) -> None:
    for c in range(4):
        i = 4*c
        a0,a1,a2,a3 = state[i:i+4]
        state[i]   = _gmul(a0,14) ^ _gmul(a1,11) ^ _gmul(a2,13) ^ _gmul(a3,9)
        state[i+1] = _gmul(a0,9)  ^ _gmul(a1,14) ^ _gmul(a2,11) ^ _gmul(a3,13)
        state[i+2] = _gmul(a0,13) ^ _gmul(a1,9)  ^ _gmul(a2,14) ^ _gmul(a3,11)
        state[i+3] = _gmul(a0,11) ^ _gmul(a1,13) ^ _gmul(a2,9)  ^ _gmul(a3,14)

def _add_round_key(state: List[int], round_key: List[int]) -> None:
    for i in range(16):
        state[i] ^= round_key[i]

def _key_expansion(key_bytes: bytes) -> List[List[int]]:
    """AES-128 key schedule -> 11 round keys"""
    if len(key_bytes) != 16:
        raise ValueError("AES key 16 byte (128-bit) olmalı")
    w = [0]*44
    for i in range(Nk):
        w[i] = (key_bytes[4*i] << 24) | (key_bytes[4*i+1] << 16) | (key_bytes[4*i+2] << 8) | key_bytes[4*i+3]
    for i in range(Nk, Nb*(Nr+1)):
        temp = w[i-1]
        if i % Nk == 0:
            temp = _sub_word(_rot_word(temp)) ^ (RCON[(i//Nk)-1] << 24)
        w[i] = w[i-Nk] ^ temp
    round_keys = []
    for r in range(Nr+1):
        rk = []
        for c in range(4):
            word = w[r*4 + c]
            rk.extend([
                (word >> 24) & 0xFF,
                (word >> 16) & 0xFF,
                (word >> 8) & 0xFF,
                word & 0xFF
            ])
        round_keys.append(rk)
    return round_keys

def _rot_word(word: int) -> int:
    return ((word << 8) & 0xFFFFFFFF) | ((word >> 24) & 0xFF)

def _sub_word(word: int) -> int:
    return ((_sbox_math((word >> 24) & 0xFF) << 24) |
            (_sbox_math((word >> 16) & 0xFF) << 16) |
            (_sbox_math((word >> 8) & 0xFF) << 8) |
            _sbox_math(word & 0xFF))

def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len])*pad_len

def _pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Geçersiz pad verisi")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("Geçersiz pad uzunluğu")
    if data[-pad_len:] != bytes([pad_len])*pad_len:
        raise ValueError("Pad doğrulaması başarısız")
    return data[:-pad_len]

def _cipher_block(block: bytes, round_keys: List[List[int]]) -> bytes:
    state = list(block)
    _add_round_key(state, round_keys[0])
    for rnd in range(1, Nr):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[rnd])
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[Nr])
    return bytes(state)

def _inv_cipher_block(block: bytes, round_keys: List[List[int]]) -> bytes:
    state = list(block)
    _add_round_key(state, round_keys[Nr])
    for rnd in range(Nr-1, 0, -1):
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, round_keys[rnd])
        _inv_mix_columns(state)
    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    _add_round_key(state, round_keys[0])
    return bytes(state)

def aes_encrypt(plaintext: str, key: str, use_lib: bool = False) -> str:
    """AES-128 ECB, PKCS7, çıktı Base64 (str)
    use_lib: True ise pycryptodome kullanır, False ise manual implementasyon.
    """
    key_bytes = key.encode("utf-8")
    if len(key_bytes) != 16:
        raise ValueError("AES anahtarı 16 byte (128-bit) olmalı. (örn: 16 karakter)")
        
    if use_lib and HAS_LIB:
        cipher = LibAES.new(key_bytes, LibAES.MODE_ECB)
        ct_bytes = cipher.encrypt(lib_pad(plaintext.encode('utf-8'), 16))
        return base64.b64encode(ct_bytes).decode('utf-8')
        
    # Manual İmplementasyon (Mevcut kod)
    round_keys = _key_expansion(key_bytes)
    data = _pkcs7_pad(plaintext.encode("utf-8"), 16)
    out = b""
    for i in range(0, len(data), 16):
        out += _cipher_block(data[i:i+16], round_keys)
    return base64.b64encode(out).decode("utf-8")

def aes_decrypt(cipher_b64: str, key: str, use_lib: bool = False) -> str:
    """AES-128 ECB, PKCS7, giriş Base64 (str)"""
    key_bytes = key.encode("utf-8")
    if len(key_bytes) != 16:
        raise ValueError("AES anahtarı 16 byte (128-bit) olmalı. (örn: 16 karakter)")
        
    try:
        data = base64.b64decode(cipher_b64.encode("utf-8"))
    except Exception:
        raise ValueError("Geçersiz Base64 şifreli metin")
        
    if use_lib and HAS_LIB:
        cipher = LibAES.new(key_bytes, LibAES.MODE_ECB)
        try:
            pt = lib_unpad(cipher.decrypt(data), 16)
            return pt.decode('utf-8')
        except ValueError:
             raise ValueError("Padding hatası (Lib)")

    # Manual İmplementasyon (Mevcut kod)
    if len(data) % 16 != 0:
        raise ValueError("Şifreli metin blok uzunluğunda değil")
    round_keys = _key_expansion(key_bytes)
    out = b""
    for i in range(0, len(data), 16):
        out += _inv_cipher_block(data[i:i+16], round_keys)
    out = _pkcs7_unpad(out, 16)
    return out.decode("utf-8")


