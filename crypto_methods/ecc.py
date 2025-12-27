import random

# Simülasyon için Güvenli Olmayan Küçük Parametreler (Eğitim Amaçlı)
# Gerçek ECC yerine "Discrete Logarithm Problem" (ElGamal benzeri) kullanıyoruz.
# Bu sayede "Asimetrik" mantık (Public ile şifrele, Private ile çöz) doğru çalışır.

# P (Modulus) - Küçük bir asal sayı seçelim (Demo için)
ECC_P = 2147483647 # Mersenne Prime 2^31 - 1
# G (Generator)
ECC_G = 16807 

def generate_ecc_keypair():
    """ECC (ElGamal Simülasyonu) Anahtar Üretimi"""
    # 1. Private Key (Rastgele bir sayı)
    private_key = random.randint(1000, ECC_P - 2)
    
    # 2. Public Key = G^Private % P
    public_key_val = pow(ECC_G, private_key, ECC_P)
    
    # Hex string formatında döndür (GUI uyumluluğu için)
    return {
        'private': str(private_key),
        'public': str(public_key_val)
    }

def ecc_encrypt(message, public_key_str, **kwargs):
    """
    ECC (ElGamal) Şifreleme
    Girdi: Mesaj, Alıcının Public Key'i
    Çıktı: (C1, C2) çifti (String formatında)
    """
    try:
        if not public_key_str or not public_key_str.isdigit():
             # Hata durumunda basit fallback veya raise
             raise ValueError("Geçersiz Public Key")

        pub_int = int(public_key_str)
        
        # Her mesaj için geçici anahtar 'k' seç
        k = random.randint(1000, ECC_P - 2)
        
        # C1 = G^k % P (Bu, 'Ephemeral Public Key' gibidir)
        c1 = pow(ECC_G, k, ECC_P)
        
        # Shared Secret = Pub^k % P
        shared_secret = pow(pub_int, k, ECC_P)
        
        # Mesajı UTF-8 byte dizisine çevir (Türkçe karakter desteği için)
        msg_bytes = message.encode('utf-8')
        
        encrypted_parts = []
        secret_bytes = str(shared_secret).encode('utf-8')
        
        for i, byte_val in enumerate(msg_bytes):
            # Secret'ın i. byte'ını kullan (döngüsel)
            key_byte = secret_bytes[i % len(secret_bytes)]
            # Byte seviyesinde XOR
            encrypted_parts.append(f"{byte_val ^ key_byte:02x}")
            
        c2_str = "".join(encrypted_parts)
        
        # Format: C1_C2
        return f"{c1}_{c2_str}"

    except Exception as e:
        raise ValueError(f"ECC Encrypt Hatası: {e}")

def ecc_decrypt(ciphertext, private_key_str, **kwargs):
    """
    ECC (ElGamal) Deşifreleme
    Girdi: Ciphertext (C1_C2), Alıcının Private Key'i
    """
    try:
        if "_" not in ciphertext:
            return "[Hata: Geçersiz ECC Mesaj Formatı]"
            
        c1_str, c2_str = ciphertext.split("_", 1)
        c1 = int(c1_str)
        priv = int(private_key_str)
        
        # Shared Secret = C1^Private % P
        # (G^k)^Priv = G^(k*Priv) = (G^Priv)^k = Pub^k  (Aynı secret!)
        shared_secret = pow(c1, priv, ECC_P)
        
        # XOR Maskesi oluştur
        secret_bytes = str(shared_secret).encode('utf-8')
        
        decrypted_bytes = []
        # C2 hex stringini decode et
        for i in range(0, len(c2_str), 2):
            hex_val = c2_str[i:i+2]
            val = int(hex_val, 16)
            
            # XOR işlemi
            byte_index = (i // 2) % len(secret_bytes)
            key_byte = secret_bytes[byte_index]
            
            decrypted_bytes.append(val ^ key_byte)
            
        # Byte listesini tekrar string'e çevir (UTF-8)
        return bytes(decrypted_bytes).decode('utf-8')


    except Exception as e:
        return f"[ECC Decrypt Hatası: {e}]"

