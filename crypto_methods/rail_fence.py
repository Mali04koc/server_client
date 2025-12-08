"""
Rail Fence Şifresi (Zigzag)
Key: Ray sayısı (örn: 3)
"""
import re


def rail_fence_encrypt(text: str, key: str = None) -> str:
    """Rail Fence şifresi ile şifrele"""
    if not key:
        raise ValueError("Rail Fence şifresi için key (ray sayısı) gereklidir")
    
    try:
        rails = int(key)
        if rails < 2:
            raise ValueError("Ray sayısı en az 2 olmalıdır")
    except ValueError:
        raise ValueError("Key bir sayı olmalıdır")
    
    # Metni temizle (sadece harfler)
    text_clean = re.sub(r'[^A-Za-z]', '', text)
    if not text_clean:
        return text
    
    # Zigzag pattern oluştur
    pattern = []
    direction = 1
    current_rail = 0
    
    for i in range(len(text_clean)):
        pattern.append((i, current_rail))
        current_rail += direction
        
        if current_rail == rails - 1 or current_rail == 0:
            direction *= -1
    
    # Ray'lere göre grupla
    rails_data = [[] for _ in range(rails)]
    for pos, rail in pattern:
        rails_data[rail].append(text_clean[pos])
    
    # Şifreli metni oluştur
    encrypted = ''.join(''.join(rail) for rail in rails_data)
    
    # Orijinal formatı koru (özel karakterler)
    result = list(text)
    encrypted_index = 0
    for i, char in enumerate(text):
        if char.isalpha():
            result[i] = encrypted[encrypted_index]
            encrypted_index += 1
    
    return ''.join(result)


def rail_fence_decrypt(encrypted_text: str, key: str = None) -> str:
    """Rail Fence şifresi ile çöz"""
    if not key:
        raise ValueError("Rail Fence şifresi için key (ray sayısı) gereklidir")
    
    try:
        rails = int(key)
        if rails < 2:
            raise ValueError("Ray sayısı en az 2 olmalıdır")
    except ValueError:
        raise ValueError("Key bir sayı olmalıdır")
    
    # Metni temizle
    text_clean = re.sub(r'[^A-Za-z]', '', encrypted_text)
    if not text_clean:
        return encrypted_text
    
    # Zigzag pattern oluştur
    pattern = []
    direction = 1
    current_rail = 0
    
    for i in range(len(text_clean)):
        pattern.append((i, current_rail))
        current_rail += direction
        
        if current_rail == rails - 1 or current_rail == 0:
            direction *= -1
    
    # Her ray'de kaç karakter olduğunu hesapla
    rail_counts = [0] * rails
    for _, rail in pattern:
        rail_counts[rail] += 1
    
    # Ray'lere göre karakterleri dağıt
    rail_data = []
    start = 0
    for count in rail_counts:
        rail_data.append(text_clean[start:start+count])
        start += count
    
    # Orijinal sırayı geri oluştur
    rail_indices = [0] * rails
    decrypted = ""
    
    for pos, rail in pattern:
        decrypted += rail_data[rail][rail_indices[rail]]
        rail_indices[rail] += 1
    
    # Orijinal formatı koru
    result = list(encrypted_text)
    decrypted_index = 0
    for i, char in enumerate(encrypted_text):
        if char.isalpha():
            result[i] = decrypted[decrypted_index]
            decrypted_index += 1
    
    return ''.join(result)

