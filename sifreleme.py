# ============================================
# 1. KLASİK KRİPTO ŞİFRELEME
# ============================================

# a. Sezar Şifreleme (Caesar Cipher)
def sezar_sifrele(metin, kaydirma):
    sonuc = ""
    for harf in metin:
        if harf.isalpha():
            # Büyük/küçük harf kontrolü
            baslangic = ord('A') if harf.isupper() else ord('a')
            yeni_harf = chr((ord(harf) - baslangic + kaydirma) % 26 + baslangic)
            sonuc += yeni_harf
        else:
            sonuc += harf
    return sonuc

def sezar_coz(metin, kaydirma):
    return sezar_sifrele(metin, -kaydirma)

print("=== SEZAR ŞİFRELEME ===")
metin = "MERHABA DUNYA"
kaydirma = 3
sifreli = sezar_sifrele(metin, kaydirma)
print(f"Orijinal: {metin}")
print(f"Şifreli: {sifreli}")
print(f"Çözülmüş: {sezar_coz(sifreli, kaydirma)}\n")


# b. Vigenere Cipher
def vigenere_sifrele(metin, anahtar):
    sonuc = ""
    anahtar_index = 0
    anahtar = anahtar.upper()
    
    for harf in metin:
        if harf.isalpha():
            baslangic = ord('A') if harf.isupper() else ord('a')
            kaydirma = ord(anahtar[anahtar_index % len(anahtar)]) - ord('A')
            yeni_harf = chr((ord(harf.upper()) - ord('A') + kaydirma) % 26 + ord('A'))
            sonuc += yeni_harf if harf.isupper() else yeni_harf.lower()
            anahtar_index += 1
        else:
            sonuc += harf
    return sonuc

def vigenere_coz(metin, anahtar):
    sonuc = ""
    anahtar_index = 0
    anahtar = anahtar.upper()
    
    for harf in metin:
        if harf.isalpha():
            baslangic = ord('A') if harf.isupper() else ord('a')
            kaydirma = ord(anahtar[anahtar_index % len(anahtar)]) - ord('A')
            yeni_harf = chr((ord(harf.upper()) - ord('A') - kaydirma) % 26 + ord('A'))
            sonuc += yeni_harf if harf.isupper() else yeni_harf.lower()
            anahtar_index += 1
        else:
            sonuc += harf
    return sonuc

print("=== VİGENERE CİPHER ===")
metin = "MERHABA"
anahtar = "ANAHTAR"
sifreli = vigenere_sifrele(metin, anahtar)
print(f"Orijinal: {metin}")
print(f"Anahtar: {anahtar}")
print(f"Şifreli: {sifreli}")
print(f"Çözülmüş: {vigenere_coz(sifreli, anahtar)}\n")


# c. Substitution Cipher (Yerine Koyma)
def substitution_sifrele(metin, anahtar_sozluk):
    sonuc = ""
    for harf in metin:
        if harf.upper() in anahtar_sozluk:
            yeni = anahtar_sozluk[harf.upper()]
            sonuc += yeni if harf.isupper() else yeni.lower()
        else:
            sonuc += harf
    return sonuc

print("=== SUBSTİTUTİON CİPHER ===")
# Basit bir anahtar haritası
anahtar = {
    'A':'Q', 'B':'W', 'C':'E', 'D':'R', 'E':'T',
    'F':'Y', 'G':'U', 'H':'I', 'I':'O', 'J':'P',
    'K':'A', 'L':'S', 'M':'D', 'N':'F', 'O':'G',
    'P':'H', 'Q':'J', 'R':'K', 'S':'L', 'T':'Z',
    'U':'X', 'V':'C', 'W':'V', 'X':'B', 'Y':'N',
    'Z':'M'
}
metin = "MERHABA"
sifreli = substitution_sifrele(metin, anahtar)
print(f"Orijinal: {metin}")
print(f"Şifreli: {sifreli}\n")


# d. Affine Cipher
def affine_sifrele(metin, a, b):
    sonuc = ""
    for harf in metin:
        if harf.isalpha():
            x = ord(harf.upper()) - ord('A')
            y = (a * x + b) % 26
            yeni_harf = chr(y + ord('A'))
            sonuc += yeni_harf if harf.isupper() else yeni_harf.lower()
        else:
            sonuc += harf
    return sonuc

def mod_inverse(a, m):
    # Modüler ters bulma
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def affine_coz(metin, a, b):
    a_inv = mod_inverse(a, 26)
    if a_inv is None:
        return "Hata: a değerinin 26 ile tersi yok!"
    
    sonuc = ""
    for harf in metin:
        if harf.isalpha():
            y = ord(harf.upper()) - ord('A')
            x = (a_inv * (y - b)) % 26
            yeni_harf = chr(x + ord('A'))
            sonuc += yeni_harf if harf.isupper() else yeni_harf.lower()
        else:
            sonuc += harf
    return sonuc

print("=== AFFİNE CİPHER ===")
metin = "MERHABA"
a, b = 5, 8  # a, 26 ile aralarında asal olmalı
sifreli = affine_sifrele(metin, a, b)
print(f"Orijinal: {metin}")
print(f"Şifreli (a={a}, b={b}): {sifreli}")
print(f"Çözülmüş: {affine_coz(sifreli, a, b)}\n")