# 🔐 Kriptoloji Mesaj Şifreleme Sistemi

Bu proje, server-client mimarisi kullanarak mesaj şifreleme işlemleri yapan bir Python uygulamasıdır.

## 📋 Gereksinimler

- Python 3.6 veya üzeri
- tkinter (genellikle Python ile birlikte gelir)

## 🚀 Projeyi Çalıştırma

### ⚡ Hızlı Başlatma (Önerilen)

**Tek komutla hem server hem GUI'yi başlatın:**

```bash
python launcher.py
```

Bu komut:
- Server'ı arka planda başlatır
- GUI'yi açar
- Her ikisini de otomatik olarak yönetir

### 🔧 Manuel Başlatma

Eğer manuel olarak başlatmak isterseniz:

#### Adım 1: Server'ı Başlatın

```bash
cd server
python server.py
```

Server başarıyla başladığında şu mesajı göreceksiniz:
```
🔐 Kriptoloji Server başlatıldı!
📍 Adres: 127.0.0.1:8080
⏰ Başlatma zamanı: ...
🔄 Client bağlantıları bekleniyor...
```

**ÖNEMLİ:** Server'ı açık tutun! Server çalışırken terminal penceresini kapatmayın.

#### Adım 2: GUI Uygulamasını Başlatın

Yeni bir terminal/komut penceresi açın ve GUI'yi başlatın:

```bash
cd GUI
python crypto_gui.py
```

veya proje kök dizininden:

```bash
python GUI\crypto_gui.py
```

GUI penceresi açıldığında:
- IP Adresi: `127.0.0.1` (varsayılan)
- Port: `8080` (varsayılan)
- Mesajınızı yazın
- Şifreleme yöntemini seçin
- Key değerini girin (gerekirse)
- "📤 Mesajı Gönder" butonuna tıklayın

## 📁 Proje Yapısı

```
server_client-main/
├── SERVER-CLIENT/
│   ├── server.py      # Server uygulaması
│   └── client.py      # Client sınıfı (GUI tarafından kullanılır)
└── GUI/
    └── crypto_gui.py  # Grafik arayüz
```

## 🔧 Alternatif: Client Test Modu

Client'ı doğrudan test etmek isterseniz:

```bash
cd SERVER-CLIENT
python client.py test
```

Bu komut, server'a otomatik test mesajları gönderir.

## ⚠️ Sorun Giderme

### Server başlamıyor
- Port 8080'in başka bir uygulama tarafından kullanılmadığından emin olun
- Firewall ayarlarını kontrol edin

### GUI bağlanamıyor
- Server'ın çalıştığından emin olun
- IP adresinin `127.0.0.1` olduğunu kontrol edin
- Port numarasının `8080` olduğunu kontrol edin

### Import hatası
- Python'un doğru yüklendiğinden emin olun
- Tüm dosyaların doğru konumda olduğunu kontrol edin

## 📝 Kullanım Örneği

1. **Terminal 1:** `cd SERVER-CLIENT` → `python server.py`
2. **Terminal 2:** `cd GUI` → `python crypto_gui.py`
3. GUI'de mesajınızı yazın ve gönderin
4. Server terminalinde mesajı göreceksiniz
5. GUI'de başarı mesajı görünecek

## 🛑 Server'ı Durdurma

Server'ı durdurmak için terminal penceresinde `Ctrl+C` tuşlarına basın.

