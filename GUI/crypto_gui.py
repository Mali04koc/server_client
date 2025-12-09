import tkinter as tk
from tkinter import ttk, messagebox
import threading
import sys
import os

# Şifreleme yöntemlerini import et
try:
    from crypto_methods import encrypt_message
except ImportError:
    encrypt_message = None
    print("[UYARI] crypto_methods modulu bulunamadi, sifreleme devre disi")

# Client sınıfını import et
try:
    # Windows ve Linux/Mac için uyumlu path
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    
    # server_client klasörünü bul
    client_dir = os.path.join(parent_dir, 'server_client')
    
    # Path'i normalize et (Windows için backslash'leri düzelt)
    client_dir = os.path.normpath(client_dir)
    
    # Debug: Path'i kontrol et
    if not os.path.exists(client_dir):
        raise ImportError(f"Client dizini bulunamadı: {client_dir}")
    
    client_file = os.path.join(client_dir, 'client.py')
    if not os.path.exists(client_file):
        raise ImportError(f"client.py dosyası bulunamadı: {client_file}")
    
    if client_dir not in sys.path:
        sys.path.insert(0, client_dir)
    
    # Doğrudan client modülünü import et (server_client paket değil)
    from client import CryptoClient
    # Print ifadesi kaldırıldı - launcher zaten stdout'u yönetiyor
    
except ImportError as e:
    # messagebox henüz import edilmiş olmalı ama yine de güvenli olalım
    error_msg = f"Client modulu yuklenemedi!\n\nHata: {str(e)}\n\nLutfen server_client/client.py dosyasinin mevcut oldugundan emin olun."
    # Print ifadesi kaldırıldı - launcher zaten stdout'u yönetiyor
    try:
        from tkinter import messagebox
        # Tkinter root oluşturmadan messagebox gösteremeyiz, bu yüzden sadece print yapıyoruz
        # messagebox.showerror("Import Hatası", error_msg)
    except:
        pass
    # CryptoClient None olarak ayarla, sonra kontrol edelim
    CryptoClient = None

class CryptoGUI:
    def __init__(self, root, auto_connect=False):
        self.root = root
        self.auto_connect = auto_connect
        self.root.title("Kriptoloji - Mesaj Şifreleme Arayüzü")
        self.root.geometry("800x700")
        self.root.configure(bg='#f0f0f0')
        
        # Ana frame
        main_frame = tk.Frame(root, bg='#f0f0f0', padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Başlık
        title_label = tk.Label(main_frame, text="🔐 Kriptoloji Mesaj Şifreleme Sistemi", 
                              font=('Arial', 18, 'bold'), bg='#f0f0f0', fg='#2c3e50')
        title_label.pack(pady=(0, 20))
        
        # Bağlantı bilgileri frame
        connection_frame = tk.LabelFrame(main_frame, text="🌐 Bağlantı Bilgileri", 
                                       font=('Arial', 12, 'bold'), bg='#f0f0f0', fg='#34495e')
        connection_frame.pack(fill=tk.X, pady=(0, 15))
        
        # IP ve Port girişi
        ip_frame = tk.Frame(connection_frame, bg='#f0f0f0')
        ip_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(ip_frame, text="IP Adresi:", font=('Arial', 10, 'bold'), 
                bg='#f0f0f0', fg='#2c3e50').pack(side=tk.LEFT, padx=(0, 10))
        self.ip_entry = tk.Entry(ip_frame, font=('Arial', 10), width=20)
        self.ip_entry.pack(side=tk.LEFT, padx=(0, 20))
        self.ip_entry.insert(0, "127.0.0.1")
        
        tk.Label(ip_frame, text="Port:", font=('Arial', 10, 'bold'), 
                bg='#f0f0f0', fg='#2c3e50').pack(side=tk.LEFT, padx=(0, 10))
        self.port_entry = tk.Entry(ip_frame, font=('Arial', 10), width=10)
        self.port_entry.pack(side=tk.LEFT)
        self.port_entry.insert(0, "8080")
        
        # Mesaj girişi frame
        message_frame = tk.LabelFrame(main_frame, text="💬 Mesaj", 
                                    font=('Arial', 12, 'bold'), bg='#f0f0f0', fg='#34495e')
        message_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # Mesaj text area
        self.message_text = tk.Text(message_frame, height=8, font=('Arial', 10), 
                                   wrap=tk.WORD, bg='white', fg='#2c3e50')
        self.message_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Şifreleme seçenekleri frame
        crypto_frame = tk.LabelFrame(main_frame, text="🔒 Şifreleme Yöntemi", 
                                   font=('Arial', 12, 'bold'), bg='#f0f0f0', fg='#34495e')
        crypto_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Şifreleme yöntemleri
        crypto_methods = [
            "Sezar Şifresi",
            "Playfair Şifresi", 
            "Vigenere Şifresi",
            "Substitution Şifresi",
            "Affine Şifresi",
            "Rail Fence Şifresi",
            "Rotate Şifresi",
            "Columnar Transposition",
            "Hill Şifresi",
            "AES",
            "GCD Şifresi",
            "Verman Şifresi",
            "Otopi Şifresi"
        ]
        
        # Şifreleme yöntemi seçimi
        method_frame = tk.Frame(crypto_frame, bg='#f0f0f0')
        method_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(method_frame, text="Şifreleme Yöntemi:", font=('Arial', 10, 'bold'), 
                bg='#f0f0f0', fg='#2c3e50').pack(side=tk.LEFT, padx=(0, 10))
        
        self.crypto_var = tk.StringVar()
        self.crypto_combo = ttk.Combobox(method_frame, textvariable=self.crypto_var, 
                                       values=crypto_methods, state="readonly", width=25)
        self.crypto_combo.pack(side=tk.LEFT, padx=(0, 10))
        self.crypto_combo.bind('<<ComboboxSelected>>', self.on_crypto_method_change)
        
        # Key girişi frame (başlangıçta gizli)
        self.key_frame = tk.Frame(crypto_frame, bg='#f0f0f0')
        self.key_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.key_label = tk.Label(self.key_frame, text="Key:", font=('Arial', 10, 'bold'), 
                                 bg='#f0f0f0', fg='#2c3e50')
        self.key_entry = tk.Entry(self.key_frame, font=('Arial', 10), width=30)
        
        # Butonlar frame
        button_frame = tk.Frame(main_frame, bg='#f0f0f0')
        button_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Gönder butonu
        self.send_button = tk.Button(button_frame, text="📤 Mesajı Gönder", 
                                   font=('Arial', 12, 'bold'), bg='#3498db', fg='white',
                                   command=self.send_message, width=20, height=2)
        self.send_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Temizle butonu
        self.clear_button = tk.Button(button_frame, text="🗑️ Temizle", 
                                    font=('Arial', 12, 'bold'), bg='#e74c3c', fg='white',
                                    command=self.clear_all, width=15, height=2)
        self.clear_button.pack(side=tk.LEFT)
        
        # Durum çubuğu
        self.status_label = tk.Label(main_frame, text="Hazır", font=('Arial', 10), 
                                   bg='#f0f0f0', fg='#27ae60')
        self.status_label.pack(pady=(10, 0))
        
        # Başlangıçta key frame'i gizle
        self.hide_key_frame()
        
        # Client bağlantısı
        self.client = None
        self.connected = False
        
        # Otomatik bağlantı (launcher'dan çağrıldığında)
        if self.auto_connect:
            self.root.after(100, self.auto_connect_to_server)
    
    def on_crypto_method_change(self, event):
        """Şifreleme yöntemi değiştiğinde key gereksinimlerini kontrol et"""
        method = self.crypto_var.get()
        
        # Key gerektiren yöntemler
        key_required_methods = {
            "Sezar Şifresi": "Kaydırma Sayısı (örn: 3)",
            "Playfair Şifresi": "Anahtar Kelime (örn: MONARCHY)",
            "Vigenere Şifresi": "Anahtar Kelime (örn: KEY)",
            "Substitution Şifresi": "Yer Değiştirme Tablosu",
            "Affine Şifresi": "a,b değerleri (örn: 5,8)",
            "Rail Fence Şifresi": "Ray Sayısı (örn: 3)",
            "Rotate Şifresi": "Döndürme Miktarı",
            "Columnar Transposition": "Anahtar Kelime",
            "Hill Şifresi": "Matris (örn: 2x2)",
            "AES": "16 byte key (örn: 16 karakter)",
            "GCD Şifresi": "GCD Değeri",
            "Verman Şifresi": "Anahtar",
            "Otopi Şifresi": "Özel Anahtar"
        }
        
        if method in key_required_methods:
            self.show_key_frame(key_required_methods[method])
        else:
            self.hide_key_frame()
    
    def show_key_frame(self, key_label_text):
        """Key girişi frame'ini göster"""
        self.key_label.config(text=f"{key_label_text}:")
        self.key_label.pack(side=tk.LEFT, padx=(0, 10))
        self.key_entry.pack(side=tk.LEFT)
        self.key_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
    
    def hide_key_frame(self):
        """Key girişi frame'ini gizle"""
        self.key_label.pack_forget()
        self.key_entry.pack_forget()
        self.key_frame.pack_forget()
    
    def send_message(self):
        """Mesaj gönderme işlemi"""
        # Form validasyonu
        if not self.ip_entry.get().strip():
            messagebox.showerror("Hata", "IP adresi giriniz!")
            return
        
        if not self.port_entry.get().strip():
            messagebox.showerror("Hata", "Port numarası giriniz!")
            return
        
        if not self.message_text.get("1.0", tk.END).strip():
            messagebox.showerror("Hata", "Mesaj giriniz!")
            return
        
        if not self.crypto_var.get():
            messagebox.showerror("Hata", "Şifreleme yöntemi seçiniz!")
            return
        
        # Key kontrolü
        method = self.crypto_var.get()
        key_required_methods = ["Sezar Şifresi", "Playfair Şifresi", "Vigenere Şifresi", 
                               "Substitution Şifresi", "Affine Şifresi", "Rail Fence Şifresi",
                               "Rotate Şifresi", "Columnar Transposition", "Hill Şifresi",
                               "AES", "GCD Şifresi", "Verman Şifresi", "Otopi Şifresi"]
        
        key_text = self.key_entry.get().strip()
        if method in key_required_methods and not key_text:
            messagebox.showerror("Hata", f"{method} için key değeri giriniz!")
            return
        # Hill için özel key formatı kontrolü
        if method == "Hill Şifresi":
            import re
            if not re.fullmatch(r"\s*-?\d+(\s*,\s*-?\d+)+\s*", key_text):
                messagebox.showerror(
                    "Hata",
                    "Hill Şifresi için key formatı: virgülle ayrılmış tam sayılar.\n"
                    "Örn (3x3): 6,24,1,13,16,10,20,17,15"
                )
                return

        # AES için key kontrolü
        if method == "AES":
            if len(key_text.encode("utf-8")) != 16:
                messagebox.showerror(
                    "Hata",
                    "AES için key 16 byte (128-bit) olmalı.\n"
                    "Örn: 16 karakterlik bir anahtar girin."
                )
                return
        
        # Hill için özel key doğrulaması (NxN virgülle ayrılmış tam sayılar)
        if method == "Hill Şifresi":
            key_str = self.key_entry.get().strip()
            try:
                parts = [p.strip() for p in key_str.split(',') if p.strip() != '']
                numbers = [int(p) for p in parts]
                if not numbers:
                    raise ValueError("Key boş olamaz")
                root = int(len(numbers) ** 0.5)
                if root * root != len(numbers):
                    raise ValueError(f"Key uzunluğu kare olmalı (4, 9, 16, ...). Şu an: {len(numbers)} değer")
            except ValueError as e:
                messagebox.showerror("Hata", f"Hill anahtarı hatalı.\n\nVirgülle ayrılmış sayılar girin.\nÖrn: 2x2 için 4 sayı: 5,17,8,3\n3x3 için 9 sayı: 6,24,1,13,16,10,20,17,15\n\nDetay: {e}")
                return
        
        # Gerçek mesaj gönderme
        self.status_label.config(text="Bağlanıyor...", fg='#f39c12')
        self.send_button.config(state='disabled')
        
        # Threading ile gerçek gönderme
        threading.Thread(target=self.real_send, daemon=True).start()
    
    def real_send(self):
        """Gerçek mesaj gönderme"""
        if CryptoClient is None:
            self.root.after(0, lambda: self.send_error("Client modülü yüklenemedi! Lütfen SERVER-CLIENT/client.py dosyasının mevcut olduğundan emin olun."))
            return
            
        client = None
        try:
            # Client oluştur
            client = CryptoClient()
            
            # Server'a bağlan
            ip = self.ip_entry.get().strip()
            try:
                port = int(self.port_entry.get().strip())
            except ValueError:
                self.root.after(0, lambda: self.send_error("Geçersiz port numarası!"))
                return
            
            self.root.after(0, lambda: self.status_label.config(text="Bağlanıyor...", fg='#f39c12'))
            
            if client.connect(ip, port, timeout=10):
                self.connected = True
                self.root.after(0, lambda: self.status_label.config(text="Bağlandı, mesaj gönderiliyor...", fg='#3498db'))
                
                # Mesajı al ve şifrele
                original_message = self.message_text.get("1.0", tk.END).strip()
                crypto_method = self.crypto_var.get()
                key = self.key_entry.get().strip() if self.key_entry.get().strip() else None
                
                # Şifreleme işlemi
                encrypted_message = original_message
                if crypto_method and encrypt_message:
                    try:
                        encrypted_message = encrypt_message(original_message, crypto_method, key)
                        self.root.after(0, lambda: self.status_label.config(
                            text=f"Mesaj sifrelendi: {crypto_method}", fg='#3498db'))
                    except Exception as e:
                        self.root.after(0, lambda: self.send_error(f"Sifreleme hatasi: {str(e)}"))
                        return
                
                # Şifrelenmiş mesajı gönder
                if client.send_message(encrypted_message, crypto_method, key):
                    # Cevap bekle (server'ın cevap göndermesi için bekleme yok, direkt bekle)
                    response = client.receive_response(timeout=10)
                    
                    if response:
                        self.root.after(0, lambda r=response: self.send_success(r))
                    else:
                        self.root.after(0, lambda: self.send_error("Server'dan cevap alınamadı. Server çalışıyor mu kontrol edin."))
                    
                    # Bağlantıyı kes (cevap aldıktan SONRA)
                    try:
                        client.disconnect()
                    except:
                        pass
                else:
                    self.root.after(0, lambda: self.send_error("Mesaj gönderilemedi"))
                    # Bağlantıyı kes
                    try:
                        client.disconnect()
                    except:
                        pass
                
                self.connected = False
                
            else:
                self.root.after(0, lambda: self.send_error("Server'a bağlanılamadı. Server çalışıyor mu kontrol edin."))
                
        except ValueError as e:
            self.root.after(0, lambda: self.send_error(f"Geçersiz değer: {str(e)}"))
        except Exception as e:
            self.root.after(0, lambda: self.send_error(f"Bağlantı hatası: {str(e)}"))
        finally:
            # Güvenli temizlik
            if client:
                try:
                    client.disconnect()
                except:
                    pass
            self.connected = False
    
    def send_success(self, response):
        """Başarılı gönderme"""
        self.status_label.config(text="Mesaj başarıyla gönderildi!", fg='#27ae60')
        self.send_button.config(state='normal')
        
        # Başarı mesajı
        messagebox.showinfo("Başarılı", 
                           f"✅ Mesaj başarıyla gönderildi!\n\n"
                           f"📡 Server: {self.ip_entry.get()}:{self.port_entry.get()}\n"
                           f"🔒 Şifreleme: {self.crypto_var.get()}\n"
                           f"🔑 Key: {self.key_entry.get() if self.key_entry.get() else 'Yok'}\n"
                           f"📨 Server Cevabı: {response.get('message', 'Cevap alındı')}")
    
    def send_error(self, error_message):
        """Hata durumu"""
        self.status_label.config(text=f"Hata: {error_message}", fg='#e74c3c')
        self.send_button.config(state='normal')
        messagebox.showerror("Hata", error_message)
    
    def auto_connect_to_server(self):
        """Otomatik olarak server'a bağlan (launcher için)"""
        # IP ve Port zaten varsayılan değerlerde (127.0.0.1:8080)
        # Sadece durum mesajını güncelle
        self.status_label.config(text="Server hazır - Mesaj göndermeye hazırsınız!", fg='#27ae60')
    
    def clear_all(self):
        """Tüm alanları temizle"""
        self.message_text.delete("1.0", tk.END)
        self.key_entry.delete(0, tk.END)
        self.crypto_var.set("")
        self.status_label.config(text="Hazır", fg='#27ae60')
        self.hide_key_frame()

def main():
    root = tk.Tk()
    app = CryptoGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
