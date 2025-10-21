import tkinter as tk
from tkinter import ttk, messagebox
import threading

class CryptoGUI:
    def __init__(self, root):
        self.root = root
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
                               "GCD Şifresi", "Verman Şifresi", "Otopi Şifresi"]
        
        if method in key_required_methods and not self.key_entry.get().strip():
            messagebox.showerror("Hata", f"{method} için key değeri giriniz!")
            return
        
        # Mesaj gönderme simülasyonu
        self.status_label.config(text="Mesaj gönderiliyor...", fg='#f39c12')
        self.send_button.config(state='disabled')
        
        # Threading ile gönderme simülasyonu
        threading.Thread(target=self.simulate_send, daemon=True).start()
    
    def simulate_send(self):
        """Mesaj gönderme simülasyonu"""
        import time
        time.sleep(2)  # 2 saniye bekleme simülasyonu
        
        # UI güncellemesi ana thread'de yapılmalı
        self.root.after(0, self.send_complete)
    
    def send_complete(self):
        """Gönderme tamamlandığında UI'yi güncelle"""
        self.status_label.config(text="Mesaj başarıyla gönderildi!", fg='#27ae60')
        self.send_button.config(state='normal')
        
        # Başarı mesajı
        messagebox.showinfo("Başarılı", "Mesaj başarıyla gönderildi!\n\n" +
                           f"IP: {self.ip_entry.get()}\n" +
                           f"Port: {self.port_entry.get()}\n" +
                           f"Şifreleme: {self.crypto_var.get()}\n" +
                           f"Key: {self.key_entry.get() if self.key_entry.get() else 'Yok'}")
    
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
