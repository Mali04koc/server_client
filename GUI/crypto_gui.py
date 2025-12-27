import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog, filedialog
import threading
import socket
import json
import time
from datetime import datetime
import os
import sys
import base64

# Şifreleme yöntemlerini import et (Mevcut yapı)
try:
    # Path düzeltmeleri (Önceki koddan)
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    server_client_dir = os.path.join(parent_dir, 'server_client')
    sys.path.insert(0, server_client_dir)
    # from server_client.client import CryptoClient # Client sınıfı artık opsiyonel, doğrudan socket kullanıyoruz
    
    # Crypto methods
    # crypto_dir = os.path.join(parent_dir, 'crypto_methods') # Yanlış
    sys.path.insert(0, parent_dir) # Doğru: Parent dizini ekle ki 'crypto_methods' modül olarak görünsün
    
    # Gerekli modülleri import et
    from crypto_methods import encrypt_message, decrypt_message, ENCRYPT_FUNCTIONS
    from crypto_methods.rsa import generate_keypair as gen_rsa
    from crypto_methods.ecc import generate_ecc_keypair as gen_ecc
    
except ImportError as e:
    print(f"Import hatası: {e}")
    encrypt_message = None
    decrypt_message = None
    gen_rsa = None
    gen_ecc = None

class CryptoChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("KriptoChat - Güvenli Mesajlaşma")
        self.root.geometry("1100x750")
        self.root.configure(bg='#f5f6fa')
        
        # Değişkenler
        self.my_port = tk.StringVar(value="9000") # Varsayılan dinleme portu
        self.target_ip = tk.StringVar(value="127.0.0.1")
        self.target_port = tk.StringVar(value="8080") # Server Portu (Relay)
        self.username = tk.StringVar(value=f"User_{datetime.now().strftime('%M%S')}")
        self.crypto_method = tk.StringVar(value="AES")
        self.key_var = tk.StringVar()
        self.dest_ip = tk.StringVar(value="127.0.0.1")
        self.download_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'downloads')
        if not os.path.exists(self.download_dir):
            os.makedirs(self.download_dir)
        
        # Asimetrik Anahtarlar
        self.my_private_key = None
        self.my_public_key_var = tk.StringVar()

        
        # Socket ve Thread kontrolü
        self.listener_running = False
        self.client_socket = None

        
        self.setup_ui()
        
        # Otomatik dinleyici başlat
        self.root.after(1000, self.start_listener_thread)

    def setup_ui(self):
        # Sol Panel (Ayarlar) - Genişlik 300px
        left_panel = tk.Frame(self.root, width=300, bg='#2c3e50')
        left_panel.pack(side=tk.LEFT, fill=tk.Y)
        left_panel.pack_propagate(False)
        
        self._setup_connection_settings(left_panel)
        self._setup_crypto_settings(left_panel)
        
        # Sağ Panel (Chat)
        right_panel = tk.Frame(self.root, bg='#ecf0f1')
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        self._setup_chat_area(right_panel)
        self._setup_input_area(right_panel)

    def _setup_connection_settings(self, parent):
        frame = tk.LabelFrame(parent, text="Bağlantı Ayarları", bg='#2c3e50', fg='white', font=('Arial', 10, 'bold'))
        frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Kullanıcı Adı
        tk.Label(frame, text="Kullanıcı Adı:", bg='#2c3e50', fg='#bdc3c7').pack(anchor='w', padx=5)
        tk.Entry(frame, textvariable=self.username).pack(fill=tk.X, padx=5, pady=(0, 10))
        
        # Benim Portum
        tk.Label(frame, text="Dinlenen Port (My Port):", bg='#2c3e50', fg='#bdc3c7').pack(anchor='w', padx=5)
        entry_port = tk.Entry(frame, textvariable=self.my_port)
        entry_port.pack(fill=tk.X, padx=5, pady=(0, 10))
        tk.Button(frame, text="Portu Yenile / Bağlan", bg='#e67e22', fg='white', command=self.restart_listener).pack(fill=tk.X, padx=5, pady=(0, 10))
        
        # Hedef Server
        tk.Label(frame, text="Server IP:", bg='#2c3e50', fg='#bdc3c7').pack(anchor='w', padx=5)
        tk.Entry(frame, textvariable=self.target_ip).pack(fill=tk.X, padx=5, pady=(0, 5))
        
        tk.Label(frame, text="Server Port:", bg='#2c3e50', fg='#bdc3c7').pack(anchor='w', padx=5)
        tk.Entry(frame, textvariable=self.target_port).pack(fill=tk.X, padx=5, pady=(0, 10))
        
        # Hedef Client (Routing için)
        tk.Label(frame, text="Hedef IP (Kime):", bg='#2c3e50', fg='#bdc3c7').pack(anchor='w', padx=5)
        tk.Entry(frame, textvariable=self.dest_ip).pack(fill=tk.X, padx=5, pady=(0, 10))

    def _setup_crypto_settings(self, parent):
        frame = tk.LabelFrame(parent, text="Kriptografi", bg='#2c3e50', fg='white', font=('Arial', 10, 'bold'))
        frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Yöntem Seçimi
        tk.Label(frame, text="Yöntem:", bg='#2c3e50', fg='#bdc3c7').pack(anchor='w', padx=5)
        
        # Dinamik yöntem listesi
        methods = list(ENCRYPT_FUNCTIONS.keys()) if 'ENCRYPT_FUNCTIONS' in globals() else ["AES", "DES"]
        # Alfabetik sırala (Okunabilirlik için)
        methods.sort()
        
        cb = ttk.Combobox(frame, textvariable=self.crypto_method, values=methods, state="readonly")
        cb.pack(fill=tk.X, padx=5, pady=(0, 10))
        
        # Key Yönetimi
        self.lbl_key = tk.Label(frame, text="Anahtar (Key):", bg='#2c3e50', fg='#bdc3c7')
        self.lbl_key.pack(anchor='w', padx=5)
        self.entry_key = tk.Entry(frame, textvariable=self.key_var)
        self.entry_key.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        # Sadece Asimetrik için görünecek alan (Benim Public Keyim)
        self.lbl_my_pub = tk.Label(frame, text="Benim Public Key (Kopyala):", bg='#2c3e50', fg='#bdc3c7')
        # Başlangıçta gizli olsun, method değişince yönetiz
        # self.lbl_my_pub.pack(anchor='w', padx=5) 
        
        self.entry_my_pub = tk.Entry(frame, textvariable=self.my_public_key_var, state='readonly')
        # self.entry_my_pub.pack(fill=tk.X, padx=5, pady=(0, 5))

        tk.Button(frame, text="🔑 Anahtar Oluştur", bg='#27ae60', fg='white', command=self.open_key_generator).pack(fill=tk.X, padx=5, pady=2)
        tk.Button(frame, text="🔓 Manuel Mesaj Çöz", bg='#8e44ad', fg='white', command=self.open_manual_decrypt).pack(fill=tk.X, padx=5, pady=5)
        
        # Mod (Lib vs Manual)
        self.use_lib = tk.BooleanVar(value=False)
        self.chk_lib = tk.Checkbutton(frame, text="Kütüphane Kullan (Hızlı)", variable=self.use_lib, bg='#2c3e50', fg='white', selectcolor='#2c3e50')
        self.chk_lib.pack(anchor='w', padx=5, pady=10)

        # Event Binding
        cb.bind("<<ComboboxSelected>>", self.update_ui_for_method)
        
        # UI Başlangıç ayarı
        self.update_ui_for_method()

    def update_ui_for_method(self, event=None):
        method = self.crypto_method.get()
        
        # 1. Asimetrik / Simetrik Arayüz Ayarı
        if method in ["RSA", "ECC"]:
            self.lbl_key.config(text="Arkadaşının Public Key'i (Yapıştır):")
            self.lbl_my_pub.pack(anchor='w', padx=5, after=self.entry_key)
            self.entry_my_pub.pack(fill=tk.X, padx=5, pady=(0, 5), after=self.lbl_my_pub)
        else:
            self.lbl_key.config(text="Ortak Gizli Anahtar (Shared Key):")
            self.lbl_my_pub.pack_forget()
            self.entry_my_pub.pack_forget()
            
        # 2. Kütüphane Desteği Ayarı
        if method in ["AES", "DES"]:
            self.chk_lib.config(state='normal')
        else:
            self.use_lib.set(False) # Diğer metodlarda otomatik kapat
            self.chk_lib.config(state='disabled')


    def _setup_chat_area(self, parent):
        # Chat Başlığı
        header = tk.Frame(parent, bg='white', height=50)
        header.pack(fill=tk.X)
        tk.Label(header, text="Canlı Sohbet", font=('Arial', 14, 'bold'), bg='white', fg='#2c3e50').pack(pady=10)
        
        # Mesaj Alanı
        self.chat_display = scrolledtext.ScrolledText(parent, state='disabled', bg='#ecf0f1', font=('Arial', 10))
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.chat_display.tag_config('sent', foreground='#2980b9', justify='right')
        self.chat_display.tag_config('received', foreground='#27ae60', justify='left')
        self.chat_display.tag_config('system', foreground='#7f8c8d', justify='center', font=('Arial', 9, 'italic'))

    def _setup_input_area(self, parent):
        input_frame = tk.Frame(parent, bg='white', height=60)
        input_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.msg_entry = tk.Entry(input_frame, font=('Arial', 12))
        self.msg_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.msg_entry.bind("<Return>", self.send_message)
        
        send_btn = tk.Button(input_frame, text="GÖNDER", bg='#3498db', fg='white', font=('Arial', 10, 'bold'), command=self.send_message)
        send_btn.pack(side=tk.RIGHT, padx=5, pady=10)
        
        attach_btn = tk.Button(input_frame, text="📎 Dosya", bg='#95a5a6', fg='white', font=('Arial', 10, 'bold'), command=self.send_file)
        attach_btn.pack(side=tk.RIGHT, padx=5, pady=10)

    def log(self, message, tag='system'):
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, f"{message}\n", tag)
        self.chat_display.see(tk.END)
        self.chat_display.see(tk.END)
        self.chat_display.config(state='disabled')

    def _ensure_key_length(self, key, method):
        """Anahtar uzunluğunu metoda göre ayarla (Pad/Truncate)"""
        if not key: return ""
        
        target_len = 0
        if method == "AES": target_len = 16
        elif method == "DES": target_len = 8
        
        if target_len > 0:
            # Byte uzunluğuna bakmamız lazım çünkü şifreleyici encode('utf-8') yapıyor
            key_bytes = key.encode('utf-8')
            if len(key_bytes) < target_len:
                # Pad (Boşluk ile tamamla)
                key_bytes += b' ' * (target_len - len(key_bytes))
            elif len(key_bytes) > target_len:
                # Truncate (Kes)
                key_bytes = key_bytes[:target_len]
            
            # Tekrar string'e çevir (Gerekirse decode hatasını yut)
            return key_bytes.decode('utf-8', errors='ignore')
            
        return key


    def open_key_generator(self):
        """Anahtar Üretme Penceresi"""
        method = self.crypto_method.get()
        new_key = ""
        
        try:
            if method == "RSA":
                if gen_rsa:
                    # pk (Public), sk (Private)
                    # Artık rastgele asal üretiyor (Argümansız çağır)
                    pk, sk = gen_rsa()
                    
                    # Store Private Locally
                    self.my_private_key = sk
                    
                    # Display Public
                    pub_str = f"Public: {pk}"
                    self.my_public_key_var.set(pub_str)
                    
                    # Kullanıcı bilgilendirme
                    messagebox.showinfo("RSA Key Pair", f"Anahtar Çifti Oluşturuldu!\n\n1. 'Benim Public Key' kutusundakini kopyala.\n2. Arkadaşına gönder.\n3. Arkadaşından gelen kodu 'Arkadaşının Public Key'i' kutusuna yapıştır.")
                else:
                    self.my_public_key_var.set("RSA_ERROR")

            elif method == "ECC":
                if gen_ecc:
                    keys = gen_ecc()
                    
                    # Store Private Locally
                    self.my_private_key = keys['private']
                    
                    # Display Public
                    self.my_public_key_var.set(keys['public'])
                    
                    messagebox.showinfo("ECC Key Pair", f"Anahtar Çifti Oluşturuldu!\n\n1. 'Benim Public Key' kutusundakini kopyala.\n2. Arkadaşına gönder.\n3. Arkadaşından gelen kodu 'Arkadaşının Public Key'i' kutusuna yapıştır.")
                else:
                    self.my_public_key_var.set("ECC_NOT_FOUND")
            
            elif method == "AES":
                import random, string
                new_key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
                self.key_var.set(new_key)
                
            elif method == "DES":
                import random, string
                new_key = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
                self.key_var.set(new_key)
                
            else:
                import random, string
                new_key = ''.join(random.choices(string.ascii_uppercase, k=5))
                self.key_var.set(new_key)
                
            if method not in ["RSA", "ECC"]:
                self.log(f"🔑 Yeni Anahtar Oluşturuldu ({method}): {new_key}", 'system')

            
        except Exception as e:
            messagebox.showerror("Key Hatası", str(e))

    def open_manual_decrypt(self):
        """Geçmiş mesajları manuel çözmek için araç"""
        method = self.crypto_method.get()
        key = self.key_var.get()
        
        if not key:
            messagebox.showwarning("Uyarı", "Önce bir anahtar (key) girmelisiniz!")
            return

        key = self.key_var.get() # Bu encrypted_text'i çözecek key olmalı
        # Eğer Asimetrik ise, bu işlem için BENİM private keyim lazım
        if method in ["RSA", "ECC"]:
            if not self.my_private_key:
                messagebox.showerror("Hata", "Önce 'Anahtar Oluştur' diyerek kendi Private Key'inizi oluşturmalısınız!")
                return
            key = self.my_private_key # Private key ile çözülür
            
            # String e çevir (RSA modülü str bekliyor parse etmek için, veya obje)
            # Bizim RSA modülü hem tuple hem string parse edebiliyor (güncellediğimiz haliyle)
            # ECC modülü string private key kullanıyor.
            # Sorun yok.
        
        # Key uzunluğunu düzelt (Sadece Simetrikler için, Asimetriklere dokunma)
        if method not in ["RSA", "ECC"]:
            key = self._ensure_key_length(key, method)


        # Kullanıcıdan şifreli metni iste
        encrypted_text = simpledialog.askstring("Manuel Çözücü", f"[{method}] Şifreli metni yapıştırın:")
        if not encrypted_text: return
        
        try:
            # Lib tercihi
            use_library = self.use_lib.get()
            
            if decrypt_message:
                if method in ["AES", "DES"]:
                    decoded = decrypt_message(encrypted_text, method, key, use_lib=use_library)
                else:
                    decoded = decrypt_message(encrypted_text, method, key)
                
                messagebox.showinfo("Sonuç", f"🔓 Çözülen Mesaj:\n\n{decoded}")
            else:
                messagebox.showerror("Hata", "Kripto modülü yüklenemedi.")
                
        except Exception as e:
            messagebox.showerror("Çözme Hatası", f"Mesaj çözülemedi!\nAnahtarın doğru olduğundan emin ol.\n\nHata: {str(e)}")

    def start_listener_thread(self):
        self.listener_running = True
        threading.Thread(target=self.poll_server, daemon=True).start()

    def poll_server(self):
        """Server'a bağlan ve sürekli dinle"""
        if self.username.get().startswith("User_"):
             # Username güncelle
             pass

        while self.listener_running:
            try:
                # Her seferinde bağlanıp kontrol et (Short Polling) veya
                # Sürekli açık socket (Persistent) kullan. 
                # Server yapımız 'threading' kullandığı için kalıcı bağlantıya uygun.
                
                self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    self.client_socket.connect((self.target_ip.get(), int(self.target_port.get())))
                except:
                    # Server kapalıysa bekle
                    time.sleep(2)
                    continue

                # Kimlik bildir (Ben bu portu dinliyorum veya sadece ben buyum)
                # Şu anki server yapısı IP tabanlı, o yüzden ekstra bir şey yapmaya gerek yok
                # Ama 'register' mesajı atabiliriz
                
                # Sürekli dinle...
                # Server tarafında 'process_message' var, ama server bana ne zaman mesaj atacak?
                # Ben bir mesaj atmadıkça server bana cevap dönmüyor şu anki yapıda.
                # Server'ın 'Active Relay' olması lazım.
                # Server.py'yi değiştirdik, artık server socket'i saklıyor.
                # O yüzden bağlantıyı KOPARMAMALIYIZ.
                
                self.root.after(0, lambda: self.log("✅ Sunucuya Bağlandı, Mesaj bekleniyor..."))
                
                # Kimlik Kaydı
                reg_msg = {
                    'type': 'register',
                    'client_id': self.username.get(),
                }
                try:
                    self.client_socket.send(json.dumps(reg_msg).encode('utf-8'))
                except: pass
                
                while self.listener_running:
                    try:
                        data = self.client_socket.recv(16384)
                        if not data: 
                            break # Bağlantı koptu
                        
                        # Birden fazla JSON gelebilir (TCP stream), basitçe split edelim veya tek varsayalım
                        try:
                            msg = json.loads(data.decode('utf-8'))
                            self.handle_incoming_message(msg)
                        except json.JSONDecodeError:
                            # Stream hatası, parçalı veri olabilir
                            pass
                            
                    except socket.error:
                        break
                
                if self.client_socket:
                    try:
                        self.client_socket.close()
                    except: pass

                self.root.after(0, lambda: self.log("⚠️ Sunucu bağlantısı kesildi. Tekrar bağlanılıyor...", 'system'))
                time.sleep(2)
                
            except Exception as e:
                # Genel hata
                time.sleep(2)

    def handle_incoming_message(self, msg):
        msg_type = msg.get('type')
        
        if msg_type == 'crypto_message':
            sender = msg.get('sender_id', 'Bilinmeyen')
            sender_username = msg.get('sender_username', '')
            
            # Kendi mesajımı görmezden gel (Loopback önleme)
            if sender_username == self.username.get():
                return

            content = msg.get('encrypted_content', '') # ŞİFRELİ MESAJ
            method = msg.get('crypto_method', '')
            
            # Deşifre denemesi
            decrypted_text = "Çözülemedi"
            
            # Çözme Anahtarı Seçimi:
            decryption_key = None
            
            if method in ["RSA", "ECC"]:
                # Asimetrik: Benim Private Key'im ile çözülür
                if self.my_private_key:
                    decryption_key = self.my_private_key
                else:
                    decrypted_text = "[Hata: Private Key Yok! Önce Anahtar Oluşturun]"
            else:
                # Simetrik: Kutudaki Key ile çözülür
                decryption_key = self.key_var.get()
                # Key uzunluk kontrolü
                decryption_key = self._ensure_key_length(decryption_key, method)
            
            # Gelen veriyi çözmeye çalış
            if decrypt_message and decryption_key:
                try:
                    # Kütüphane kullanımına göre burası ayrılacak
                    use_lib = False
                    # Şimdilik sadece AES ve DES için destek var
                    if method in ["AES", "DES"]:
                        pass

                    decrypted_text = decrypt_message(content, method, decryption_key) # Opsiyonel: use_lib=self.use_lib.get()

                except Exception as e:
                    decrypted_text = f"[Hata: {e}]"
            
            display_text = f"[{sender}]\n🔒 {content}\n🔓 {decrypted_text}"
            self.root.after(0, lambda: self.log(display_text, 'received'))
            
        elif msg_type == 'file_message':
            sender = msg.get('sender_id', 'Bilinmeyen')
            filename = msg.get('filename', 'unknown_file')
            encrypted_content = msg.get('encrypted_content', '')
            method = msg.get('crypto_method', '')
            
            self.root.after(0, lambda: self.log(f"[{sender}] 📎 Dosya Gönderdi: {filename}", 'received'))
            
            # Otomatik İndir/Çöz ve Kaydet
            try:
                # 1. Key Hazırla
                decryption_key = None
                if method in ["RSA", "ECC"]:
                    if self.my_private_key:
                        decryption_key = self.my_private_key
                else:
                    decryption_key = self.key_var.get()
                    decryption_key = self._ensure_key_length(decryption_key, method)
                
                if decryption_key:
                    # 2. İçeriği Çöz (Base64 string olarak döner)
                    decrypted_b64 = "HATA"
                    if decrypt_message:
                        try:
                            # Dosyalar genelde büyük olduğu için kütüphane kullanılması mantıklı
                            # ama şimdilik mevcut config'e uyalım
                            use_lib = True if method in ["AES", "DES"] else False
                            if method in ["AES", "DES"]:
                                # Lib encryption base64 döner, biz de base64 şifreli veri bekliyoruz
                                decrypted_b64 = decrypt_message(encrypted_content, method, decryption_key, use_lib=use_lib)
                            else:
                                decrypted_b64 = decrypt_message(encrypted_content, method, decryption_key)
                        except Exception as e:
                            print(f"File Decrypt Error: {e}")
                            
                    # 3. Base64 -> Dosya
                    try:
                        file_data = base64.b64decode(decrypted_b64)
                        save_path = os.path.join(self.download_dir, f"received_{filename}")
                        with open(save_path, "wb") as f:
                            f.write(file_data)
                        
                        self.root.after(0, lambda: self.log(f"💾 Dosya Kaydedildi: {save_path}", 'system'))
                    except Exception as e:
                         self.root.after(0, lambda: self.log(f"❌ Dosya kaydetme hatası: {e}", 'system'))

            except Exception as e:
                pass

        elif msg_type == 'ack':
            # İletildi bilgisi
            count = msg.get('count', 0)
            self.root.after(0, lambda: self.log(f"✓ Mesaj {count} kişiye iletildi", 'system'))

    def restart_listener(self):
        self.listener_running = False
        # Varsa eski soketi kapat ki thread 'recv' bloğundan çıksın
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
        
        time.sleep(0.5)
        self.start_listener_thread()

    def send_message(self, event=None):
        msg_text = self.msg_entry.get()
        if not msg_text: return
        
        target_ip = self.dest_ip.get()
        method = self.crypto_method.get()
        key = self.key_var.get()
        
        # Şifreleme Anahtarı Seçimi:
        encryption_key = None
        
        if method in ["RSA", "ECC"]:
            # Asimetrik: Karşı tarafın Public Key'i (Kutudaki) ile şifrelenir
            encryption_key = self.key_var.get()
            if not encryption_key:
                 messagebox.showwarning("Uyarı", "Mesaj göndermek için arkadaşının Public Key'ini girmelisin!")
                 return
        else:
             # Simetrik: Kutudaki Key
             encryption_key = self.key_var.get()
             encryption_key = self._ensure_key_length(encryption_key, method)
        

        
        # Şifreleme
        encrypted_text = msg_text
        start_time = time.time()
        
        if encrypt_message:
            try:
                # Lib vs Manual seçimi
                # Sadece AES ve DES için destekliyoruz şu an
                use_library = self.use_lib.get()
                if method in ["AES", "DES"]:
                    encrypted_text = encrypt_message(msg_text, method, encryption_key, use_lib=use_library)
                else:
                    encrypted_text = encrypt_message(msg_text, method, encryption_key)

            except Exception as e:
                messagebox.showerror("Şifreleme Hatası", str(e))
                return
        
        enc_time = time.time() - start_time
        
        # Gönderme (Yeni socket açıp atalım, mevcut listener socket'i sadece dinleme için)
        # Server relay için tek bir bağlantı yeterli aslında ama basitlik için gönder-kapat yapıyoruz
        # ANCAK: Server relay mantığında, gönderen kişinin kim olduğunu server'ın bilmesi için
        # Listener socket üzerinden göndermek en mantıklısı.
        # Fakat Listener socket 'recv' bloğunda kilitli.
        # Çözüm: Ayrı bir socket açıp gönderelim. Server göndereni IP'den tanır.
        
        try:
            s_send = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s_send.connect((self.target_ip.get(), int(self.target_port.get())))
            
            payload = {
                'type': 'crypto_message',
                'target_ip': target_ip,
                'sender_username': self.username.get(), # Kimlik
                'message': encrypted_text, # Server log için
                'encrypted_content': encrypted_text, # İletim için
                'crypto_method': method,
                'key': 'HIDDEN_FOR_SECURITY' if method in ['RSA', 'ECC'] else encryption_key, # RSA anahtarını logda gösterme veya sembolik
                'timestamp': str(datetime.now())

            }
            
            s_send.send(json.dumps(payload).encode('utf-8'))
            s_send.close()
            
            self.log(f"Sen: {msg_text}", 'sent')
            self.log(f"Bilgi: Şifreleme {enc_time:.5f}s sürdü", 'system')
            self.msg_entry.delete(0, tk.END)
            
        except Exception as e:
            messagebox.showerror("Gönderim Hatası", f"Server'a ulaşılamadı: {e}")

    def send_file(self):
        """Dosya Seçip Gönderme"""
        file_path = filedialog.askopenfilename(title="Gönderilecek Dosyayı Seç")
        if not file_path: return
        
        filename = os.path.basename(file_path)
        
        # Dosya limit kontrolü (Örn 5MB)
        if os.path.getsize(file_path) > 5 * 1024 * 1024:
             messagebox.showwarning("Uyarı", "Dosya çok büyük! (Max 5MB)")
             return

        try:
            # 1. Dosyayı Oku (Binary)
            with open(file_path, "rb") as f:
                file_data = f.read()
            
            # 2. Base64'e çevir (Transport için)
            b64_data = base64.b64encode(file_data).decode('utf-8')
            
            # 3. Şifrele
            method = self.crypto_method.get()
            key = self.key_var.get()
            encryption_key = key
            
            if method in ["RSA", "ECC"]:
                encryption_key = key # Public Key
                if not encryption_key:
                    messagebox.showwarning("Uyarı", "Public Key girilmemiş!")
                    return
            else:
                encryption_key = self._ensure_key_length(key, method)
                
            encrypted_content = ""
            if encrypt_message:
                use_lib = True if method in ["AES", "DES"] else False # Büyük veri için lib tercih et
                if method in ["AES", "DES"]:
                    encrypted_content = encrypt_message(b64_data, method, encryption_key, use_lib=use_lib)
                else:
                    encrypted_content = encrypt_message(b64_data, method, encryption_key)
            
            # 4. Gönder
            s_send = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s_send.connect((self.target_ip.get(), int(self.target_port.get())))
            
            payload = {
                'type': 'file_message',
                'target_ip': self.dest_ip.get(),
                'sender_username': self.username.get(),
                'filename': filename,
                'encrypted_content': encrypted_content,
                'crypto_method': method,
                'timestamp': str(datetime.now())
            }
            
            # Büyük verilerde sendall kullanmak daha güvenli
            s_send.sendall(json.dumps(payload).encode('utf-8'))
            s_send.close()
            
            self.log(f"Sen: [DOSYA] {filename}", 'sent')
            
        except Exception as e:
            messagebox.showerror("Dosya Gönderme Hatası", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoChatGUI(root)
    root.mainloop()
