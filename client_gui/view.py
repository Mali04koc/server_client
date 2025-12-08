"""
View - GUI görünümü (tkinter)
"""
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from typing import Optional, Callable
from datetime import datetime


class ClientGUIView:
    """Client GUI görünümü"""
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Kriptoloji - Mesaj Alıcı Arayüzü")
        self.root.geometry("1000x700")
        self.root.configure(bg='#f0f0f0')
        
        # Callback'ler
        self.on_decrypt_callback: Optional[Callable] = None
        self.on_delete_callback: Optional[Callable] = None
        self.on_clear_all_callback: Optional[Callable] = None
        self.on_refresh_callback: Optional[Callable] = None
        self.on_message_select_callback: Optional[Callable] = None
        
        self._create_widgets()
    
    def _create_widgets(self):
        """Widget'ları oluştur"""
        # Ana frame
        main_frame = tk.Frame(self.root, bg='#f0f0f0', padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Başlık
        title_label = tk.Label(
            main_frame, 
            text="Kriptoloji - Mesaj Alıcı Sistemi", 
            font=('Arial', 18, 'bold'), 
            bg='#f0f0f0', 
            fg='#2c3e50'
        )
        title_label.pack(pady=(0, 20))
        
        # Butonlar frame
        button_frame = tk.Frame(main_frame, bg='#f0f0f0')
        button_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Yenile butonu
        self.refresh_button = tk.Button(
            button_frame,
            text="Yenile",
            font=('Arial', 10, 'bold'),
            bg='#3498db',
            fg='white',
            command=self._on_refresh,
            width=12,
            height=1
        )
        self.refresh_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Temizle butonu
        self.clear_button = tk.Button(
            button_frame,
            text="Tumunu Temizle",
            font=('Arial', 10, 'bold'),
            bg='#e74c3c',
            fg='white',
            command=self._on_clear_all,
            width=15,
            height=1
        )
        self.clear_button.pack(side=tk.LEFT)
        
        # Mesaj listesi frame
        list_frame = tk.LabelFrame(
            main_frame,
            text="Gelen Mesajlar",
            font=('Arial', 12, 'bold'),
            bg='#f0f0f0',
            fg='#34495e'
        )
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # Treeview (mesaj listesi)
        columns = ('ID', 'Gonderen IP', 'Mesaj (Ozet)', 'Zaman', 'Durum')
        self.message_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=10)
        
        # Sütun başlıkları
        self.message_tree.heading('ID', text='ID')
        self.message_tree.heading('Gonderen IP', text='Gonderen IP')
        self.message_tree.heading('Mesaj (Ozet)', text='Mesaj (Ozet)')
        self.message_tree.heading('Zaman', text='Zaman')
        self.message_tree.heading('Durum', text='Durum')
        
        # Sütun genişlikleri
        self.message_tree.column('ID', width=50, anchor='center')
        self.message_tree.column('Gonderen IP', width=150, anchor='center')
        self.message_tree.column('Mesaj (Ozet)', width=300, anchor='w')
        self.message_tree.column('Zaman', width=150, anchor='center')
        self.message_tree.column('Durum', width=100, anchor='center')
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.message_tree.yview)
        self.message_tree.configure(yscrollcommand=scrollbar.set)
        
        self.message_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
        
        # Seçim eventi
        self.message_tree.bind('<<TreeviewSelect>>', self._on_message_select)
        
        # Mesaj detayları frame
        detail_frame = tk.LabelFrame(
            main_frame,
            text="Mesaj Detaylari",
            font=('Arial', 12, 'bold'),
            bg='#f0f0f0',
            fg='#34495e'
        )
        detail_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # Detay içeriği
        detail_content = tk.Frame(detail_frame, bg='#f0f0f0')
        detail_content.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # IP bilgisi
        ip_frame = tk.Frame(detail_content, bg='#f0f0f0')
        ip_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(
            ip_frame,
            text="Gonderen IP:",
            font=('Arial', 10, 'bold'),
            bg='#f0f0f0',
            fg='#2c3e50'
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        self.ip_label = tk.Label(
            ip_frame,
            text="-",
            font=('Arial', 10),
            bg='#f0f0f0',
            fg='#34495e'
        )
        self.ip_label.pack(side=tk.LEFT)
        
        # Şifreleme yöntemi
        method_frame = tk.Frame(detail_content, bg='#f0f0f0')
        method_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(
            method_frame,
            text="Sifreleme Yontemi:",
            font=('Arial', 10, 'bold'),
            bg='#f0f0f0',
            fg='#2c3e50'
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        self.method_label = tk.Label(
            method_frame,
            text="-",
            font=('Arial', 10),
            bg='#f0f0f0',
            fg='#34495e'
        )
        self.method_label.pack(side=tk.LEFT)
        
        # Key bilgisi
        key_frame = tk.Frame(detail_content, bg='#f0f0f0')
        key_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(
            key_frame,
            text="Key:",
            font=('Arial', 10, 'bold'),
            bg='#f0f0f0',
            fg='#2c3e50'
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        self.key_label_detail = tk.Label(
            key_frame,
            text="-",
            font=('Arial', 10),
            bg='#f0f0f0',
            fg='#34495e'
        )
        self.key_label_detail.pack(side=tk.LEFT)
        
        # Şifreli mesaj
        tk.Label(
            detail_content,
            text="Sifreli Mesaj:",
            font=('Arial', 10, 'bold'),
            bg='#f0f0f0',
            fg='#2c3e50'
        ).pack(anchor='w', pady=(0, 5))
        
        self.encrypted_text = scrolledtext.ScrolledText(
            detail_content,
            height=5,
            font=('Arial', 10),
            wrap=tk.WORD,
            bg='white',
            fg='#2c3e50',
            state='disabled'
        )
        self.encrypted_text.pack(fill=tk.X, pady=(0, 10))
        
        # Çözülmüş mesaj
        tk.Label(
            detail_content,
            text="Cozulmus Mesaj:",
            font=('Arial', 10, 'bold'),
            bg='#f0f0f0',
            fg='#2c3e50'
        ).pack(anchor='w', pady=(0, 5))
        
        self.decrypted_text = scrolledtext.ScrolledText(
            detail_content,
            height=5,
            font=('Arial', 10),
            wrap=tk.WORD,
            bg='#ecf0f1',
            fg='#27ae60',
            state='disabled'
        )
        self.decrypted_text.pack(fill=tk.X, pady=(0, 10))
        
        # Butonlar
        action_frame = tk.Frame(detail_content, bg='#f0f0f0')
        action_frame.pack(fill=tk.X)
        
        self.decrypt_button = tk.Button(
            action_frame,
            text="Mesaji Coz",
            font=('Arial', 12, 'bold'),
            bg='#27ae60',
            fg='white',
            command=self._on_decrypt,
            width=15,
            height=2,
            state='disabled'
        )
        self.decrypt_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.delete_button = tk.Button(
            action_frame,
            text="Mesaji Sil",
            font=('Arial', 12, 'bold'),
            bg='#e74c3c',
            fg='white',
            command=self._on_delete,
            width=15,
            height=2,
            state='disabled'
        )
        self.delete_button.pack(side=tk.LEFT)
        
        # Durum çubuğu
        self.status_label = tk.Label(
            main_frame,
            text="Hazir",
            font=('Arial', 10),
            bg='#f0f0f0',
            fg='#27ae60'
        )
        self.status_label.pack(pady=(10, 0))
    
    def _on_message_select(self, event):
        """Mesaj seçildiğinde"""
        selection = self.message_tree.selection()
        if selection:
            item = self.message_tree.item(selection[0])
            message_id = int(item['values'][0])
            
            # Mesaj detaylarını göster (callback ile)
            if hasattr(self, 'on_message_select_callback') and self.on_message_select_callback:
                self.on_message_select_callback(message_id)
            
            # Butonları aktif et
            if item['values'][4] == "Cozuldu":  # Durum kontrolü
                self.decrypt_button.config(state='disabled', text="Cozuldu")
            else:
                self.decrypt_button.config(state='normal', text="Mesaji Coz")
            self.delete_button.config(state='normal')
        else:
            self.decrypt_button.config(state='disabled')
            self.delete_button.config(state='disabled')
            self.clear_message_details()
    
    def _on_decrypt(self):
        """Çöz butonuna tıklandığında"""
        selection = self.message_tree.selection()
        if selection and self.on_decrypt_callback:
            item = self.message_tree.item(selection[0])
            message_id = int(item['values'][0])
            self.on_decrypt_callback(message_id)
    
    def _on_delete(self):
        """Sil butonuna tıklandığında"""
        selection = self.message_tree.selection()
        if selection and self.on_delete_callback:
            item = self.message_tree.item(selection[0])
            message_id = int(item['values'][0])
            if messagebox.askyesno("Onay", "Bu mesaji silmek istediginize emin misiniz?"):
                self.on_delete_callback(message_id)
    
    def _on_clear_all(self):
        """Tümünü temizle butonuna tıklandığında"""
        if self.on_clear_all_callback:
            if messagebox.askyesno("Onay", "Tum mesajlari silmek istediginize emin misiniz?"):
                self.on_clear_all_callback()
    
    def _on_refresh(self):
        """Yenile butonuna tıklandığında"""
        if self.on_refresh_callback:
            self.on_refresh_callback()
    
    def set_decrypt_callback(self, callback: Callable):
        """Çöz callback'ini ayarla"""
        self.on_decrypt_callback = callback
    
    def set_delete_callback(self, callback: Callable):
        """Sil callback'ini ayarla"""
        self.on_delete_callback = callback
    
    def set_clear_all_callback(self, callback: Callable):
        """Tümünü temizle callback'ini ayarla"""
        self.on_clear_all_callback = callback
    
    def set_refresh_callback(self, callback: Callable):
        """Yenile callback'ini ayarla"""
        self.on_refresh_callback = callback
    
    def set_message_select_callback(self, callback: Callable):
        """Mesaj seçildiğinde çağrılacak callback'i ayarla"""
        self.on_message_select_callback = callback
    
    def update_message_list(self, messages: list):
        """Mesaj listesini güncelle"""
        # Mevcut öğeleri temizle
        for item in self.message_tree.get_children():
            self.message_tree.delete(item)
        
        # Yeni mesajları ekle
        for msg in messages:
            # Mesaj özeti (ilk 50 karakter)
            content_preview = msg.encrypted_content[:50]
            if len(msg.encrypted_content) > 50:
                content_preview += "..."
            
            # Zaman formatı
            time_str = msg.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            
            # Durum
            status = "Cozuldu" if msg.is_decrypted else "Sifreli"
            
            self.message_tree.insert(
                '',
                tk.END,
                values=(
                    msg.id,
                    msg.sender_ip,
                    content_preview,
                    time_str,
                    status
                )
            )
    
    def show_message_details(self, message):
        """Mesaj detaylarını göster"""
        # IP adresi
        ip_text = message.sender_ip if message.sender_ip else "-"
        self.ip_label.config(text=ip_text)
        
        # Şifreleme yöntemi
        method_text = message.crypto_method if message.crypto_method else "-"
        self.method_label.config(text=method_text)
        
        # Key bilgisi
        key_text = message.key if message.key else "-"
        self.key_label_detail.config(text=key_text)
        
        # Şifreli mesaj
        self.encrypted_text.config(state='normal')
        self.encrypted_text.delete('1.0', tk.END)
        self.encrypted_text.insert('1.0', message.encrypted_content or "")
        self.encrypted_text.config(state='disabled')
        
        # Çözülmüş mesaj
        self.decrypted_text.config(state='normal')
        self.decrypted_text.delete('1.0', tk.END)
        if message.is_decrypted and message.decrypted_content:
            self.decrypted_text.insert('1.0', message.decrypted_content)
            self.decrypt_button.config(state='disabled', text="Cozuldu")
        else:
            self.decrypted_text.insert('1.0', "Mesaj henuz cozulmedi...\n\nMesaji cozmek icin 'Mesaji Coz' butonuna tiklayin.")
            # Şifreleme yöntemi varsa butonu aktif et
            if message.crypto_method:
                self.decrypt_button.config(state='normal', text="Mesaji Coz")
            else:
                self.decrypt_button.config(state='disabled', text="Sifreleme yontemi yok")
        self.decrypted_text.config(state='disabled')
    
    def clear_message_details(self):
        """Mesaj detaylarını temizle"""
        self.ip_label.config(text="-")
        self.method_label.config(text="-")
        self.key_label_detail.config(text="-")
        
        self.encrypted_text.config(state='normal')
        self.encrypted_text.delete('1.0', tk.END)
        self.encrypted_text.config(state='disabled')
        
        self.decrypted_text.config(state='normal')
        self.decrypted_text.delete('1.0', tk.END)
        self.decrypted_text.config(state='disabled')
        
        self.decrypt_button.config(state='disabled', text="Mesaji Coz")
        self.delete_button.config(state='disabled')
    
    def update_status(self, text: str, color: str = '#27ae60'):
        """Durum çubuğunu güncelle"""
        self.status_label.config(text=text, fg=color)
    
    def show_error(self, message: str):
        """Hata mesajı göster"""
        messagebox.showerror("Hata", message)
    
    def show_info(self, message: str):
        """Bilgi mesajı göster"""
        messagebox.showinfo("Bilgi", message)

