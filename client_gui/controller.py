"""
Controller - View ve Model arasındaki bağlantıyı kuran sınıf
"""
from typing import Optional
import sys
import os

# Şifre çözme yöntemlerini import et
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

try:
    from crypto_methods import decrypt_message
except ImportError:
    decrypt_message = None
    print("[UYARI] crypto_methods modulu bulunamadi, sifre cozme devre disi")

from .model import Message, MessageRepository
from .view import ClientGUIView
import threading
import time


class ClientGUIController:
    """Client GUI Controller"""
    
    def __init__(self, view: ClientGUIView, model: MessageRepository, server=None):
        self.view = view
        self.model = model
        self.server = server  # Server referansı (mesajları almak için)
        
        # Callback'leri bağla
        self.view.set_decrypt_callback(self.decrypt_message)
        self.view.set_delete_callback(self.delete_message)
        self.view.set_clear_all_callback(self.clear_all_messages)
        self.view.set_refresh_callback(self.refresh_messages)
        self.view.set_message_select_callback(self._show_message_details)
        
        # İlk yükleme
        self.refresh_messages()
        
        # Server'dan mesajları periyodik olarak kontrol et (her zaman başlat)
        self._start_message_listener()
    
    def add_message(self, sender_ip: str, encrypted_content: str,
                   crypto_method: Optional[str] = None,
                   key: Optional[str] = None):
        """Yeni mesaj ekle"""
        message = self.model.add_message(
            sender_ip=sender_ip,
            encrypted_content=encrypted_content,
            crypto_method=crypto_method,
            key=key
        )
        self.refresh_messages()
        self.view.update_status(f"Yeni mesaj alindi: {sender_ip}", '#3498db')
        return message
    
    def decrypt_message(self, message_id: int):
        """Mesajı çöz"""
        message = self.model.get_message(message_id)
        if not message:
            self.view.show_error("Mesaj bulunamadi!")
            return
        
        if message.is_decrypted:
            self.view.show_info("Bu mesaj zaten cozulmus!")
            return
        
        # Şifre çözme işlemi (şimdilik basit bir örnek)
        # Gerçek uygulamada burada şifre çözme algoritması olacak
        try:
            decrypted = self._decrypt_content(
                message.encrypted_content,
                message.crypto_method,
                message.key
            )
            
            self.model.update_message(message_id, decrypted)
            self.refresh_messages()
            self._show_message_details(message_id)
            self.view.update_status("Mesaj basariyla cozuldu!", '#27ae60')
        except Exception as e:
            self.view.show_error(f"Mesaj cozulemedi: {str(e)}")
            self.view.update_status("Mesaj cozme hatasi!", '#e74c3c')
    
    def _decrypt_content(self, encrypted_content: str, 
                         crypto_method: Optional[str],
                         key: Optional[str]) -> str:
        """
        Şifre çözme işlemi
        """
        if not crypto_method:
            # Şifreleme yöntemi belirtilmemişse, mesajı olduğu gibi döndür
            return encrypted_content
        
        # crypto_methods modülünü kullan
        if decrypt_message:
            try:
                return decrypt_message(encrypted_content, crypto_method, key)
            except Exception as e:
                raise ValueError(f"Şifre çözme hatası: {str(e)}")
        else:
            # Modül yüklenememişse, mesajı olduğu gibi döndür
            return encrypted_content
    
    def delete_message(self, message_id: int):
        """Mesajı sil"""
        if self.model.delete_message(message_id):
            self.refresh_messages()
            self.view.clear_message_details()
            self.view.update_status("Mesaj silindi!", '#e74c3c')
        else:
            self.view.show_error("Mesaj silinemedi!")
    
    def clear_all_messages(self):
        """Tüm mesajları temizle"""
        self.model.clear_all()
        self.refresh_messages()
        self.view.clear_message_details()
        self.view.update_status("Tum mesajlar temizlendi!", '#e74c3c')
    
    def refresh_messages(self):
        """Mesaj listesini yenile"""
        messages = self.model.get_all_messages()
        self.view.update_message_list(messages)
        
        # Seçili mesaj varsa detaylarını göster
        selection = self.view.message_tree.selection()
        if selection:
            item = self.view.message_tree.item(selection[0])
            message_id = int(item['values'][0])
            self._show_message_details(message_id)
        else:
            self.view.clear_message_details()
        
        self.view.update_status(f"Toplam {len(messages)} mesaj", '#27ae60')
    
    def _show_message_details(self, message_id: int):
        """Mesaj detaylarını göster"""
        message = self.model.get_message(message_id)
        if message:
            self.view.show_message_details(message)
        else:
            self.view.clear_message_details()
    
    def get_selected_message_id(self) -> Optional[int]:
        """Seçili mesaj ID'sini al"""
        selection = self.view.message_tree.selection()
        if selection:
            item = self.view.message_tree.item(selection[0])
            return int(item['values'][0])
        return None
    
    def _start_message_listener(self):
        """Server'dan mesajları dinle"""
        def listener():
            last_message_count = 0
            while True:
                try:
                    if self.server:
                        # Server'dan yeni mesajları al (doğrudan instance üzerinden)
                        try:
                            server_messages = self.server.get_messages()
                            
                            # Yeni mesajları kontrol et
                            if len(server_messages) > last_message_count:
                                # Yeni mesajlar var
                                new_messages = server_messages[last_message_count:]
                                
                                for msg_data in new_messages:
                                    # Yeni mesaj ekle
                                    self.model.add_message(
                                        sender_ip=msg_data['sender_ip'],
                                        encrypted_content=msg_data['encrypted_content'],
                                        crypto_method=msg_data.get('crypto_method'),
                                        key=msg_data.get('key')
                                    )
                                
                                last_message_count = len(server_messages)
                                
                                # GUI'yi güncelle
                                self.view.root.after(0, self.refresh_messages)
                        except (AttributeError, Exception) as e:
                            # Server instance'ı yok veya hata, socket ile bağlanmayı dene
                            new_count = self._connect_to_server_for_messages(last_message_count)
                            if new_count > last_message_count:
                                last_message_count = new_count
                    else:
                        # Server yok, socket ile bağlanmayı dene
                        new_count = self._connect_to_server_for_messages(last_message_count)
                        if new_count > last_message_count:
                            last_message_count = new_count
                    
                    time.sleep(1)  # 1 saniyede bir kontrol et
                except Exception as e:
                    print(f"[HATA] Message listener hatasi: {e}")
                    import traceback
                    traceback.print_exc()
                    time.sleep(2)
        
        # Listener thread'ini başlat
        listener_thread = threading.Thread(target=listener, daemon=True)
        listener_thread.start()
    
    def _connect_to_server_for_messages(self, last_count=0):
        """Server'a socket ile bağlanıp mesajları al"""
        try:
            import socket
            import json
            from datetime import datetime
            
            # Server'a bağlan
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect(('127.0.0.1', 8080))
            
            # Mesaj listesini iste
            request = {
                'type': 'get_messages',
                'timestamp': datetime.now().isoformat()
            }
            sock.sendall(json.dumps(request).encode('utf-8'))
            
            # Cevabı al
            sock.settimeout(3)
            data = sock.recv(8192)
            sock.close()
            
            if data:
                response = json.loads(data.decode('utf-8'))
                if response.get('type') == 'messages_response':
                    messages = response.get('messages', [])
                    
                    # Yeni mesajları kontrol et
                    if len(messages) > last_count:
                        # Yeni mesajlar var
                        new_messages = messages[last_count:]
                        for msg_data in new_messages:
                            # Timestamp'i datetime'a çevir
                            timestamp = msg_data.get('timestamp')
                            if isinstance(timestamp, str):
                                try:
                                    from datetime import datetime
                                    timestamp = datetime.fromisoformat(timestamp)
                                except:
                                    timestamp = datetime.now()
                            
                            self.model.add_message(
                                sender_ip=msg_data['sender_ip'],
                                encrypted_content=msg_data['encrypted_content'],
                                crypto_method=msg_data.get('crypto_method'),
                                key=msg_data.get('key')
                            )
                        
                        # GUI'yi güncelle
                        self.view.root.after(0, self.refresh_messages)
                        return len(messages)
            
            return last_count
        except Exception as e:
            # Bağlantı hatası, sessizce devam et
            return last_count

