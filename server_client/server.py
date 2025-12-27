import socket
import threading
import json
import time
from datetime import datetime

class CryptoServer:
    def __init__(self, host='127.0.0.1', port=8080):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        
        # Aktif Socket haritası: "IP:Port" -> Socket Obj
        self.active_clients = {} 
        self.clients_lock = threading.Lock()
        
        # Standart log ve eski usul queue (Gerekirse)
        self.message_queue = []
        self.message_lock = threading.Lock()
        
    def start_server(self):
        """Server'ı başlat"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            print(f"🔐 Kriptoloji ARA SUNUCU (Relay) başlatıldı!")
            print(f"📍 Adres: {self.host}:{self.port}")
            print(f"⏰ Başlatma zamanı: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("🔄 Client bağlantıları bekleniyor...\n")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    
                    # Client'ı aktif listeye hemen kaydetme (Handshake bekleyebiliriz ama şimdilik IP ile kaydedelim)
                    # Gerçek port client'ın 'bind' portu değil, 'source' portudur.
                    # Ancak biz mesajlaşmada hedef olarak kullanıcının SERVER'a bağlandığı portu değil,
                    # Kendi dinlediği bir port varsa onu kullanabiliriz.
                    # BASİT SENARYO: Server üzerinden router mantığı.
                    
                    client_id = f"{client_address[0]}:{client_address[1]}"
                    print(f"✅ Yeni bağlantı kabul edildi: {client_id}")
                    
                    with self.clients_lock:
                        self.active_clients[client_id] = client_socket
                    
                    # Her client için ayrı thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address, client_id)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.error as e:
                    if self.running:
                        print(f"❌ Server hatası: {e}")
                    break
                    
        except Exception as e:
            print(f"❌ Server başlatma hatası: {e}")
        finally:
            self.stop_server()
    
    def handle_client(self, client_socket, client_address, client_id):
        """Client ile iletişimi yönet"""
        try:
            client_socket.settimeout(None) # Timeout kapalı, sürekli bağlantı
            
            buffer = ""
            while self.running:
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    
                    buffer += data.decode('utf-8')
                    
                    while True:
                        try:
                            # JSON parse denemesi
                            message, idx = getattr(json, 'JSONDecoder')().raw_decode(buffer)
                            
                            # Başarılı olursa buffer'dan sil
                            buffer = buffer[idx:].lstrip()
                            
                            self.process_message(client_socket, client_address, message, client_id)
                            
                        except ValueError:
                            # Tam bir JSON yoksa devam et (daha fazla veri bekle)
                            break
                        
                except socket.error as e:
                    print(f"❌ Socket hatası {client_id}: {e}")
                    break
                    
        except Exception as e:
            print(f"❌ Client {client_id} thread hatası: {e}")
        finally:
            print(f"🔌 Client {client_id} ayrıldı")
            with self.clients_lock:
                if client_id in self.active_clients:
                    del self.active_clients[client_id]
            try:
                client_socket.close()
            except:
                pass

    
    def process_message(self, client_socket, client_address, message, sender_id):
        """Gelen mesajı işle ve YÖNLENDİR"""
        message_type = message.get('type', 'unknown')
        
        # print(f"📨 [{sender_id}] İşlem: {message_type}")
        
        if message_type == 'crypto_message' or message_type == 'file_message':
            self.handle_relay_message(client_socket, message, sender_id)
        elif message_type == 'register':
            # Client kendi dinlediği portu veya kimliğini bildirebilir
            pass 
        elif message_type == 'ping':
             # Ping cevabı
             client_socket.send(json.dumps({'type': 'pong'}).encode('utf-8'))
        else:
            # Geriye dönük uyumluluk veya diğer işlemler
            pass
            
    def handle_relay_message(self, sender_socket, message, sender_id):
        """Mesajı HEDEF'e ilet"""
        target_ip = message.get('target_ip') # Hedef IP (Örn: 127.0.0.1)
        # target_port = message.get('target_port') # Opsiyonel: Hedef belirli bir portsa
        
        # Mesajı zenginleştir (Server Timestamp ekle)
        message['server_relayed_at'] = datetime.now().isoformat()
        message['sender_id'] = sender_id
        
        # YÖNLENDİRME MANTIĞI:
        # Eğer hedef belirtilmişse, active_clients içinde o IP'ye sahip olanları bul.
        # Eğer hedef yoksa (Broadcast), gönderen hariç herkese at.
        
        relay_count = 0
        with self.clients_lock:
            for cid, sock in self.active_clients.items():
                # Gönderene geri atma (Broadcast durumunda)
                if cid == sender_id:
                    continue
                
                # Eğer hedef IP belirtilmişse ve uyuşmuyorsa atlama
                if target_ip and not cid.startswith(target_ip):
                     # Burada port eşleşmesi de yapılabilir ama genelde client'ın çıkış portu rastgeledir.
                     # Bu yüzden sadece IP eşleşmesi şu aşamada mantıklı (Localhost için herkes 127.0.0.1 olsa da)
                     # Local test için 'target_port' desteği eklemek şart olabilir.
                     continue
                
                try:
                    sock.sendall(json.dumps(message).encode('utf-8'))
                    relay_count += 1
                except Exception as e:
                    print(f"Hata Relay -> {cid}: {e}")
                    
        # Gönderene "İletildi" bilgisi dön
        response = {
            'type': 'ack',
            'status': 'relayed',
            'count': relay_count,
            'timestamp': datetime.now().isoformat()
        }
        try:
            sender_socket.send(json.dumps(response).encode('utf-8'))
            print(f"🔀 Mesaj yönlendirildi: {sender_id} -> {relay_count} kişi")
        except:
            pass

    def stop_server(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        print("🛑 Server durduruldu")

def main():
    server = CryptoServer()
    try:
        server.start_server()
    except KeyboardInterrupt:
        server.stop_server()

if __name__ == "__main__":
    main()
