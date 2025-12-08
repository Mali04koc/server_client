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
        self.clients = []
        self.running = False
        # Mesajları saklamak için liste ve lock
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
            
            print(f"🔐 Kriptoloji Server başlatıldı!")
            print(f"📍 Adres: {self.host}:{self.port}")
            print(f"⏰ Başlatma zamanı: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("🔄 Client bağlantıları bekleniyor...\n")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    print(f"✅ Yeni client bağlandı: {client_address}")
                    
                    # Client'ı listeye ekle
                    self.clients.append(client_address)
                    
                    # Her client için ayrı thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.error as e:
                    if self.running:
                        print(f"❌ Server hatası: {e}")
                    break
                except OSError as e:
                    if self.running:
                        print(f"❌ Server hatası: {e}")
                    break
                    
        except Exception as e:
            print(f"❌ Server başlatma hatası: {e}")
        finally:
            self.stop_server()
    
    def handle_client(self, client_socket, client_address):
        """Client ile iletişimi yönet"""
        try:
            # Socket timeout ayarla (30 saniye)
            client_socket.settimeout(30.0)
            
            while self.running:
                try:
                    # Mesaj al
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    
                    try:
                        # JSON mesajı parse et
                        message = json.loads(data.decode('utf-8'))
                        self.process_message(client_socket, client_address, message)
                        
                    except json.JSONDecodeError:
                        # JSON değilse düz metin olarak işle
                        message_text = data.decode('utf-8')
                        print(f"📨 [{client_address}] Düz metin: {message_text}")
                        
                        # Echo mesajı gönder
                        response = {
                            'type': 'echo',
                            'message': f"Server'dan echo: {message_text}",
                            'timestamp': datetime.now().isoformat(),
                            'client': f"{client_address[0]}:{client_address[1]}"
                        }
                        client_socket.send(json.dumps(response).encode('utf-8'))
                        
                except socket.timeout:
                    # Timeout durumunda bağlantıyı kontrol et
                    continue
                except socket.error as e:
                    print(f"❌ Socket hatası {client_address}: {e}")
                    break
                    
        except Exception as e:
            print(f"❌ Client {client_address} hatası: {e}")
        finally:
            print(f"🔌 Client {client_address} bağlantısı kesildi")
            try:
                client_socket.close()
            except:
                pass
            if client_address in self.clients:
                self.clients.remove(client_address)
    
    def process_message(self, client_socket, client_address, message):
        """Gelen mesajı işle"""
        message_type = message.get('type', 'unknown')
        
        print(f"📨 [{client_address}] Mesaj türü: {message_type}")
        
        if message_type == 'crypto_message':
            self.handle_crypto_message(client_socket, client_address, message)
        elif message_type == 'ping':
            self.handle_ping(client_socket, client_address, message)
        elif message_type == 'get_messages':
            self.handle_get_messages(client_socket, client_address, message)
        else:
            self.handle_unknown_message(client_socket, client_address, message)
    
    def handle_crypto_message(self, client_socket, client_address, message):
        """Şifreli mesajı işle"""
        crypto_method = message.get('crypto_method', 'Bilinmiyor')
        original_message = message.get('message', '')
        key = message.get('key', '')
        
        print(f"🔒 Şifreleme yöntemi: {crypto_method}")
        print(f"💬 Mesaj: {original_message}")
        print(f"🔑 Key: {key}")
        
        # Mesajı queue'ya ekle (client_gui için)
        with self.message_lock:
            message_data = {
                'sender_ip': client_address[0],
                'encrypted_content': original_message,
                'crypto_method': crypto_method,
                'key': key,
                'timestamp': datetime.now()
            }
            self.message_queue.append(message_data)
            # Son 100 mesajı tut (bellek yönetimi)
            if len(self.message_queue) > 100:
                self.message_queue.pop(0)
        
        # Server'dan cevap hazırla
        response = {
            'type': 'crypto_response',
            'status': 'success',
            'message': f"Mesajınız alındı ve işlendi!",
            'crypto_method': crypto_method,
            'timestamp': datetime.now().isoformat(),
            'server_info': {
                'host': self.host,
                'port': self.port,
                'processed_at': datetime.now().isoformat()
            }
        }
        
        # Cevabı gönder
        try:
            response_json = json.dumps(response)
            response_bytes = response_json.encode('utf-8')
            client_socket.sendall(response_bytes)  # sendall kullan (tüm veriyi gönder)
            print(f"✅ Cevap gönderildi: {client_address} ({len(response_bytes)} bytes)")
        except BrokenPipeError:
            print(f"⚠️ Client bağlantısı kapanmış: {client_address}")
        except Exception as e:
            print(f"❌ Cevap gönderme hatası {client_address}: {e}")
            import traceback
            traceback.print_exc()
    
    def get_messages(self):
        """Mesaj queue'sunu al"""
        with self.message_lock:
            return self.message_queue.copy()
    
    def clear_messages(self):
        """Mesaj queue'sunu temizle"""
        with self.message_lock:
            self.message_queue.clear()
    
    def handle_ping(self, client_socket, client_address, message):
        """Ping mesajını işle"""
        response = {
            'type': 'pong',
            'message': 'Server aktif!',
            'timestamp': datetime.now().isoformat(),
            'server_time': datetime.now().isoformat()
        }
        try:
            client_socket.sendall(json.dumps(response).encode('utf-8'))
            print(f"🏓 Pong gönderildi: {client_address}")
        except Exception as e:
            print(f"❌ Pong gönderme hatası {client_address}: {e}")
    
    def handle_get_messages(self, client_socket, client_address, message):
        """Mesaj listesini isteyen client'a gönder"""
        try:
            with self.message_lock:
                messages_copy = []
                for msg in self.message_queue:
                    messages_copy.append({
                        'sender_ip': msg['sender_ip'],
                        'encrypted_content': msg['encrypted_content'],
                        'crypto_method': msg.get('crypto_method'),
                        'key': msg.get('key'),
                        'timestamp': msg['timestamp'].isoformat() if hasattr(msg['timestamp'], 'isoformat') else str(msg['timestamp'])
                    })
            
            response = {
                'type': 'messages_response',
                'messages': messages_copy,
                'count': len(messages_copy),
                'timestamp': datetime.now().isoformat()
            }
            client_socket.sendall(json.dumps(response).encode('utf-8'))
            print(f"📬 Mesaj listesi gönderildi: {client_address} ({len(messages_copy)} mesaj)")
        except Exception as e:
            print(f"❌ Mesaj listesi gönderme hatası {client_address}: {e}")
            import traceback
            traceback.print_exc()
    
    def handle_unknown_message(self, client_socket, client_address, message):
        """Bilinmeyen mesaj türünü işle"""
        response = {
            'type': 'error',
            'message': 'Bilinmeyen mesaj türü!',
            'timestamp': datetime.now().isoformat()
        }
        client_socket.send(json.dumps(response).encode('utf-8'))
        print(f"❓ Bilinmeyen mesaj: {client_address}")
    
    def stop_server(self):
        """Server'ı durdur"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        print("🛑 Server durduruldu")

def main():
    print("🚀 Kriptoloji Server Başlatılıyor...")
    
    # Server ayarları
    HOST = '127.0.0.1'
    PORT = 8080
    
    server = CryptoServer(HOST, PORT)
    
    try:
        server.start_server()
    except KeyboardInterrupt:
        print("\n🛑 Server kapatılıyor...")
        server.stop_server()
    except Exception as e:
        print(f"❌ Server hatası: {e}")

if __name__ == "__main__":
    main()
