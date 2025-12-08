import socket
import json
import threading
import time
from datetime import datetime

class CryptoClient:
    def __init__(self):
        self.socket = None
        self.connected = False
        self.host = None
        self.port = None
        
    def connect(self, host, port, timeout=10):
        """Server'a bağlan"""
        try:
            self.host = host
            self.port = port
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(timeout)
            self.socket.connect((host, port))
            # Bağlantı başarılı olduktan sonra timeout'u ayarla (varsayılan 30 saniye)
            self.socket.settimeout(30.0)
            self.connected = True
            
            print(f"✅ Server'a bağlandı: {host}:{port}")
            return True
            
        except socket.timeout:
            print(f"❌ Bağlantı zaman aşımı: {host}:{port}")
            self.connected = False
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
                self.socket = None
            return False
        except ConnectionRefusedError:
            print(f"❌ Bağlantı reddedildi: {host}:{port} - Server çalışmıyor olabilir")
            self.connected = False
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
                self.socket = None
            return False
        except Exception as e:
            print(f"❌ Bağlantı hatası: {e}")
            self.connected = False
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
                self.socket = None
            return False
    
    def disconnect(self):
        """Server bağlantısını kes"""
        self.connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
        print("🔌 Bağlantı kesildi")
    
    def send_message(self, message, crypto_method=None, key=None):
        """Mesaj gönder"""
        if not self.connected or not self.socket:
            print("❌ Bağlantı yok!")
            return False
        
        try:
            # Mesaj paketini hazırla
            message_packet = {
                'type': 'crypto_message',
                'message': message,
                'crypto_method': crypto_method,
                'key': key,
                'timestamp': datetime.now().isoformat(),
                'client_info': {
                    'host': self.host,
                    'port': self.port
                }
            }
            
            # JSON olarak gönder
            json_message = json.dumps(message_packet)
            self.socket.sendall(json_message.encode('utf-8'))  # sendall kullan (tüm veriyi gönder)
            
            print(f"📤 Mesaj gönderildi: {message[:50]}...")
            return True
            
        except socket.error as e:
            print(f"❌ Socket hatası: {e}")
            self.connected = False
            return False
        except Exception as e:
            print(f"❌ Mesaj gönderme hatası: {e}")
            return False
    
    def send_ping(self):
        """Ping gönder"""
        if not self.connected or not self.socket:
            return False
        
        try:
            ping_packet = {
                'type': 'ping',
                'timestamp': datetime.now().isoformat()
            }
            
            json_ping = json.dumps(ping_packet)
            self.socket.send(json_ping.encode('utf-8'))
            print("🏓 Ping gönderildi")
            return True
            
        except socket.error as e:
            print(f"❌ Socket hatası: {e}")
            self.connected = False
            return False
        except Exception as e:
            print(f"❌ Ping hatası: {e}")
            return False
    
    def receive_response(self, timeout=5):
        """Server'dan cevap al"""
        if not self.connected or not self.socket:
            return None
        
        old_timeout = None
        try:
            # Timeout ayarla
            old_timeout = self.socket.gettimeout()
            self.socket.settimeout(timeout)
            
            # Veriyi al
            data = self.socket.recv(4096)
            
            # Timeout'u eski haline getir
            if old_timeout is not None:
                self.socket.settimeout(old_timeout)
            
            if data:
                try:
                    response = json.loads(data.decode('utf-8'))
                    print(f"📨 Server cevabı: {response.get('message', 'Cevap alındı')}")
                    return response
                except json.JSONDecodeError as e:
                    print(f"❌ JSON decode hatası: {e}, Veri: {data[:100]}")
                    return None
            else:
                print("❌ Cevap alınamadı (boş veri)")
                return None
                
        except socket.timeout:
            print("⏰ Cevap zaman aşımı")
            # Timeout'u eski haline getir
            if old_timeout is not None:
                try:
                    self.socket.settimeout(old_timeout)
                except:
                    pass
            return None
        except socket.error as e:
            print(f"❌ Socket hatası: {e}")
            self.connected = False
            return None
        except Exception as e:
            print(f"❌ Cevap alma hatası: {e}")
            return None

def test_client():
    """Client test fonksiyonu"""
    print("🧪 Client Test Başlatılıyor...")
    
    # Client oluştur
    client = CryptoClient()
    
    # Server'a bağlan
    if client.connect('127.0.0.1', 8080):
        print("✅ Bağlantı başarılı!")
        
        # Test mesajları gönder
        test_messages = [
            {
                'message': 'Merhaba Server!',
                'crypto_method': 'Sezar Şifresi',
                'key': '3'
            },
            {
                'message': 'Bu bir test mesajıdır',
                'crypto_method': 'Vigenere Şifresi', 
                'key': 'KEY'
            }
        ]
        
        for test_msg in test_messages:
            print(f"\n📤 Test mesajı gönderiliyor...")
            client.send_message(
                test_msg['message'],
                test_msg['crypto_method'],
                test_msg['key']
            )
            
            # Cevap bekle
            response = client.receive_response()
            if response:
                print(f"✅ Cevap alındı: {response}")
            
            time.sleep(1)  # 1 saniye bekle
        
        # Ping test
        print(f"\n🏓 Ping testi...")
        client.send_ping()
        ping_response = client.receive_response()
        
        # Bağlantıyı kes
        client.disconnect()
        print("✅ Test tamamlandı!")
        
    else:
        print("❌ Bağlantı başarısız!")

def main():
    """Ana fonksiyon - GUI ile entegrasyon için"""
    print("🚀 Kriptoloji Client Başlatılıyor...")
    
    # Test modu
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'test':
        test_client()
    else:
        print("💡 Test için: python client.py test")
        print("💡 GUI entegrasyonu için CryptoClient sınıfını kullanın")

if __name__ == "__main__":
    main()
