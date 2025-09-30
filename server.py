import socket

# Sunucu ayarları
HOST = '127.0.0.1'  # localhost
PORT = 5000         # Port numarası

# Socket oluştur
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)

print(f"Sunucu {HOST}:{PORT} adresinde dinlemeye başladı...")

while True:
    # İstemci bağlantısını kabul et
    client_socket, address = server_socket.accept()
    print(f"\n{address} adresinden bağlantı geldi")
    
    # İstemciden veri al
    data = client_socket.recv(1024).decode('utf-8')
    print(f"İstemciden gelen veri: {data}")
    
    # İstemciye yanıt gönder
    response = f"Veri alındı: '{data}' - Sunucu tarafından işlendi"
    client_socket.send(response.encode('utf-8'))
    
    # Bağlantıyı kapat
    client_socket.close()
    print("Bağlantı kapatıldı")