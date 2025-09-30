import socket

# Sunucu bilgileri
HOST = '127.0.0.1'  # localhost
PORT = 5000         # Sunucu port numarası

# Socket oluştur
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Sunucuya bağlan
print(f"Sunucuya bağlanılıyor: {HOST}:{PORT}")
client_socket.connect((HOST, PORT))
print("Bağlantı kuruldu!")

# Kullanıcıdan veri al
message = input("Sunucuya göndermek istediğiniz veriyi girin: ")

# Sunucuya veri gönder
client_socket.send(message.encode('utf-8'))
print(f"Gönderilen veri: {message}")

# Sunucudan yanıt al
response = client_socket.recv(1024).decode('utf-8')
print(f"Sunucudan gelen yanıt: {response}")

# Bağlantıyı kapat
client_socket.close()
print("Bağlantı kapatıldı")