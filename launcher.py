"""
Bu dosyayı çalıştırın: python launcher.py
Server ve GUI birlikte başlayacak!
"""
import threading
import time
import sys
import os

# Windows encoding sorununu çöz
if sys.platform == 'win32':
    import io
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    except:
        pass

# Proje root dizini
project_root = os.path.dirname(os.path.abspath(__file__))

# Server modülünü import et
server_client_dir = os.path.join(project_root, 'server_client')
server_client_dir = os.path.normpath(server_client_dir)
if server_client_dir not in sys.path:
    sys.path.insert(0, server_client_dir)

try:
    from server_client.server import CryptoServer
    print("[OK] Server modulu yuklendi")
except ImportError as e:
    print(f"[HATA] Server modulu yuklenemedi: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# GUI modülünü import et
gui_dir = os.path.join(project_root, 'GUI')
gui_dir = os.path.normpath(gui_dir)
if gui_dir not in sys.path:
    sys.path.insert(0, gui_dir)

try:
    import tkinter as tk
    from GUI.crypto_gui import CryptoGUI
    print("[OK] GUI modulu yuklendi")
except ImportError as e:
    print(f"[HATA] GUI modulu yuklenemedi: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

def start_server_thread():
    """Server'ı arka planda başlat"""
    print("[SERVER] Server thread baslatiliyor...")
    try:
        crypto_server = CryptoServer('127.0.0.1', 8080)
        crypto_server.start_server()
    except Exception as e:
        print(f"[HATA] Server hatasi: {e}")
        import traceback
        traceback.print_exc()

def main():
    print("=" * 60)
    print("KRIPTOLOJI SISTEMI BASLATILIYOR")
    print("=" * 60)
    
    # 1. Server'ı thread'de başlat
    server_thread = threading.Thread(target=start_server_thread, daemon=True)
    server_thread.start()
    
    # Server'ın başlaması için kısa bir bekleme
    print("\n[BEKLE] Server baslatiliyor...")
    time.sleep(2)
    print("[OK] Server hazir!\n")
    
    # 2. GUI'yi ana thread'de başlat (otomatik bağlantı ile)
    print("[GUI] GUI aciliyor...\n")
    try:
        root = tk.Tk()
        app = CryptoGUI(root, auto_connect=True)
        root.mainloop()
    except Exception as e:
        print(f"[HATA] GUI hatasi: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n[KAPAT] Program kapatildi")

if __name__ == "__main__":
    main()