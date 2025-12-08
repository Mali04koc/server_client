"""
Main - Client GUI ana dosyası
"""
import tkinter as tk
import sys
import os

# Proje root dizini
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Server modülünü import et (mesajları almak için)
server_client_dir = os.path.join(project_root, 'server_client')
sys.path.insert(0, server_client_dir)

try:
    import importlib.util
    server_file = os.path.join(server_client_dir, "server.py")
    spec = importlib.util.spec_from_file_location("server_module", server_file)
    server_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(server_module)
    CryptoServer = server_module.CryptoServer
except Exception as e:
    print(f"[UYARI] Server modulu yuklenemedi: {e}")
    CryptoServer = None

from client_gui.model import MessageRepository
from client_gui.view import ClientGUIView
from client_gui.controller import ClientGUIController


# Global server instance (launcher'dan gelir)
_global_server = None

def set_server_instance(server):
    """Server instance'ını ayarla (launcher'dan çağrılır)"""
    global _global_server
    _global_server = server


def main():
    """Ana fonksiyon"""
    # Root window oluştur
    root = tk.Tk()
    
    # Model, View, Controller oluştur
    model = MessageRepository()
    view = ClientGUIView(root)
    
    # Server instance'ını al (eğer varsa)
    server = _global_server
    
    # Eğer server yoksa, launcher'dan almayı dene
    if server is None:
        try:
            # Launcher'dan server instance'ını almayı dene
            from launcher import _global_server_instance
            server = _global_server_instance
            if server:
                print("[OK] Server instance launcher'dan alindi")
        except Exception as e:
            print(f"[UYARI] Launcher'dan server instance alinamadi: {e}")
            server = None
    
    # Server yoksa da çalışabilir (socket ile bağlanacak)
    controller = ClientGUIController(view, model, server=server)
    
    # GUI'yi başlat
    root.mainloop()


if __name__ == "__main__":
    main()

