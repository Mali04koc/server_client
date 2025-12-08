"""
Main - Client GUI ana dosyası
"""
import tkinter as tk
import sys
import os

# Proje root dizini
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from client_gui.model import MessageRepository
from client_gui.view import ClientGUIView
from client_gui.controller import ClientGUIController


def main():
    """Ana fonksiyon"""
    # Root window oluştur
    root = tk.Tk()
    
    # Model, View, Controller oluştur
    model = MessageRepository()
    view = ClientGUIView(root)
    controller = ClientGUIController(view, model)
    
    # Örnek mesajlar ekle (test için)
    # Gerçek uygulamada bu mesajlar server'dan gelecek
    controller.add_message(
        sender_ip="192.168.1.100",
        encrypted_content="Khoor Zruog!",
        crypto_method="Sezar Şifresi",
        key="3"
    )
    
    controller.add_message(
        sender_ip="192.168.1.101",
        encrypted_content="Bu bir şifreli mesajdır",
        crypto_method="Vigenere Şifresi",
        key="KEY"
    )
    
    controller.add_message(
        sender_ip="10.0.0.50",
        encrypted_content="Test mesajı 123",
        crypto_method=None,
        key=None
    )
    
    # GUI'yi başlat
    root.mainloop()


if __name__ == "__main__":
    main()

