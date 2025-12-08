"""
Model - Mesaj verilerini tutan sınıflar
"""
from datetime import datetime
from typing import Optional, List
from dataclasses import dataclass, field


@dataclass
class Message:
    """Mesaj modeli"""
    id: int
    sender_ip: str
    encrypted_content: str
    decrypted_content: Optional[str] = None
    crypto_method: Optional[str] = None
    key: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    is_decrypted: bool = False
    
    def to_dict(self) -> dict:
        """Mesajı dictionary'ye çevir"""
        return {
            'id': self.id,
            'sender_ip': self.sender_ip,
            'encrypted_content': self.encrypted_content,
            'decrypted_content': self.decrypted_content,
            'crypto_method': self.crypto_method,
            'key': self.key,
            'timestamp': self.timestamp.isoformat(),
            'is_decrypted': self.is_decrypted
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'Message':
        """Dictionary'den mesaj oluştur"""
        timestamp = datetime.fromisoformat(data['timestamp']) if isinstance(data.get('timestamp'), str) else data.get('timestamp', datetime.now())
        return cls(
            id=data['id'],
            sender_ip=data['sender_ip'],
            encrypted_content=data['encrypted_content'],
            decrypted_content=data.get('decrypted_content'),
            crypto_method=data.get('crypto_method'),
            key=data.get('key'),
            timestamp=timestamp,
            is_decrypted=data.get('is_decrypted', False)
        )


class MessageRepository:
    """Mesaj verilerini yöneten repository"""
    
    def __init__(self):
        self._messages: List[Message] = []
        self._next_id = 1
    
    def add_message(self, sender_ip: str, encrypted_content: str, 
                   crypto_method: Optional[str] = None, 
                   key: Optional[str] = None) -> Message:
        """Yeni mesaj ekle"""
        message = Message(
            id=self._next_id,
            sender_ip=sender_ip,
            encrypted_content=encrypted_content,
            crypto_method=crypto_method,
            key=key
        )
        self._messages.append(message)
        self._next_id += 1
        return message
    
    def get_message(self, message_id: int) -> Optional[Message]:
        """ID'ye göre mesaj bul"""
        for msg in self._messages:
            if msg.id == message_id:
                return msg
        return None
    
    def get_all_messages(self) -> List[Message]:
        """Tüm mesajları getir"""
        return self._messages.copy()
    
    def update_message(self, message_id: int, decrypted_content: str) -> bool:
        """Mesajı güncelle (şifre çözme)"""
        message = self.get_message(message_id)
        if message:
            message.decrypted_content = decrypted_content
            message.is_decrypted = True
            return True
        return False
    
    def delete_message(self, message_id: int) -> bool:
        """Mesajı sil"""
        message = self.get_message(message_id)
        if message:
            self._messages.remove(message)
            return True
        return False
    
    def clear_all(self):
        """Tüm mesajları temizle"""
        self._messages.clear()
        self._next_id = 1

