"""Cryptographic functions for secure password storage."""

import os
import base64
from typing import Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


class PasswordCrypto:
    """Handles encryption and decryption of passwords using master password."""
    
    def __init__(self):
        self.ph = PasswordHasher()
    
    def generate_salt(self) -> bytes:
        """Generate a random salt for key derivation."""
        return os.urandom(16)
    
    def derive_key(self, master_password: str, salt: bytes) -> bytes:
        """Derive encryption key from master password and salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return key
    
    def hash_master_password(self, password: str) -> str:
        """Hash master password using Argon2."""
        return self.ph.hash(password)
    
    def verify_master_password(self, password: str, hashed: str) -> bool:
        """Verify master password against stored hash."""
        try:
            self.ph.verify(hashed, password)
            return True
        except VerifyMismatchError:
            return False
    
    def encrypt_password(self, password: str, key: bytes) -> str:
        """Encrypt a password using the derived key."""
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(password.encode())
        return base64.urlsafe_b64encode(encrypted_data).decode()
    
    def decrypt_password(self, encrypted_password: str, key: bytes) -> str:
        """Decrypt a password using the derived key."""
        fernet = Fernet(key)
        encrypted_data = base64.urlsafe_b64decode(encrypted_password.encode())
        decrypted_data = fernet.decrypt(encrypted_data)
        return decrypted_data.decode()
    
    def encrypt_data(self, data: dict, master_password: str, salt: bytes) -> dict:
        """Encrypt password data using master password."""
        key = self.derive_key(master_password, salt)
        encrypted_data = {}
        
        for field in ['password', 'username', 'notes']:
            if field in data and data[field]:
                encrypted_data[field] = self.encrypt_password(data[field], key)
            else:
                encrypted_data[field] = data.get(field, '')
        
        # Service name is not encrypted for searching purposes
        encrypted_data['service'] = data.get('service', '')
        return encrypted_data
    
    def decrypt_data(self, encrypted_data: dict, master_password: str, salt: bytes) -> dict:
        """Decrypt password data using master password."""
        key = self.derive_key(master_password, salt)
        decrypted_data = {}
        
        for field in ['password', 'username', 'notes']:
            if field in encrypted_data and encrypted_data[field]:
                decrypted_data[field] = self.decrypt_password(encrypted_data[field], key)
            else:
                decrypted_data[field] = encrypted_data.get(field, '')
        
        decrypted_data['service'] = encrypted_data.get('service', '')
        return decrypted_data
