"""Tests for cryptographic functions"""

import pytest
from pryva.crypto import PasswordCrypto


class TestPasswordCrypto:
    
    def setup_method(self):
        self.crypto = PasswordCrypto()
    
    def test_generate_salt(self):
        """Test salt generation."""
        salt1 = self.crypto.generate_salt()
        salt2 = self.crypto.generate_salt()
        
        assert len(salt1) == 16
        assert len(salt2) == 16
        assert salt1 != salt2  # Should be random
    
    def test_derive_key(self):
        """Test key derivation."""
        password = "test_password"
        salt = self.crypto.generate_salt()
        
        key1 = self.crypto.derive_key(password, salt)
        key2 = self.crypto.derive_key(password, salt)
        
        assert key1 == key2  # Same password and salt should produce same key
        assert len(key1) == 44  # Base64 encoded 32-byte key
    
    def test_hash_and_verify_master_password(self):
        """Test master password hashing and verification."""
        password = "my_secure_password"
        
        hashed = self.crypto.hash_master_password(password)
        assert hashed != password  # Should be hashed
        
        # Verify correct password
        assert self.crypto.verify_master_password(password, hashed)
        
        # Verify incorrect password
        assert not self.crypto.verify_master_password("wrong_password", hashed)
    
    def test_encrypt_decrypt_password(self):
        """Test password encryption and decryption."""
        password = "secret_password"
        master_password = "master_password"
        salt = self.crypto.generate_salt()
        
        key = self.crypto.derive_key(master_password, salt)
        
        # Encrypt
        encrypted = self.crypto.encrypt_password(password, key)
        assert encrypted != password
        
        # Decrypt
        decrypted = self.crypto.decrypt_password(encrypted, key)
        assert decrypted == password
    
    def test_encrypt_decrypt_data(self):
        """Test data encryption and decryption."""
        data = {
            'service': 'Gmail',
            'username': 'user@example.com',
            'password': 'secret123',
            'notes': 'My email account'
        }
        master_password = "master_password"
        salt = self.crypto.generate_salt()
        
        # Encrypt
        encrypted_data = self.crypto.encrypt_data(data, master_password, salt)
        
        # Service name should not be encrypted
        assert encrypted_data['service'] == data['service']
        
        # Other fields should be encrypted
        assert encrypted_data['username'] != data['username']
        assert encrypted_data['password'] != data['password']
        assert encrypted_data['notes'] != data['notes']
        
        # Decrypt
        decrypted_data = self.crypto.decrypt_data(encrypted_data, master_password, salt)
        
        # Should match original data
        assert decrypted_data == data
