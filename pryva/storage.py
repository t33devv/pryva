"""Database storage for encrypted password entries."""

import sqlite3
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from .crypto import PasswordCrypto


class PasswordStorage:
    """Handles SQLite database operations for password storage."""
    
    def __init__(self, db_path: Optional[str] = None):
        """Initialize database connection."""
        if db_path is None:
            # Store database in user's home directory
            home_dir = Path.home()
            pryva_dir = home_dir / '.pryva'
            pryva_dir.mkdir(exist_ok=True)
            db_path = pryva_dir / 'passwords.db'
        
        self.db_path = str(db_path)
        self.crypto = PasswordCrypto()
        self._init_database()
    
    def _init_database(self):
        """Initialize database tables if they don't exist."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create main passwords table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service TEXT NOT NULL UNIQUE,
                    username TEXT,
                    password TEXT NOT NULL,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create metadata table for storing master password hash and salt
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            ''')
            
            conn.commit()
    
    def is_initialized(self) -> bool:
        """Check if the password vault has been initialized with a master password."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM metadata WHERE key = 'master_hash'")
            result = cursor.fetchone()
            return result is not None
    
    def initialize_vault(self, master_password: str) -> bool:
        """Initialize the vault with a master password."""
        if self.is_initialized():
            return False
        
        # Generate salt and hash master password
        salt = self.crypto.generate_salt()
        master_hash = self.crypto.hash_master_password(master_password)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO metadata (key, value) VALUES ('master_hash', ?)", (master_hash,))
            cursor.execute("INSERT INTO metadata (key, value) VALUES ('salt', ?)", (salt.hex(),))
            conn.commit()
        
        return True
    
    def verify_master_password(self, master_password: str) -> bool:
        """Verify the master password."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM metadata WHERE key = 'master_hash'")
            result = cursor.fetchone()
            
            if not result:
                return False
            
            master_hash = result[0]
            return self.crypto.verify_master_password(master_password, master_hash)
    
    def get_salt(self) -> bytes:
        """Get the salt for key derivation."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM metadata WHERE key = 'salt'")
            result = cursor.fetchone()
            
            if not result:
                raise ValueError("Vault not initialized")
            
            return bytes.fromhex(result[0])
    
    def add_password(self, service: str, username: str, password: str, notes: str, master_password: str) -> bool:
        """Add a new password entry."""
        if not self.verify_master_password(master_password):
            raise ValueError("Invalid master password")
        
        salt = self.get_salt()
        data = {
            'service': service,
            'username': username,
            'password': password,
            'notes': notes
        }
        
        encrypted_data = self.crypto.encrypt_data(data, master_password, salt)
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO passwords (service, username, password, notes)
                    VALUES (?, ?, ?, ?)
                ''', (
                    encrypted_data['service'],
                    encrypted_data['username'],
                    encrypted_data['password'],
                    encrypted_data['notes']
                ))
                conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Service already exists
            return False
    
    def get_password(self, service: str, master_password: str) -> Optional[Dict[str, str]]:
        """Retrieve a password entry by service name."""
        if not self.verify_master_password(master_password):
            raise ValueError("Invalid master password")
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT service, username, password, notes, created_at, updated_at
                FROM passwords WHERE service = ?
            ''', (service,))
            result = cursor.fetchone()
            
            if not result:
                return None
            
            salt = self.get_salt()
            encrypted_data = {
                'service': result[0],
                'username': result[1],
                'password': result[2],
                'notes': result[3]
            }
            
            decrypted_data = self.crypto.decrypt_data(encrypted_data, master_password, salt)
            decrypted_data['created_at'] = result[4]
            decrypted_data['updated_at'] = result[5]
            
            return decrypted_data
    
    def list_services(self) -> List[str]:
        """List all stored service names."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT service FROM passwords ORDER BY service")
            results = cursor.fetchall()
            return [row[0] for row in results]
    
    def update_password(self, service: str, username: str, password: str, notes: str, master_password: str) -> bool:
        """Update an existing password entry."""
        if not self.verify_master_password(master_password):
            raise ValueError("Invalid master password")
        
        salt = self.get_salt()
        data = {
            'service': service,
            'username': username,
            'password': password,
            'notes': notes
        }
        
        encrypted_data = self.crypto.encrypt_data(data, master_password, salt)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE passwords 
                SET username = ?, password = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
                WHERE service = ?
            ''', (
                encrypted_data['username'],
                encrypted_data['password'],
                encrypted_data['notes'],
                service
            ))
            
            if cursor.rowcount == 0:
                return False
            
            conn.commit()
            return True
    
    def delete_password(self, service: str, master_password: str) -> bool:
        """Delete a password entry."""
        if not self.verify_master_password(master_password):
            raise ValueError("Invalid master password")
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM passwords WHERE service = ?", (service,))
            
            if cursor.rowcount == 0:
                return False
            
            conn.commit()
            return True
    
    def search_services(self, keyword: str, master_password: str) -> List[Dict[str, str]]:
        """Search for services containing the keyword."""
        if not self.verify_master_password(master_password):
            raise ValueError("Invalid master password")
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT service, username, password, notes, created_at, updated_at
                FROM passwords WHERE service LIKE ? ORDER BY service
            ''', (f'%{keyword}%',))
            results = cursor.fetchall()
            
            salt = self.get_salt()
            decrypted_results = []
            
            for result in results:
                encrypted_data = {
                    'service': result[0],
                    'username': result[1],
                    'password': result[2],
                    'notes': result[3]
                }
                
                decrypted_data = self.crypto.decrypt_data(encrypted_data, master_password, salt)
                decrypted_data['created_at'] = result[4]
                decrypted_data['updated_at'] = result[5]
                decrypted_results.append(decrypted_data)
            
            return decrypted_results
