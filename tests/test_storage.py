"""Tests for password storage."""

import pytest
import tempfile
import os
from pryva.storage import PasswordStorage


class TestPasswordStorage:
    """Test cases for PasswordStorage class."""
    
    def setup_method(self):
        """Set up test fixtures with temporary database."""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()
        self.storage = PasswordStorage(self.temp_db.name)
        self.master_password = "test_master_password"
    
    def teardown_method(self):
        """Clean up temporary database."""
        if os.path.exists(self.temp_db.name):
            os.unlink(self.temp_db.name)
    
    def test_initialization(self):
        """Test vault initialization."""
        assert not self.storage.is_initialized()
        
        # Initialize vault
        result = self.storage.initialize_vault(self.master_password)
        assert result is True
        assert self.storage.is_initialized()
        
        # Cannot initialize again
        result = self.storage.initialize_vault(self.master_password)
        assert result is False
    
    def test_master_password_verification(self):
        """Test master password verification."""
        self.storage.initialize_vault(self.master_password)
        
        # Correct password
        assert self.storage.verify_master_password(self.master_password)
        
        # Incorrect password
        assert not self.storage.verify_master_password("wrong_password")
    
    def test_add_and_get_password(self):
        """Test adding and retrieving passwords."""
        self.storage.initialize_vault(self.master_password)
        
        # Add password
        result = self.storage.add_password(
            service="Gmail",
            username="user@example.com",
            password="secret123",
            notes="My email",
            master_password=self.master_password
        )
        assert result is True
        
        # Get password
        entry = self.storage.get_password("Gmail", self.master_password)
        assert entry is not None
        assert entry['service'] == "Gmail"
        assert entry['username'] == "user@example.com"
        assert entry['password'] == "secret123"
        assert entry['notes'] == "My email"
        assert 'created_at' in entry
        assert 'updated_at' in entry
    
    def test_add_duplicate_service(self):
        """Test adding duplicate service names."""
        self.storage.initialize_vault(self.master_password)
        
        # Add first password
        result1 = self.storage.add_password(
            service="Gmail",
            username="user1@example.com",
            password="password1",
            notes="",
            master_password=self.master_password
        )
        assert result1 is True
        
        # Try to add duplicate service
        result2 = self.storage.add_password(
            service="Gmail",
            username="user2@example.com",
            password="password2",
            notes="",
            master_password=self.master_password
        )
        assert result2 is False
    
    def test_list_services(self):
        """Test listing all services."""
        self.storage.initialize_vault(self.master_password)
        
        # Initially empty
        services = self.storage.list_services()
        assert services == []
        
        # Add some passwords
        self.storage.add_password("Gmail", "user@gmail.com", "pass1", "", self.master_password)
        self.storage.add_password("GitHub", "user@github.com", "pass2", "", self.master_password)
        
        services = self.storage.list_services()
        assert len(services) == 2
        assert "Gmail" in services
        assert "GitHub" in services
    
    def test_update_password(self):
        """Test updating existing passwords."""
        self.storage.initialize_vault(self.master_password)
        
        # Add initial password
        self.storage.add_password("Gmail", "old@example.com", "oldpass", "old notes", self.master_password)
        
        # Update password
        result = self.storage.update_password(
            service="Gmail",
            username="new@example.com",
            password="newpass",
            notes="new notes",
            master_password=self.master_password
        )
        assert result is True
        
        # Verify update
        entry = self.storage.get_password("Gmail", self.master_password)
        assert entry['username'] == "new@example.com"
        assert entry['password'] == "newpass"
        assert entry['notes'] == "new notes"
        
        # Try to update non-existent service
        result = self.storage.update_password("NonExistent", "user", "pass", "", self.master_password)
        assert result is False
    
    def test_delete_password(self):
        """Test deleting passwords."""
        self.storage.initialize_vault(self.master_password)
        
        # Add password
        self.storage.add_password("Gmail", "user@example.com", "password", "", self.master_password)
        
        # Verify it exists
        entry = self.storage.get_password("Gmail", self.master_password)
        assert entry is not None
        
        # Delete password
        result = self.storage.delete_password("Gmail", self.master_password)
        assert result is True
        
        # Verify it's gone
        entry = self.storage.get_password("Gmail", self.master_password)
        assert entry is None
        
        # Try to delete non-existent service
        result = self.storage.delete_password("NonExistent", self.master_password)
        assert result is False
    
    def test_search_services(self):
        """Test searching for services."""
        self.storage.initialize_vault(self.master_password)
        
        # Add some test data
        self.storage.add_password("Gmail", "user@gmail.com", "pass1", "", self.master_password)
        self.storage.add_password("GitHub", "user@github.com", "pass2", "", self.master_password)
        self.storage.add_password("Google Drive", "user@gmail.com", "pass3", "", self.master_password)
        
        # Search for "Git"
        results = self.storage.search_services("Git", self.master_password)
        assert len(results) == 1
        assert results[0]['service'] == "GitHub"
        
        # Search for "G" (should match Gmail, GitHub, and Google Drive)
        results = self.storage.search_services("G", self.master_password)
        assert len(results) == 3
        
        # Search for non-existent keyword
        results = self.storage.search_services("NonExistent", self.master_password)
        assert len(results) == 0
    
    def test_invalid_master_password(self):
        """Test operations with invalid master password."""
        self.storage.initialize_vault(self.master_password)
        
        with pytest.raises(ValueError, match="Invalid master password"):
            self.storage.add_password("Gmail", "user", "pass", "", "wrong_password")
        
        with pytest.raises(ValueError, match="Invalid master password"):
            self.storage.get_password("Gmail", "wrong_password")
        
        with pytest.raises(ValueError, match="Invalid master password"):
            self.storage.update_password("Gmail", "user", "pass", "", "wrong_password")
        
        with pytest.raises(ValueError, match="Invalid master password"):
            self.storage.delete_password("Gmail", "wrong_password")
        
        with pytest.raises(ValueError, match="Invalid master password"):
            self.storage.search_services("Gmail", "wrong_password")
