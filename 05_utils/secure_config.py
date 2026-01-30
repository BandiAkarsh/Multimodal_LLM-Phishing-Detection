"""
Secure Configuration Manager

Handles encryption and secure storage of sensitive configuration data
like email credentials, API keys, and passwords.

Uses Fernet symmetric encryption with automatic key management.
Falls back to system keyring for additional security layer.

Author: Phishing Guard Team
Version: 2.0.0
"""

import os
import json
import base64
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import keyring
import getpass


class SecureConfigManager:
    """
    Manages secure storage and retrieval of sensitive configuration.
    
    Features:
    - Fernet encryption for config files
    - System keyring integration for master key
    - Automatic key generation and rotation
    - Secure deletion of plaintext files
    - Migration from legacy plaintext configs
    """
    
    def __init__(self, app_name="phishing_guard"):
        self.app_name = app_name
        self.config_dir = Path.home() / f".{app_name}"
        self.config_dir.mkdir(mode=0o700, exist_ok=True)
        
        # Key storage paths
        self.key_file = self.config_dir / ".master_key"
        self.salt_file = self.config_dir / ".salt"
        self.config_file = self.config_dir / "config.enc"
        
        # Legacy paths (for migration)
        self.legacy_config = Path("email_config.json")
        self.project_legacy = Path.cwd() / "email_config.json"
    
    def _get_or_create_key(self) -> bytes:
        """
        Get existing encryption key or generate new one.
        
        Priority:
        1. Keyring (most secure)
        2. Key file (fallback)
        3. Generate new (first run)
        
        Returns:
            bytes: 32-byte encryption key
        """
        # Try keyring first
        try:
            keyring_key = keyring.get_password(self.app_name, "master_key")
            if keyring_key:
                return base64.urlsafe_b64decode(keyring_key.encode())
        except Exception:
            pass
        
        # Try key file
        if self.key_file.exists():
            try:
                with open(self.key_file, 'rb') as f:
                    return f.read()
            except Exception:
                pass
        
        # Generate new key
        key = Fernet.generate_key()
        
        # Save to keyring (preferred)
        try:
            keyring.set_password(
                self.app_name, 
                "master_key", 
                base64.urlsafe_b64encode(key).decode()
            )
        except Exception:
            # Fallback to file
            with open(self.key_file, 'wb') as f:
                f.write(key)
            os.chmod(self.key_file, 0o600)
        
        return key
    
    def _get_fernet(self) -> Fernet:
        """Get configured Fernet instance."""
        key = self._get_or_create_key()
        return Fernet(key)
    
    def encrypt_config(self, config_data: dict) -> None:
        """
        Encrypt and save configuration data.
        
        Args:
            config_data: Dictionary containing sensitive configuration
            
        Example:
            config = {
                "email": "user@gmail.com",
                "password": "secret_password",
                "server": "imap.gmail.com"
            }
            manager.encrypt_config(config)
        """
        f = self._get_fernet()
        
        # Convert to JSON and encrypt
        plaintext = json.dumps(config_data, indent=2).encode('utf-8')
        encrypted = f.encrypt(plaintext)
        
        # Write encrypted config
        with open(self.config_file, 'wb') as cf:
            cf.write(encrypted)
        
        # Secure permissions
        os.chmod(self.config_file, 0o600)
        
        print(f"[✓] Configuration encrypted and saved to {self.config_file}")
    
    def decrypt_config(self) -> dict:
        """
        Decrypt and return configuration data.
        
        Returns:
            dict: Decrypted configuration
            
        Raises:
            FileNotFoundError: If no encrypted config exists
            Exception: If decryption fails (wrong key, corrupted data)
        """
        if not self.config_file.exists():
            raise FileNotFoundError(
                f"No encrypted config found at {self.config_file}. "
                "Run setup first."
            )
        
        f = self._get_fernet()
        
        with open(self.config_file, 'rb') as cf:
            encrypted = cf.read()
        
        try:
            plaintext = f.decrypt(encrypted)
            return json.loads(plaintext.decode('utf-8'))
        except Exception as e:
            raise Exception(
                f"Failed to decrypt configuration. "
                f"Key may be corrupted or config file tampered. Error: {e}"
            )
    
    def migrate_from_legacy(self, legacy_path: str = None) -> bool:
        """
        Migrate from legacy plaintext JSON config to encrypted format.
        
        Args:
            legacy_path: Path to legacy config file (default: email_config.json)
            
        Returns:
            bool: True if migration successful, False otherwise
        """
        if legacy_path is None:
            # Check common locations
            possible_paths = [
                self.legacy_config,
                self.project_legacy,
                Path.cwd() / "email_config.json",
                Path.home() / "email_config.json"
            ]
            
            for path in possible_paths:
                if path.exists():
                    legacy_path = path
                    break
        else:
            legacy_path = Path(legacy_path)
        
        if not legacy_path or not legacy_path.exists():
            print("[i] No legacy plaintext config found to migrate")
            return False
        
        try:
            # Read legacy config
            with open(legacy_path, 'r') as f:
                legacy_data = json.load(f)
            
            print(f"[i] Found legacy config at {legacy_path}")
            print("[i] Migrating to encrypted format...")
            
            # Encrypt and save
            self.encrypt_config(legacy_data)
            
            # Securely delete legacy file (overwrite + delete)
            self._secure_delete(legacy_path)
            
            print(f"[✓] Migration complete. Legacy file securely deleted.")
            return True
            
        except Exception as e:
            print(f"[✗] Migration failed: {e}")
            return False
    
    def _secure_delete(self, filepath: Path) -> None:
        """
        Securely delete file by overwriting with random data first.
        
        Args:
            filepath: Path to file to delete
        """
        try:
            # Get file size
            size = filepath.stat().st_size
            
            # Overwrite with random data (3 passes)
            with open(filepath, 'ba+') as f:
                for _ in range(3):
                    f.seek(0)
                    f.write(os.urandom(size))
                    f.flush()
                    os.fsync(f.fileno())
            
            # Delete file
            filepath.unlink()
            
        except Exception as e:
            print(f"[!] Warning: Could not securely delete {filepath}: {e}")
            # Try regular delete
            try:
                filepath.unlink()
            except:
                pass
    
    def update_config(self, updates: dict) -> None:
        """
        Update specific fields in encrypted config.
        
        Args:
            updates: Dictionary with fields to update
            
        Example:
            manager.update_config({"password": "new_password"})
        """
        # Decrypt current config
        config = self.decrypt_config()
        
        # Apply updates
        config.update(updates)
        
        # Re-encrypt
        self.encrypt_config(config)
        
        print("[✓] Configuration updated successfully")
    
    def get_config(self, key: str = None) -> any:
        """
        Get configuration value(s).
        
        Args:
            key: Specific config key to retrieve (default: all)
            
        Returns:
            Value for specific key, or entire config dict
        """
        config = self.decrypt_config()
        
        if key:
            return config.get(key)
        return config
    
    def config_exists(self) -> bool:
        """Check if encrypted config exists."""
        return self.config_file.exists()
    
    def rotate_key(self) -> None:
        """
        Rotate encryption key and re-encrypt config.
        Use periodically for security.
        """
        if not self.config_exists():
            print("[!] No config to re-encrypt")
            return
        
        print("[i] Rotating encryption key...")
        
        # Decrypt with old key
        config = self.decrypt_config()
        
        # Generate new key
        new_key = Fernet.generate_key()
        
        # Update keyring/file
        try:
            keyring.set_password(
                self.app_name, 
                "master_key", 
                base64.urlsafe_b64encode(new_key).decode()
            )
        except:
            with open(self.key_file, 'wb') as f:
                f.write(new_key)
            os.chmod(self.key_file, 0o600)
        
        # Re-encrypt with new key
        f = Fernet(new_key)
        plaintext = json.dumps(config, indent=2).encode('utf-8')
        encrypted = f.encrypt(plaintext)
        
        with open(self.config_file, 'wb') as cf:
            cf.write(encrypted)
        
        print("[✓] Encryption key rotated successfully")


def demo():
    """Demonstrate secure config functionality."""
    print("=" * 60)
    print("Secure Configuration Manager Demo")
    print("=" * 60)
    
    manager = SecureConfigManager()
    
    # Test migration
    print("\n[1] Checking for legacy config to migrate...")
    manager.migrate_from_legacy()
    
    # Test saving new config
    print("\n[2] Creating new encrypted config...")
    test_config = {
        "email": "demo@example.com",
        "password": "demo_password_123",
        "server": "imap.gmail.com",
        "port": 993,
        "use_ssl": True
    }
    manager.encrypt_config(test_config)
    
    # Test retrieval
    print("\n[3] Retrieving encrypted config...")
    retrieved = manager.get_config()
    print(f"Email: {retrieved.get('email')}")
    print(f"Server: {retrieved.get('server')}")
    print(f"Password: {'*' * len(retrieved.get('password', ''))}")
    
    # Test update
    print("\n[4] Updating password...")
    manager.update_config({"password": "new_secure_password"})
    
    # Verify update
    new_password = manager.get_config("password")
    print(f"New password set: {'*' * len(new_password)}")
    
    # Show file locations
    print("\n[5] Secure storage locations:")
    print(f"   Config: {manager.config_file}")
    print(f"   Key: {manager.key_file}")
    print(f"   Permissions: 600 (owner read/write only)")
    
    print("\n" + "=" * 60)
    print("Demo complete!")
    print("=" * 60)


if __name__ == "__main__":
    demo()
