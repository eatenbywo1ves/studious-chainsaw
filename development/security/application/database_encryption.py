"""
Database Field-Level Encryption Module
Provides transparent encryption/decryption for sensitive database fields
"""

import os
from typing import Optional
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
import logging

logger = logging.getLogger(__name__)


class DatabaseEncryption:
    """
    Field-level encryption for database sensitive data
    Uses Fernet symmetric encryption (AES-128-CBC with HMAC)
    """

    def __init__(self, key_path: Optional[str] = None):
        """
        Initialize database encryption

        Args:
            key_path: Path to encryption key file. If None, uses environment variable
        """
        self.key_path = key_path or os.getenv("DB_ENCRYPTION_KEY_PATH")
        self._fernet: Optional[Fernet] = None
        self._initialized = False

        if self.key_path:
            self._load_key()

    def _load_key(self) -> None:
        """Load encryption key from file"""
        try:
            key_file = Path(self.key_path)

            if not key_file.exists():
                logger.warning(f"Encryption key not found at {self.key_path}")
                return

            with open(key_file, 'rb') as f:
                key = f.read().strip()

            self._fernet = Fernet(key)
            self._initialized = True
            logger.info(f"Database encryption initialized with key from {self.key_path}")

        except Exception as e:
            logger.error(f"Failed to load encryption key: {e}")
            self._initialized = False

    @property
    def is_available(self) -> bool:
        """Check if encryption is available"""
        return self._initialized and self._fernet is not None

    def encrypt_field(self, value: Optional[str]) -> Optional[str]:
        """
        Encrypt a database field value

        Args:
            value: Plaintext value to encrypt

        Returns:
            Encrypted value as base64 string, or None if value is None
        """
        if value is None:
            return None

        if not self.is_available:
            logger.warning("Database encryption not available, storing plaintext")
            return value

        try:
            encrypted = self._fernet.encrypt(value.encode())
            return encrypted.decode('utf-8')
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise

    def decrypt_field(self, encrypted_value: Optional[str]) -> Optional[str]:
        """
        Decrypt a database field value

        Args:
            encrypted_value: Encrypted value as base64 string

        Returns:
            Decrypted plaintext value, or None if encrypted_value is None
        """
        if encrypted_value is None:
            return None

        if not self.is_available:
            logger.warning("Database encryption not available, returning value as-is")
            return encrypted_value

        try:
            decrypted = self._fernet.decrypt(encrypted_value.encode())
            return decrypted.decode('utf-8')
        except InvalidToken:
            # Value might not be encrypted (migration scenario)
            logger.warning("Failed to decrypt value - may be plaintext")
            return encrypted_value
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise

    def encrypt_dict(self, data: dict, fields_to_encrypt: list) -> dict:
        """
        Encrypt specific fields in a dictionary

        Args:
            data: Dictionary containing fields to encrypt
            fields_to_encrypt: List of field keys to encrypt

        Returns:
            Dictionary with encrypted fields
        """
        encrypted_data = data.copy()

        for field in fields_to_encrypt:
            if field in encrypted_data:
                encrypted_data[field] = self.encrypt_field(str(encrypted_data[field]))

        return encrypted_data

    def decrypt_dict(self, data: dict, fields_to_decrypt: list) -> dict:
        """
        Decrypt specific fields in a dictionary

        Args:
            data: Dictionary containing encrypted fields
            fields_to_decrypt: List of field keys to decrypt

        Returns:
            Dictionary with decrypted fields
        """
        decrypted_data = data.copy()

        for field in fields_to_decrypt:
            if field in decrypted_data:
                decrypted_data[field] = self.decrypt_field(decrypted_data[field])

        return decrypted_data


class EncryptedField:
    """
    SQLAlchemy custom type for encrypted fields
    Automatically encrypts on write, decrypts on read
    """

    def __init__(self, encryption_manager: DatabaseEncryption):
        """
        Initialize encrypted field type

        Args:
            encryption_manager: DatabaseEncryption instance
        """
        self.encryption_manager = encryption_manager

    def process_bind_param(self, value: Optional[str], dialect) -> Optional[str]:
        """Called when saving to database - encrypts the value"""
        if value is not None:
            return self.encryption_manager.encrypt_field(value)
        return None

    def process_result_value(self, value: Optional[str], dialect) -> Optional[str]:
        """Called when loading from database - decrypts the value"""
        if value is not None:
            return self.encryption_manager.decrypt_field(value)
        return None


# Global encryption manager instance (singleton pattern)
_encryption_manager: Optional[DatabaseEncryption] = None


def get_encryption_manager(key_path: Optional[str] = None) -> DatabaseEncryption:
    """
    Get global encryption manager instance

    Args:
        key_path: Path to encryption key (only used on first call)

    Returns:
        DatabaseEncryption instance
    """
    global _encryption_manager

    if _encryption_manager is None:
        _encryption_manager = DatabaseEncryption(key_path=key_path)

    return _encryption_manager


def encrypt_sensitive_metadata(metadata: dict) -> dict:
    """
    Encrypt sensitive fields in metadata JSON

    Args:
        metadata: Dictionary containing metadata

    Returns:
        Dictionary with sensitive fields encrypted
    """
    encryption = get_encryption_manager()

    # Define sensitive metadata fields that should be encrypted
    sensitive_fields = [
        'payment_method_token',
        'credit_card_last4',
        'bank_account_number',
        'ssn',
        'tax_id',
        'api_secret',
        'webhook_secret',
        'internal_notes',
        'phone_number'
    ]

    return encryption.encrypt_dict(metadata, sensitive_fields)


def decrypt_sensitive_metadata(encrypted_metadata: dict) -> dict:
    """
    Decrypt sensitive fields in metadata JSON

    Args:
        encrypted_metadata: Dictionary containing encrypted metadata

    Returns:
        Dictionary with sensitive fields decrypted
    """
    encryption = get_encryption_manager()

    sensitive_fields = [
        'payment_method_token',
        'credit_card_last4',
        'bank_account_number',
        'ssn',
        'tax_id',
        'api_secret',
        'webhook_secret',
        'internal_notes',
        'phone_number'
    ]

    return encryption.decrypt_dict(encrypted_metadata, sensitive_fields)


# Utility functions for common operations
def encrypt_email(email: str) -> str:
    """Encrypt email address"""
    return get_encryption_manager().encrypt_field(email)


def decrypt_email(encrypted_email: str) -> str:
    """Decrypt email address"""
    return get_encryption_manager().decrypt_field(encrypted_email)


def generate_encryption_key(output_path: Optional[str] = None) -> bytes:
    """
    Generate a new Fernet encryption key

    Args:
        output_path: Path to save the key file. If None, returns key without saving

    Returns:
        Generated encryption key
    """
    key = Fernet.generate_key()

    if output_path:
        key_file = Path(output_path)
        key_file.parent.mkdir(parents=True, exist_ok=True)

        with open(key_file, 'wb') as f:
            f.write(key)

        # Set restrictive permissions (owner read/write only)
        if os.name != 'nt':  # Unix/Linux
            os.chmod(key_file, 0o600)

        logger.info(f"Encryption key generated and saved to {output_path}")

    return key
