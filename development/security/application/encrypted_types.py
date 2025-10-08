"""
SQLAlchemy Encrypted Column Types
Provides TypeDecorator implementations for transparent field encryption
"""

from typing import Optional
from sqlalchemy import String, TypeDecorator
from sqlalchemy.dialects.postgresql import JSONB
import json
import logging

from security.application.database_encryption import get_encryption_manager

logger = logging.getLogger(__name__)


class EncryptedString(TypeDecorator):
    """
    SQLAlchemy type that encrypts string values before storage
    and decrypts them on retrieval
    """

    impl = String
    cache_ok = True

    def __init__(self, length=None, **kwargs):
        """
        Initialize encrypted string column

        Args:
            length: Maximum length for the encrypted string (should be larger than plaintext)
        """
        # Encrypted values are base64 encoded and longer than plaintext
        # Fernet adds ~56 bytes overhead + base64 encoding
        if length:
            length = max(length * 2, 512)  # At least 2x original length or 512 chars

        super().__init__(length=length, **kwargs)

    def process_bind_param(self, value: Optional[str], dialect) -> Optional[str]:
        """Encrypt value before saving to database"""
        if value is None:
            return None

        encryption = get_encryption_manager()

        if not encryption.is_available:
            logger.warning("Encryption not available - storing plaintext (NOT RECOMMENDED)")
            return value

        try:
            return encryption.encrypt_field(value)
        except Exception as e:
            logger.error(f"Failed to encrypt field: {e}")
            raise

    def process_result_value(self, value: Optional[str], dialect) -> Optional[str]:
        """Decrypt value when loading from database"""
        if value is None:
            return None

        encryption = get_encryption_manager()

        if not encryption.is_available:
            logger.warning("Encryption not available - returning raw value")
            return value

        try:
            return encryption.decrypt_field(value)
        except Exception as e:
            logger.error(f"Failed to decrypt field: {e}")
            # Return encrypted value to avoid data loss
            return value


class EncryptedJSON(TypeDecorator):
    """
    SQLAlchemy type that encrypts JSONB fields with selective field encryption
    Only encrypts sensitive fields, leaves others as plaintext
    """

    impl = JSONB
    cache_ok = True

    def __init__(self, sensitive_fields=None, **kwargs):
        """
        Initialize encrypted JSON column

        Args:
            sensitive_fields: List of field names to encrypt within the JSON
        """
        self.sensitive_fields = sensitive_fields or []
        super().__init__(**kwargs)

    def process_bind_param(self, value: Optional[dict], dialect) -> Optional[dict]:
        """Encrypt sensitive fields before saving"""
        if value is None or not isinstance(value, dict):
            return value

        encryption = get_encryption_manager()

        if not encryption.is_available or not self.sensitive_fields:
            return value

        try:
            encrypted_value = value.copy()

            for field in self.sensitive_fields:
                if field in encrypted_value and encrypted_value[field] is not None:
                    # Convert to string, encrypt, store with marker
                    field_str = json.dumps(encrypted_value[field]) if not isinstance(encrypted_value[field], str) else encrypted_value[field]
                    encrypted_value[field] = encryption.encrypt_field(field_str)
                    # Add marker to indicate this field is encrypted
                    encrypted_value[f"__{field}_encrypted"] = True

            return encrypted_value
        except Exception as e:
            logger.error(f"Failed to encrypt JSON fields: {e}")
            raise

    def process_result_value(self, value: Optional[dict], dialect) -> Optional[dict]:
        """Decrypt sensitive fields when loading"""
        if value is None or not isinstance(value, dict):
            return value

        encryption = get_encryption_manager()

        if not encryption.is_available or not self.sensitive_fields:
            return value

        try:
            decrypted_value = value.copy()

            for field in self.sensitive_fields:
                # Check if field was encrypted (has marker)
                if f"__{field}_encrypted" in decrypted_value:
                    if field in decrypted_value and decrypted_value[field] is not None:
                        decrypted_str = encryption.decrypt_field(decrypted_value[field])
                        # Try to parse as JSON, fallback to string
                        try:
                            decrypted_value[field] = json.loads(decrypted_str)
                        except (json.JSONDecodeError, TypeError):
                            decrypted_value[field] = decrypted_str
                    # Remove encryption marker
                    del decrypted_value[f"__{field}_encrypted"]

            return decrypted_value
        except Exception as e:
            logger.error(f"Failed to decrypt JSON fields: {e}")
            # Return encrypted value to avoid data loss
            return value


# Pre-configured types for common use cases
def EncryptedEmail():
    return EncryptedString(255)
def EncryptedPhone():
    return EncryptedString(50)
def EncryptedName():
    return EncryptedString(200)
def EncryptedApiSecret():
    return EncryptedString(512)


# Helper function to create encrypted metadata column
def create_encrypted_metadata(sensitive_fields=None):
    """
    Create an EncryptedJSON column for metadata with default sensitive fields

    Args:
        sensitive_fields: Additional fields to encrypt (added to defaults)

    Returns:
        EncryptedJSON column instance
    """
    default_sensitive = [
        'payment_method_token',
        'credit_card_last4',
        'bank_account_number',
        'ssn',
        'tax_id',
        'api_secret',
        'webhook_secret',
        'internal_notes',
        'phone_number',
        'address',
        'personal_data'
    ]

    if sensitive_fields:
        default_sensitive.extend(sensitive_fields)

    return EncryptedJSON(sensitive_fields=default_sensitive)
