"""
Unit Tests for Database Encryption Module
Tests field-level encryption, key management, and SQLAlchemy integration
"""

import pytest
from pathlib import Path
from cryptography.fernet import Fernet

from security.application.database_encryption import (
    DatabaseEncryption,
    get_encryption_manager,
    encrypt_sensitive_metadata,
    decrypt_sensitive_metadata,
    generate_encryption_key,
)
from security.application.encrypted_types import EncryptedString, EncryptedJSON


class TestDatabaseEncryption:
    """Test DatabaseEncryption class"""

    def test_initialization_with_valid_key(self, tmp_path):
        """Test encryption manager initializes with valid key"""
        # Generate test key
        key_path = tmp_path / "test.key"
        generate_encryption_key(str(key_path))

        # Initialize encryption
        encryption = DatabaseEncryption(key_path=str(key_path))

        assert encryption.is_available is True
        assert encryption._fernet is not None

    def test_initialization_without_key(self):
        """Test encryption manager handles missing key gracefully"""
        encryption = DatabaseEncryption(key_path="/nonexistent/key.key")

        assert encryption.is_available is False
        assert encryption._fernet is None

    def test_encrypt_decrypt_field(self, tmp_path):
        """Test field encryption and decryption"""
        key_path = tmp_path / "test.key"
        generate_encryption_key(str(key_path))

        encryption = DatabaseEncryption(key_path=str(key_path))

        # Test encryption
        plaintext = "sensitive_data@example.com"
        encrypted = encryption.encrypt_field(plaintext)

        assert encrypted != plaintext
        assert encrypted.startswith("gAAAAA")  # Fernet token format

        # Test decryption
        decrypted = encryption.decrypt_field(encrypted)
        assert decrypted == plaintext

    def test_encrypt_none_value(self, tmp_path):
        """Test encrypting None returns None"""
        key_path = tmp_path / "test.key"
        generate_encryption_key(str(key_path))

        encryption = DatabaseEncryption(key_path=str(key_path))

        assert encryption.encrypt_field(None) is None
        assert encryption.decrypt_field(None) is None

    def test_encrypt_dict_selective_fields(self, tmp_path):
        """Test encrypting specific fields in a dictionary"""
        key_path = tmp_path / "test.key"
        generate_encryption_key(str(key_path))

        encryption = DatabaseEncryption(key_path=str(key_path))

        data = {
            "public_field": "visible",
            "sensitive_field": "secret_123",
            "another_public": "data",
        }

        # Encrypt only sensitive_field
        encrypted_data = encryption.encrypt_dict(data, ["sensitive_field"])

        assert encrypted_data["public_field"] == "visible"
        assert encrypted_data["another_public"] == "data"
        assert encrypted_data["sensitive_field"] != "secret_123"
        assert encrypted_data["sensitive_field"].startswith("gAAAAA")

    def test_decrypt_dict_selective_fields(self, tmp_path):
        """Test decrypting specific fields in a dictionary"""
        key_path = tmp_path / "test.key"
        generate_encryption_key(str(key_path))

        encryption = DatabaseEncryption(key_path=str(key_path))

        data = {"public": "visible", "secret": "password123"}

        # Encrypt
        encrypted = encryption.encrypt_dict(data, ["secret"])

        # Decrypt
        decrypted = encryption.decrypt_dict(encrypted, ["secret"])

        assert decrypted["public"] == "visible"
        assert decrypted["secret"] == "password123"

    def test_encryption_without_key_fallback(self):
        """Test that encryption falls back to plaintext when key unavailable"""
        encryption = DatabaseEncryption(key_path=None)

        plaintext = "test_value"
        result = encryption.encrypt_field(plaintext)

        # Should return plaintext when encryption unavailable
        assert result == plaintext


class TestEncryptedTypes:
    """Test SQLAlchemy custom encrypted types"""

    def test_encrypted_string_type(self, tmp_path):
        """Test EncryptedString TypeDecorator"""
        key_path = tmp_path / "test.key"
        generate_encryption_key(str(key_path))

        # Initialize encryption manager (reset singleton)
        import security.application.database_encryption as db_enc

        db_enc._encryption_manager = None
        get_encryption_manager(key_path=str(key_path))

        encrypted_type = EncryptedString(255)

        # Test bind param (encryption)
        plaintext = "test@example.com"
        encrypted = encrypted_type.process_bind_param(plaintext, None)

        assert encrypted != plaintext
        assert encrypted.startswith("gAAAAA")

        # Test result value (decryption)
        decrypted = encrypted_type.process_result_value(encrypted, None)
        assert decrypted == plaintext

    def test_encrypted_string_none_handling(self, tmp_path):
        """Test EncryptedString handles None values"""
        key_path = tmp_path / "test.key"
        generate_encryption_key(str(key_path))

        import security.application.database_encryption as db_enc

        db_enc._encryption_manager = None
        get_encryption_manager(key_path=str(key_path))

        encrypted_type = EncryptedString(255)

        assert encrypted_type.process_bind_param(None, None) is None
        assert encrypted_type.process_result_value(None, None) is None

    def test_encrypted_json_selective_encryption(self, tmp_path):
        """Test EncryptedJSON encrypts only specified fields"""
        key_path = tmp_path / "test.key"
        generate_encryption_key(str(key_path))

        # Initialize encryption manager (reset singleton)
        import security.application.database_encryption as db_enc

        db_enc._encryption_manager = None
        get_encryption_manager(key_path=str(key_path))

        encrypted_type = EncryptedJSON(sensitive_fields=["ssn", "credit_card"])

        data = {
            "name": "John Doe",
            "ssn": "123-45-6789",
            "credit_card": "4111111111111111",
            "preference": "dark_mode",
        }

        # Encrypt
        encrypted = encrypted_type.process_bind_param(data, None)

        assert encrypted["name"] == "John Doe"  # Not encrypted
        assert encrypted["preference"] == "dark_mode"  # Not encrypted
        assert encrypted["ssn"] != "123-45-6789"  # Encrypted
        assert encrypted["credit_card"] != "4111111111111111"  # Encrypted
        assert encrypted["__ssn_encrypted"] is True  # Marker added
        assert encrypted["__credit_card_encrypted"] is True

        # Decrypt
        decrypted = encrypted_type.process_result_value(encrypted, None)

        assert decrypted["name"] == "John Doe"
        assert decrypted["ssn"] == "123-45-6789"
        # Credit card was numeric string, JSON conversion makes it int
        assert str(decrypted["credit_card"]) == "4111111111111111"
        assert "__ssn_encrypted" not in decrypted  # Marker removed


class TestSensitiveMetadata:
    """Test metadata encryption helpers"""

    def test_encrypt_sensitive_metadata(self, tmp_path):
        """Test encrypting sensitive metadata fields"""
        key_path = tmp_path / "test.key"
        generate_encryption_key(str(key_path))

        import security.application.database_encryption as db_enc

        db_enc._encryption_manager = None
        get_encryption_manager(key_path=str(key_path))

        metadata = {
            "user_preference": "dark",
            "payment_method_token": "tok_123456",
            "credit_card_last4": "1234",
            "feature_flags": {"new_ui": True},
        }

        encrypted = encrypt_sensitive_metadata(metadata)

        # Non-sensitive fields unchanged
        assert encrypted["user_preference"] == "dark"
        assert encrypted["feature_flags"] == {"new_ui": True}

        # Sensitive fields encrypted
        assert encrypted["payment_method_token"] != "tok_123456"
        assert encrypted["credit_card_last4"] != "1234"

    def test_decrypt_sensitive_metadata(self, tmp_path):
        """Test decrypting sensitive metadata fields"""
        key_path = tmp_path / "test.key"
        generate_encryption_key(str(key_path))

        import security.application.database_encryption as db_enc

        db_enc._encryption_manager = None
        get_encryption_manager(key_path=str(key_path))

        metadata = {"setting": "value", "payment_method_token": "tok_secret"}

        encrypted = encrypt_sensitive_metadata(metadata)
        decrypted = decrypt_sensitive_metadata(encrypted)

        assert decrypted["setting"] == "value"
        assert decrypted["payment_method_token"] == "tok_secret"


class TestKeyGeneration:
    """Test encryption key generation"""

    def test_generate_encryption_key(self, tmp_path):
        """Test generating new encryption key"""
        key_path = tmp_path / "new_key.key"

        key = generate_encryption_key(str(key_path))

        # Verify key generated
        assert key is not None
        assert len(key) == 44  # Fernet key length

        # Verify key saved to file
        assert key_path.exists()

        # Verify key can be used for encryption
        with open(key_path, "rb") as f:
            loaded_key = f.read().strip()

        fernet = Fernet(loaded_key)
        encrypted = fernet.encrypt(b"test")
        decrypted = fernet.decrypt(encrypted)

        assert decrypted == b"test"

    def test_generate_key_without_path(self):
        """Test generating key without saving to file"""
        key = generate_encryption_key(output_path=None)

        assert key is not None
        assert len(key) == 44

        # Verify key works
        fernet = Fernet(key)
        encrypted = fernet.encrypt(b"test")
        assert fernet.decrypt(encrypted) == b"test"


class TestSingletonPattern:
    """Test global encryption manager singleton"""

    def test_get_encryption_manager_singleton(self, tmp_path):
        """Test get_encryption_manager returns same instance"""
        key_path = tmp_path / "test.key"
        generate_encryption_key(str(key_path))

        # Reset singleton
        from security.application import database_encryption

        database_encryption._encryption_manager = None

        # Get instance
        mgr1 = get_encryption_manager(key_path=str(key_path))
        mgr2 = get_encryption_manager()

        # Should be same instance
        assert mgr1 is mgr2


class TestEdgeCases:
    """Test edge cases and error handling"""

    def test_decrypt_invalid_token(self, tmp_path):
        """Test decrypting invalid token returns original value"""
        key_path = tmp_path / "test.key"
        generate_encryption_key(str(key_path))

        encryption = DatabaseEncryption(key_path=str(key_path))

        # Try to decrypt plaintext (invalid token)
        result = encryption.decrypt_field("not_encrypted_value")

        # Should return original value (graceful degradation)
        assert result == "not_encrypted_value"

    def test_encrypt_empty_string(self, tmp_path):
        """Test encrypting empty string"""
        key_path = tmp_path / "test.key"
        generate_encryption_key(str(key_path))

        encryption = DatabaseEncryption(key_path=str(key_path))

        encrypted = encryption.encrypt_field("")
        decrypted = encryption.decrypt_field(encrypted)

        assert decrypted == ""

    def test_encrypt_unicode_string(self, tmp_path):
        """Test encrypting Unicode strings"""
        key_path = tmp_path / "test.key"
        generate_encryption_key(str(key_path))

        encryption = DatabaseEncryption(key_path=str(key_path))

        unicode_text = "Hello 世界 🌍"
        encrypted = encryption.encrypt_field(unicode_text)
        decrypted = encryption.decrypt_field(encrypted)

        assert decrypted == unicode_text


# Pytest fixtures
@pytest.fixture
def tmp_path(tmpdir):
    """Provide temporary directory for tests"""
    return Path(tmpdir)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
