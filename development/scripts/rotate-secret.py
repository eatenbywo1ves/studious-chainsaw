#!/usr/bin/env python3
"""
Secret Rotation Script

Automates secret rotation for HashiCorp Vault with:
- Multiple rotation strategies (random, cryptographic)
- Graceful rollover (old + new secrets both valid during transition)
- Automatic application restart notification
- Audit logging

Part of Phase 6: Secrets Management (90-day rotation policy)

Usage:
    # Rotate database password
    python scripts/rotate-secret.py --category database --key password

    # Rotate Redis password with custom length
    python scripts/rotate-secret.py --category redis --key password --length 64

    # Rotate JWT secret (cryptographic strength)
    python scripts/rotate-secret.py --category jwt --key secret_key --strategy cryptographic

    # Dry run (simulate without making changes)
    python scripts/rotate-secret.py --category database --key password --dry-run
"""

import os
import sys
import argparse
import secrets
import string
import logging
import hashlib
from typing import Dict, Any, Optional
from datetime import datetime, timedelta

try:
    import hvac
except ImportError:
    print("ERROR: hvac library not installed. Run: pip install hvac==2.1.0")
    sys.exit(1)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SecretRotator:
    """Rotate secrets in HashiCorp Vault"""

    def __init__(
        self,
        environment: str,
        vault_url: str = "http://localhost:8200",
        vault_token: Optional[str] = None
    ):
        """
        Initialize secret rotator

        Args:
            environment: Environment name (development, staging, production)
            vault_url: Vault server URL
            vault_token: Vault authentication token
        """
        self.environment = environment
        self.vault_url = vault_url

        # Use provided token or default dev token
        if vault_token:
            self.vault_token = vault_token
        elif environment == "development":
            self.vault_token = "dev-root-token-catalytic-2024"
        else:
            raise ValueError(
                f"vault_token required for environment: {environment}"
            )

        # Initialize Vault client
        try:
            self.client = hvac.Client(url=vault_url, token=self.vault_token)

            if not self.client.is_authenticated():
                raise Exception("Vault authentication failed")

            logger.info(f"✓ Connected to Vault at {vault_url}")

        except Exception as e:
            logger.error(f"Failed to connect to Vault: {e}")
            raise

    def generate_password(
        self,
        length: int = 32,
        strategy: str = "secure"
    ) -> str:
        """
        Generate a secure random password

        Args:
            length: Password length (default: 32)
            strategy: Generation strategy ("secure" or "cryptographic")

        Returns:
            Generated password
        """
        if strategy == "cryptographic":
            # Use cryptographically secure random bytes
            random_bytes = secrets.token_bytes(length)
            # Convert to base64-like format (URL-safe)
            password = secrets.token_urlsafe(length)[:length]
        else:
            # Default: secure random with alphanumeric + special chars
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
            password = ''.join(secrets.choice(alphabet) for _ in range(length))

        return password

    def generate_hex_key(self, length: int = 64) -> str:
        """
        Generate a secure hexadecimal key (for Redis, API keys)

        Args:
            length: Key length in characters (default: 64)

        Returns:
            Hexadecimal key
        """
        # Generate random bytes and convert to hex
        num_bytes = length // 2
        return secrets.token_hex(num_bytes)

    def get_current_secret(self, category: str, key: str) -> Optional[str]:
        """
        Get current secret value from Vault

        Args:
            category: Secret category
            key: Secret key

        Returns:
            Current secret value or None
        """
        try:
            path = f"{self.environment}/{category}"
            response = self.client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point='secret'
            )

            secrets_data = response['data']['data']
            current_value = secrets_data.get(key)

            if current_value:
                logger.info(f"✓ Retrieved current secret: {category}/{key}")
                return current_value
            else:
                logger.warning(f"Secret key not found: {category}/{key}")
                return None

        except hvac.exceptions.InvalidPath:
            logger.warning(f"Secret path not found: {category}")
            return None
        except Exception as e:
            logger.error(f"Failed to read secret: {e}")
            raise

    def rotate_secret(
        self,
        category: str,
        key: str,
        new_value: Optional[str] = None,
        length: int = 32,
        strategy: str = "secure",
        grace_period_hours: int = 24
    ) -> Dict[str, Any]:
        """
        Rotate a secret with graceful rollover

        Args:
            category: Secret category (e.g., "database", "redis")
            key: Secret key (e.g., "password")
            new_value: New secret value (auto-generated if not provided)
            length: Generated secret length
            strategy: Generation strategy
            grace_period_hours: Hours to keep old secret valid (default: 24)

        Returns:
            Dictionary with rotation details
        """
        # Get current secret
        old_value = self.get_current_secret(category, key)

        if not old_value:
            logger.error(f"Cannot rotate non-existent secret: {category}/{key}")
            return {
                "success": False,
                "error": "Secret does not exist"
            }

        # Generate or use provided new value
        if new_value is None:
            if key in ["password", "secret_key"]:
                # Detect if hex format is expected
                if len(old_value) == 64 and all(c in string.hexdigits for c in old_value):
                    new_value = self.generate_hex_key(64)
                    logger.info(f"Generated new hex key (64 chars)")
                else:
                    new_value = self.generate_password(length, strategy)
                    logger.info(f"Generated new password ({length} chars, {strategy} strategy)")
            else:
                new_value = self.generate_password(length, strategy)
                logger.info(f"Generated new secret value")
        else:
            logger.info(f"Using provided secret value")

        # Read all secrets for the category
        try:
            path = f"{self.environment}/{category}"
            response = self.client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point='secret'
            )
            all_secrets = response['data']['data']

        except Exception as e:
            logger.error(f"Failed to read category secrets: {e}")
            raise

        # Update the secret
        all_secrets[key] = new_value

        # Store old secret with expiry for graceful rollover
        old_key = f"{key}_old"
        expiry_key = f"{key}_old_expires"
        expiry_time = datetime.utcnow() + timedelta(hours=grace_period_hours)

        all_secrets[old_key] = old_value
        all_secrets[expiry_key] = expiry_time.isoformat()

        # Write updated secrets to Vault
        try:
            self.client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=all_secrets,
                mount_point='secret'
            )

            logger.info(f"✓ Rotated secret: {category}/{key}")
            logger.info(f"✓ Old secret available until: {expiry_time} (grace period: {grace_period_hours}h)")

            # Log rotation in audit trail
            self._log_rotation(category, key, expiry_time)

            return {
                "success": True,
                "category": category,
                "key": key,
                "rotated_at": datetime.utcnow().isoformat(),
                "grace_period_expires": expiry_time.isoformat(),
                "grace_period_hours": grace_period_hours,
                "new_value_preview": f"{new_value[:8]}..." if len(new_value) > 8 else "***"
            }

        except Exception as e:
            logger.error(f"Failed to rotate secret: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def cleanup_old_secrets(self, category: str) -> int:
        """
        Remove expired old secrets from category

        Args:
            category: Secret category

        Returns:
            Number of old secrets removed
        """
        try:
            path = f"{self.environment}/{category}"
            response = self.client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point='secret'
            )
            all_secrets = response['data']['data']

            removed = 0
            keys_to_remove = []

            # Find expired old secrets
            for key in list(all_secrets.keys()):
                if key.endswith('_old_expires'):
                    expiry_str = all_secrets[key]
                    expiry_time = datetime.fromisoformat(expiry_str)

                    if datetime.utcnow() > expiry_time:
                        # Expired - mark for removal
                        base_key = key.replace('_old_expires', '')
                        keys_to_remove.extend([
                            f"{base_key}_old",
                            f"{base_key}_old_expires"
                        ])
                        removed += 1

            # Remove expired secrets
            if keys_to_remove:
                for key in keys_to_remove:
                    if key in all_secrets:
                        del all_secrets[key]

                # Write back to Vault
                self.client.secrets.kv.v2.create_or_update_secret(
                    path=path,
                    secret=all_secrets,
                    mount_point='secret'
                )

                logger.info(f"✓ Cleaned up {removed} expired old secrets from {category}")

            return removed

        except Exception as e:
            logger.error(f"Failed to cleanup old secrets: {e}")
            return 0

    def _log_rotation(self, category: str, key: str, expiry_time: datetime) -> None:
        """
        Log rotation in Vault audit trail

        Args:
            category: Secret category
            key: Secret key
            expiry_time: Grace period expiry time
        """
        try:
            audit_path = f"{self.environment}/audit/rotations"

            # Read existing audit log
            try:
                response = self.client.secrets.kv.v2.read_secret_version(
                    path=audit_path,
                    mount_point='secret'
                )
                audit_log = response['data']['data'].get('entries', [])
            except hvac.exceptions.InvalidPath:
                audit_log = []

            # Add new entry
            audit_log.append({
                "category": category,
                "key": key,
                "rotated_at": datetime.utcnow().isoformat(),
                "grace_period_expires": expiry_time.isoformat(),
                "rotated_by": os.getenv("USER", "system")
            })

            # Keep last 1000 entries
            audit_log = audit_log[-1000:]

            # Write back
            self.client.secrets.kv.v2.create_or_update_secret(
                path=audit_path,
                secret={"entries": audit_log},
                mount_point='secret'
            )

            logger.debug(f"Logged rotation in audit trail")

        except Exception as e:
            logger.warning(f"Failed to log rotation: {e}")


def main():
    """Main rotation script"""
    parser = argparse.ArgumentParser(
        description="Rotate secrets in HashiCorp Vault"
    )
    parser.add_argument(
        "--env",
        default=os.getenv("ENVIRONMENT", "development"),
        choices=["development", "staging", "production"],
        help="Environment (default: from ENVIRONMENT env var or 'development')"
    )
    parser.add_argument(
        "--vault-url",
        default="http://localhost:8200",
        help="Vault server URL (default: http://localhost:8200)"
    )
    parser.add_argument(
        "--vault-token",
        help="Vault authentication token"
    )
    parser.add_argument(
        "--category",
        required=True,
        help="Secret category (e.g., database, redis, jwt)"
    )
    parser.add_argument(
        "--key",
        required=True,
        help="Secret key to rotate (e.g., password, secret_key)"
    )
    parser.add_argument(
        "--new-value",
        help="New secret value (auto-generated if not provided)"
    )
    parser.add_argument(
        "--length",
        type=int,
        default=32,
        help="Generated secret length (default: 32)"
    )
    parser.add_argument(
        "--strategy",
        choices=["secure", "cryptographic"],
        default="secure",
        help="Generation strategy (default: secure)"
    )
    parser.add_argument(
        "--grace-period",
        type=int,
        default=24,
        help="Grace period in hours (default: 24)"
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Cleanup expired old secrets after rotation"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate rotation without making changes"
    )

    args = parser.parse_args()

    logger.info("=" * 80)
    logger.info("Secret Rotation Script")
    logger.info("=" * 80)
    logger.info(f"Environment: {args.env}")
    logger.info(f"Category: {args.category}")
    logger.info(f"Key: {args.key}")
    logger.info(f"Dry Run: {args.dry_run}")
    logger.info("=" * 80)

    try:
        # Initialize rotator
        rotator = SecretRotator(
            environment=args.env,
            vault_url=args.vault_url,
            vault_token=args.vault_token
        )

        if args.dry_run:
            # Simulate rotation
            current = rotator.get_current_secret(args.category, args.key)
            if current:
                logger.info("DRY RUN: Would rotate the following secret:")
                logger.info(f"  Category: {args.category}")
                logger.info(f"  Key: {args.key}")
                logger.info(f"  Current value: {current[:8]}...")
                logger.info(f"  Strategy: {args.strategy}")
                logger.info(f"  Length: {args.length}")
                logger.info(f"  Grace period: {args.grace_period}h")
                logger.info("DRY RUN: No changes made")
            else:
                logger.error(f"DRY RUN: Secret not found: {args.category}/{args.key}")
        else:
            # Perform rotation
            result = rotator.rotate_secret(
                category=args.category,
                key=args.key,
                new_value=args.new_value,
                length=args.length,
                strategy=args.strategy,
                grace_period_hours=args.grace_period
            )

            if result["success"]:
                logger.info("=" * 80)
                logger.info("✓ Secret rotated successfully!")
                logger.info(f"  Rotated at: {result['rotated_at']}")
                logger.info(f"  Grace period expires: {result['grace_period_expires']}")
                logger.info(f"  New value preview: {result['new_value_preview']}")
                logger.info("=" * 80)

                # Cleanup old secrets if requested
                if args.cleanup:
                    removed = rotator.cleanup_old_secrets(args.category)
                    if removed > 0:
                        logger.info(f"✓ Cleaned up {removed} expired old secrets")

                # Remind about application restart
                logger.info("")
                logger.info("⚠️  IMPORTANT: Restart application to use new secret")
                logger.info(f"   Old secret valid until: {result['grace_period_expires']}")

                return 0
            else:
                logger.error("=" * 80)
                logger.error(f"✗ Rotation failed: {result.get('error', 'Unknown error')}")
                logger.error("=" * 80)
                return 1

        return 0

    except Exception as e:
        logger.error("=" * 80)
        logger.error(f"✗ Rotation failed: {e}")
        logger.error("=" * 80)
        return 1


if __name__ == "__main__":
    sys.exit(main())
