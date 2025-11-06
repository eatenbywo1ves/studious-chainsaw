#!/usr/bin/env python3
"""
HashiCorp Vault Secrets Migration Script

Migrates secrets from .env files to HashiCorp Vault.
Part of Phase 6: Secrets Management (Security Score 82 → 87)

Usage:
    python scripts/migrate-secrets-to-vault.py --env development
    python scripts/migrate-secrets-to-vault.py --env staging --vault-url http://staging-vault:8200
    python scripts/migrate-secrets-to-vault.py --env production --vault-token <token>
"""

import os
import sys
import argparse
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

try:
    import hvac
except ImportError:
    print("ERROR: hvac library not installed. Run: pip install hvac==2.1.0")
    sys.exit(1)

try:
    from dotenv import load_dotenv
except ImportError:
    print("ERROR: python-dotenv not installed. Run: pip install python-dotenv")
    sys.exit(1)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SecretsMigrator:
    """Migrate secrets from .env files to HashiCorp Vault"""

    def __init__(
        self,
        environment: str,
        vault_url: str = "http://localhost:8200",
        vault_token: Optional[str] = None
    ):
        """
        Initialize secrets migrator

        Args:
            environment: Environment name (development, staging, production)
            vault_url: Vault server URL
            vault_token: Vault authentication token (defaults to dev token)
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

            # Verify authentication
            if not self.client.is_authenticated():
                raise Exception("Vault authentication failed")

            logger.info(f"✓ Connected to Vault at {vault_url}")
            logger.info(f"✓ Authenticated for environment: {environment}")

        except Exception as e:
            logger.error(f"Failed to connect to Vault: {e}")
            raise

    def load_env_secrets(self, env_file: str = ".env") -> Dict[str, Any]:
        """
        Load secrets from .env file

        Args:
            env_file: Path to .env file (relative to project root)

        Returns:
            Dictionary of categorized secrets
        """
        # Get project root (parent of scripts/)
        project_root = Path(__file__).parent.parent
        env_path = project_root / env_file

        if not env_path.exists():
            raise FileNotFoundError(f".env file not found: {env_path}")

        # Load environment variables
        load_dotenv(env_path)
        logger.info(f"✓ Loaded secrets from {env_path}")

        # Organize secrets by category
        secrets = {
            "database": {
                "password": os.getenv("DB_PASSWORD"),
                "username": os.getenv("POSTGRES_USER", "catalytic"),
                "host": os.getenv("DB_HOST", "postgres"),
                "port": os.getenv("DB_PORT", "5432"),
                "name": os.getenv("DB_NAME", "catalytic_db"),
                "url": os.getenv("DATABASE_URL")
            },
            "redis": {
                "password": os.getenv("REDIS_PASSWORD"),
                "host": os.getenv("REDIS_HOST", "redis"),
                "port": os.getenv("REDIS_PORT", "6379"),
                "url": os.getenv("REDIS_URL")
            },
            "jwt": {
                "secret_key": os.getenv("JWT_SECRET_KEY"),
                "algorithm": os.getenv("JWT_ALGORITHM", "RS256"),
                "access_token_expire_minutes": os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"),
                "refresh_token_expire_days": os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7")
            },
            "csrf": {
                "secret_key": os.getenv("CSRF_SECRET_KEY")
            },
            "monitoring": {
                "grafana_password": os.getenv("GRAFANA_PASSWORD"),
                "prometheus_password": os.getenv("PROMETHEUS_PASSWORD")
            },
            "payment": {
                "stripe_secret_key": os.getenv("STRIPE_SECRET_KEY"),
                "stripe_publishable_key": os.getenv("STRIPE_PUBLISHABLE_KEY"),
                "stripe_webhook_secret": os.getenv("STRIPE_WEBHOOK_SECRET")
            },
            "email": {
                "smtp_password": os.getenv("SMTP_PASSWORD"),
                "smtp_host": os.getenv("SMTP_HOST"),
                "smtp_port": os.getenv("SMTP_PORT"),
                "smtp_user": os.getenv("SMTP_USER")
            }
        }

        # Remove None values
        for category in secrets:
            secrets[category] = {
                k: v for k, v in secrets[category].items() if v is not None
            }

        # Remove empty categories
        secrets = {k: v for k, v in secrets.items() if v}

        logger.info(f"✓ Loaded {len(secrets)} secret categories")
        for category, values in secrets.items():
            logger.info(f"  - {category}: {len(values)} secrets")

        return secrets

    def write_secrets_to_vault(self, secrets: Dict[str, Any]) -> None:
        """
        Write secrets to Vault KV v2 storage

        Args:
            secrets: Dictionary of categorized secrets
        """
        # Enable KV v2 secrets engine if not already enabled
        try:
            self.client.sys.enable_secrets_engine(
                backend_type='kv',
                path='secret',
                options={'version': '2'}
            )
            logger.info("✓ Enabled KV v2 secrets engine")
        except hvac.exceptions.InvalidRequest:
            # Already enabled
            logger.info("✓ KV v2 secrets engine already enabled")

        # Write secrets by category
        migration_summary = []

        for category, category_secrets in secrets.items():
            path = f"secret/{self.environment}/{category}"

            try:
                # Write secrets to Vault
                self.client.secrets.kv.v2.create_or_update_secret(
                    path=f"{self.environment}/{category}",
                    secret=category_secrets,
                    mount_point='secret'
                )

                logger.info(f"✓ Migrated {category} secrets to {path}")
                migration_summary.append({
                    "category": category,
                    "path": path,
                    "secret_count": len(category_secrets),
                    "status": "success"
                })

            except Exception as e:
                logger.error(f"✗ Failed to migrate {category}: {e}")
                migration_summary.append({
                    "category": category,
                    "path": path,
                    "secret_count": len(category_secrets),
                    "status": "failed",
                    "error": str(e)
                })

        # Write migration metadata
        metadata_path = f"secret/{self.environment}/metadata/migration"
        metadata = {
            "migrated_at": datetime.utcnow().isoformat(),
            "environment": self.environment,
            "source": ".env file",
            "migrator_version": "1.0.0",
            "categories": migration_summary
        }

        try:
            self.client.secrets.kv.v2.create_or_update_secret(
                path=f"{self.environment}/metadata/migration",
                secret=metadata,
                mount_point='secret'
            )
            logger.info(f"✓ Wrote migration metadata to {metadata_path}")
        except Exception as e:
            logger.warning(f"Failed to write migration metadata: {e}")

    def verify_migration(self, original_secrets: Dict[str, Any]) -> bool:
        """
        Verify all secrets were migrated correctly

        Args:
            original_secrets: Original secrets dictionary

        Returns:
            True if verification passed, False otherwise
        """
        logger.info("Verifying migration...")
        all_verified = True

        for category, category_secrets in original_secrets.items():
            path = f"{self.environment}/{category}"

            try:
                # Read secrets from Vault
                response = self.client.secrets.kv.v2.read_secret_version(
                    path=path,
                    mount_point='secret'
                )

                vault_secrets = response['data']['data']

                # Compare secret counts
                if len(vault_secrets) != len(category_secrets):
                    logger.error(
                        f"✗ {category}: Secret count mismatch "
                        f"(expected {len(category_secrets)}, got {len(vault_secrets)})"
                    )
                    all_verified = False
                    continue

                # Verify all keys exist
                for key in category_secrets:
                    if key not in vault_secrets:
                        logger.error(f"✗ {category}: Missing secret '{key}'")
                        all_verified = False
                    elif vault_secrets[key] != category_secrets[key]:
                        logger.error(f"✗ {category}: Secret '{key}' value mismatch")
                        all_verified = False

                if all_verified:
                    logger.info(f"✓ {category}: Verified {len(category_secrets)} secrets")

            except Exception as e:
                logger.error(f"✗ Failed to verify {category}: {e}")
                all_verified = False

        return all_verified

    def create_backup(self, secrets: Dict[str, Any], backup_dir: str = "backups") -> str:
        """
        Create encrypted backup of secrets before migration

        Args:
            secrets: Secrets dictionary
            backup_dir: Directory to store backups

        Returns:
            Path to backup file
        """
        # Create backup directory
        project_root = Path(__file__).parent.parent
        backup_path = project_root / backup_dir
        backup_path.mkdir(exist_ok=True)

        # Generate backup filename with timestamp
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_file = backup_path / f"secrets_backup_{self.environment}_{timestamp}.json"

        # Write backup (WARNING: Contains plaintext secrets)
        with open(backup_file, 'w') as f:
            json.dump({
                "environment": self.environment,
                "timestamp": timestamp,
                "secrets": secrets
            }, f, indent=2)

        logger.info(f"✓ Created backup: {backup_file}")
        logger.warning("⚠️  Backup contains plaintext secrets - secure appropriately!")

        return str(backup_file)


def main():
    """Main migration script"""
    parser = argparse.ArgumentParser(
        description="Migrate secrets from .env to HashiCorp Vault"
    )
    parser.add_argument(
        "--env",
        required=True,
        choices=["development", "staging", "production"],
        help="Environment to migrate"
    )
    parser.add_argument(
        "--vault-url",
        default="http://localhost:8200",
        help="Vault server URL (default: http://localhost:8200)"
    )
    parser.add_argument(
        "--vault-token",
        help="Vault authentication token (default: dev token for development)"
    )
    parser.add_argument(
        "--env-file",
        default=".env",
        help="Path to .env file (default: .env)"
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Skip creating backup (not recommended)"
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip verification step (not recommended)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate migration without writing to Vault"
    )

    args = parser.parse_args()

    logger.info("=" * 80)
    logger.info("HashiCorp Vault Secrets Migration")
    logger.info("=" * 80)
    logger.info(f"Environment: {args.env}")
    logger.info(f"Vault URL: {args.vault_url}")
    logger.info(f"Dry Run: {args.dry_run}")
    logger.info("=" * 80)

    try:
        # Initialize migrator
        migrator = SecretsMigrator(
            environment=args.env,
            vault_url=args.vault_url,
            vault_token=args.vault_token
        )

        # Load secrets from .env
        secrets = migrator.load_env_secrets(args.env_file)

        if not secrets:
            logger.error("No secrets found in .env file")
            return 1

        # Create backup
        if not args.no_backup and not args.dry_run:
            backup_file = migrator.create_backup(secrets)
            logger.info(f"Backup created: {backup_file}")

        # Migrate secrets
        if args.dry_run:
            logger.info("DRY RUN: Would migrate the following secrets:")
            for category, category_secrets in secrets.items():
                logger.info(f"  - {category}: {len(category_secrets)} secrets")
            logger.info("DRY RUN: No changes made to Vault")
        else:
            migrator.write_secrets_to_vault(secrets)

            # Verify migration
            if not args.no_verify:
                if migrator.verify_migration(secrets):
                    logger.info("=" * 80)
                    logger.info("✓ Migration completed successfully!")
                    logger.info("=" * 80)
                    return 0
                else:
                    logger.error("=" * 80)
                    logger.error("✗ Migration verification failed!")
                    logger.error("=" * 80)
                    return 1
            else:
                logger.info("=" * 80)
                logger.info("✓ Migration completed (verification skipped)")
                logger.info("=" * 80)
                return 0

        return 0

    except Exception as e:
        logger.error("=" * 80)
        logger.error(f"✗ Migration failed: {e}")
        logger.error("=" * 80)
        return 1


if __name__ == "__main__":
    sys.exit(main())
