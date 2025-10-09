#!/usr/bin/env python3
"""
Database Migration Script: SQLite to PostgreSQL
Safely migrates development data to production PostgreSQL database
"""

import os
import sys
from pathlib import Path
from datetime import datetime
import argparse
from typing import Dict

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from database.models import (
    Base,
    Tenant,
    User,
    Subscription,
    ApiKey,
    UsageLog,
    AuditLog,
    Webhook,
    WebhookDelivery,
)


class DatabaseMigrator:
    """Handles migration from SQLite to PostgreSQL"""

    def __init__(self, source_url: str, target_url: str, dry_run: bool = False):
        self.source_url = source_url
        self.target_url = target_url
        self.dry_run = dry_run
        self.migration_log = []

        # Create engines
        if source_url.startswith("sqlite"):
            self.source_engine = create_engine(
                source_url, connect_args={"check_same_thread": False}
            )
        else:
            self.source_engine = create_engine(source_url)

        if target_url.startswith("sqlite"):
            self.target_engine = create_engine(
                target_url, connect_args={"check_same_thread": False}
            )
        else:
            self.target_engine = create_engine(target_url, pool_pre_ping=True)

        # Create sessions
        self.SourceSession = sessionmaker(bind=self.source_engine)
        self.TargetSession = sessionmaker(bind=self.target_engine)

    def log(self, message: str, level: str = "INFO"):
        """Log migration activity"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        self.migration_log.append(log_entry)
        print(log_entry)

    def verify_connections(self) -> bool:
        """Verify database connections"""
        self.log("Verifying database connections...")

        try:
            with self.source_engine.connect() as conn:
                result = conn.execute(text("SELECT 1"))
                result.fetchone()
            self.log("✓ Source database connection successful")
        except Exception as e:
            self.log(f"✗ Source database connection failed: {e}", "ERROR")
            return False

        try:
            with self.target_engine.connect() as conn:
                result = conn.execute(text("SELECT 1"))
                result.fetchone()
            self.log("✓ Target database connection successful")
        except Exception as e:
            self.log(f"✗ Target database connection failed: {e}", "ERROR")
            return False

        return True

    def create_target_schema(self):
        """Create schema in target database"""
        self.log("Creating target database schema...")

        if self.dry_run:
            self.log("[DRY RUN] Would create tables in target database", "INFO")
            return

        Base.metadata.create_all(self.target_engine)
        self.log("✓ Target schema created")

    def get_table_row_count(self, engine, table_name: str) -> int:
        """Get row count for a table"""
        with engine.connect() as conn:
            result = conn.execute(text(f"SELECT COUNT(*) FROM {table_name}"))
            return result.scalar()

    def migrate_table_data(self, model_class):
        """Migrate data for a specific model"""
        table_name = model_class.__tablename__
        self.log(f"Migrating table: {table_name}")

        source_session = self.SourceSession()
        target_session = self.TargetSession()

        try:
            # Get source data
            source_records = source_session.query(model_class).all()
            record_count = len(source_records)

            self.log(f"  Found {record_count} records in source")

            if record_count == 0:
                self.log(f"  No records to migrate for {table_name}")
                return

            if self.dry_run:
                self.log(f"  [DRY RUN] Would migrate {record_count} records", "INFO")
                return

            # Check if target has data
            target_count = target_session.query(model_class).count()
            if target_count > 0:
                self.log(f"  WARNING: Target has {target_count} existing records", "WARNING")
                user_input = input(f"    Clear existing {table_name} data? (y/N): ")
                if user_input.lower() == "y":
                    target_session.query(model_class).delete()
                    target_session.commit()
                    self.log(f"  Cleared {target_count} existing records")

            # Migrate records
            migrated = 0
            errors = []

            for record in source_records:
                try:
                    # Create new instance with same data
                    record_dict = {
                        c.name: getattr(record, c.name) for c in record.__table__.columns
                    }

                    new_record = model_class(**record_dict)
                    target_session.add(new_record)
                    migrated += 1

                    if migrated % 100 == 0:
                        target_session.commit()
                        self.log(f"  Migrated {migrated}/{record_count} records...")

                except Exception as e:
                    errors.append(str(e))
                    self.log(f"  Error migrating record: {e}", "ERROR")

            # Final commit
            target_session.commit()

            if errors:
                self.log(
                    f"  ✓ Migrated {migrated}/{record_count} records with {len(errors)} errors",
                    "WARNING",
                )
            else:
                self.log(f"  ✓ Successfully migrated {migrated}/{record_count} records")

        except Exception as e:
            target_session.rollback()
            self.log(f"  ✗ Migration failed for {table_name}: {e}", "ERROR")
            raise

        finally:
            source_session.close()
            target_session.close()

    def verify_migration(self) -> Dict[str, Dict[str, int]]:
        """Verify migration by comparing record counts"""
        self.log("Verifying migration...")

        models = [Tenant, User, Subscription, ApiKey, UsageLog, AuditLog, Webhook, WebhookDelivery]
        results = {}

        for model in models:
            table_name = model.__tablename__

            source_count = self.get_table_row_count(self.source_engine, table_name)
            target_count = self.get_table_row_count(self.target_engine, table_name)

            results[table_name] = {
                "source": source_count,
                "target": target_count,
                "match": source_count == target_count,
            }

            status = "✓" if source_count == target_count else "✗"
            self.log(f"  {status} {table_name}: source={source_count}, target={target_count}")

        return results

    def create_backup(self, db_url: str, backup_path: str):
        """Create backup of database"""
        self.log(f"Creating backup: {backup_path}")

        if db_url.startswith("sqlite"):
            # SQLite: just copy the file
            import shutil

            db_file = db_url.replace("sqlite:///", "")
            shutil.copy2(db_file, backup_path)
            self.log("✓ SQLite backup created")

        elif db_url.startswith("postgresql"):
            # PostgreSQL: use pg_dump
            import subprocess

            result = subprocess.run(["pg_dump", db_url, "-f", backup_path], capture_output=True)
            if result.returncode == 0:
                self.log("✓ PostgreSQL backup created")
            else:
                self.log(f"✗ Backup failed: {result.stderr.decode()}", "ERROR")

    def migrate(self):
        """Execute full migration"""
        self.log("=" * 80)
        self.log("DATABASE MIGRATION: SQLite → PostgreSQL")
        self.log("=" * 80)

        if self.dry_run:
            self.log("DRY RUN MODE - No changes will be made", "INFO")

        # Step 1: Verify connections
        if not self.verify_connections():
            self.log("Connection verification failed. Aborting.", "ERROR")
            return False

        # Step 2: Create target schema
        self.create_target_schema()

        # Step 3: Migrate data (order matters due to foreign keys)
        migration_order = [
            Tenant,
            User,
            Subscription,
            ApiKey,
            UsageLog,
            AuditLog,
            Webhook,
            WebhookDelivery,
        ]

        for model in migration_order:
            try:
                self.migrate_table_data(model)
            except Exception as e:
                self.log(f"Migration failed for {model.__tablename__}: {e}", "ERROR")
                if not self.dry_run:
                    user_input = input("Continue with remaining tables? (y/N): ")
                    if user_input.lower() != "y":
                        return False

        # Step 4: Verify migration
        if not self.dry_run:
            verification_results = self.verify_migration()

            # Check if all tables match
            all_match = all(r["match"] for r in verification_results.values())

            if all_match:
                self.log("=" * 80)
                self.log("✓ MIGRATION COMPLETED SUCCESSFULLY", "SUCCESS")
                self.log("=" * 80)
            else:
                self.log("=" * 80)
                self.log("✗ MIGRATION COMPLETED WITH DISCREPANCIES", "WARNING")
                self.log("=" * 80)

        # Step 5: Save migration log
        log_file = f"migration_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(log_file, "w") as f:
            f.write("\n".join(self.migration_log))
        self.log(f"Migration log saved: {log_file}")

        return True


def main():
    """Main migration function"""
    parser = argparse.ArgumentParser(description="Migrate SQLite database to PostgreSQL")
    parser.add_argument(
        "--source",
        default="sqlite:///C:/Users/Corbin/development/saas/catalytic_saas.db",
        help="Source database URL (default: SQLite development DB)",
    )
    parser.add_argument("--target", help="Target database URL (PostgreSQL production DB)")
    parser.add_argument("--dry-run", action="store_true", help="Run in dry-run mode (no changes)")
    parser.add_argument("--backup", action="store_true", help="Create backup before migration")

    args = parser.parse_args()

    # Get target URL from environment if not provided
    if not args.target:
        from dotenv import load_dotenv

        load_dotenv(".env.production")
        args.target = os.getenv("DATABASE_URL")

        if not args.target:
            print(
                "ERROR: Target database URL not provided and DATABASE_URL not set in .env.production"
            )
            sys.exit(1)

    # Validate URLs
    if args.source == args.target:
        print("ERROR: Source and target databases cannot be the same")
        sys.exit(1)

    # Create migrator
    migrator = DatabaseMigrator(
        source_url=args.source, target_url=args.target, dry_run=args.dry_run
    )

    # Create backup if requested
    if args.backup and not args.dry_run:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"backup_before_migration_{timestamp}.sql"
        migrator.create_backup(args.source, backup_path)

    # Run migration
    success = migrator.migrate()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
