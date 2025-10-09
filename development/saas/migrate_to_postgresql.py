#!/usr/bin/env python3
"""
SQLite to PostgreSQL Migration Script
Migrates data from SQLite development database to PostgreSQL production database
"""

import os
import sys
from datetime import datetime
from dotenv import load_dotenv

# Load environment
load_dotenv()

try:
    from sqlalchemy import create_engine, inspect
    from sqlalchemy.orm import sessionmaker
except ImportError:
    print("Error: sqlalchemy not installed")
    print("Run: pip install sqlalchemy psycopg2-binary")
    sys.exit(1)

# Import models
sys.path.insert(0, os.path.dirname(__file__))
from database.models import Base  # noqa: E402


def get_sqlite_url():
    """Get SQLite database URL"""
    sqlite_path = os.path.join(os.path.dirname(__file__), "catalytic_saas.db")
    return f"sqlite:///{sqlite_path}"


def get_postgresql_url():
    """Get PostgreSQL database URL from environment"""
    pg_url = os.getenv("POSTGRESQL_URL") or os.getenv("DATABASE_URL")

    if not pg_url or not pg_url.startswith("postgresql"):
        print("\n" + "=" * 70)
        print("POSTGRESQL CONFIGURATION REQUIRED")
        print("=" * 70)
        print("\nTo migrate to PostgreSQL, you need to:")
        print("\n1. Install PostgreSQL:")
        print("   Windows: https://www.postgresql.org/download/windows/")
        print("   Mac: brew install postgresql")
        print("   Linux: apt-get install postgresql")
        print("\n2. Create database:")
        print("   psql -U postgres")
        print("   CREATE DATABASE catalytic_saas;")
        print("   CREATE USER catalytic WITH ENCRYPTED PASSWORD 'your_password';")
        print("   GRANT ALL PRIVILEGES ON DATABASE catalytic_saas TO catalytic;")
        print("\n3. Add to .env:")
        print(
            "   POSTGRESQL_URL=postgresql://catalytic:your_password@localhost:5432/catalytic_saas"
        )
        print("\n4. Update DATABASE_URL in .env:")
        print("   DATABASE_URL=postgresql://catalytic:your_password@localhost:5432/catalytic_saas")
        print("\n" + "=" * 70 + "\n")
        sys.exit(1)

    return pg_url


def test_postgresql_connection(pg_url):
    """Test PostgreSQL connection"""
    print("\n" + "=" * 70)
    print("TESTING POSTGRESQL CONNECTION")
    print("=" * 70 + "\n")

    try:
        engine = create_engine(pg_url, echo=False)
        with engine.connect() as conn:
            result = conn.execute("SELECT version();")
            version = result.fetchone()[0]
            print("[OK] Connected to PostgreSQL")
            print(f"  Version: {version}")
            return engine
    except Exception as e:
        print(f"[ERROR] Failed to connect to PostgreSQL: {str(e)}")
        print("\nTroubleshooting:")
        print("- Verify PostgreSQL is running")
        print("- Check connection string is correct")
        print("- Verify user has permissions")
        print("- Check firewall allows connection")
        sys.exit(1)


def backup_sqlite(sqlite_url):
    """Create backup of SQLite database"""
    print("\n" + "=" * 70)
    print("BACKING UP SQLITE DATABASE")
    print("=" * 70 + "\n")

    try:
        sqlite_path = sqlite_url.replace("sqlite:///", "")

        if not os.path.exists(sqlite_path):
            print(f"[ERROR] SQLite database not found: {sqlite_path}")
            return False

        # Create backup
        backup_path = sqlite_path.replace(
            ".db", f"_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        )

        import shutil

        shutil.copy2(sqlite_path, backup_path)

        backup_size = os.path.getsize(backup_path)
        print(f"[OK] Backup created: {backup_path}")
        print(f"  Size: {backup_size:,} bytes")
        return True

    except Exception as e:
        print(f"[ERROR] Backup failed: {str(e)}")
        return False


def analyze_sqlite_data(sqlite_engine):
    """Analyze SQLite database content"""
    print("\n" + "=" * 70)
    print("ANALYZING SQLITE DATABASE")
    print("=" * 70 + "\n")

    inspector = inspect(sqlite_engine)
    tables = inspector.get_table_names()

    SessionLocal = sessionmaker(bind=sqlite_engine)
    session = SessionLocal()

    table_info = {}

    for table in tables:
        try:
            result = session.execute(f"SELECT COUNT(*) FROM {table}")
            count = result.fetchone()[0]
            table_info[table] = count
            print(f"  {table:.<40} {count:>10} rows")
        except Exception as e:
            print(f"  {table:.<40} [ERROR: {str(e)}]")

    session.close()

    return table_info


def create_postgresql_schema(pg_engine):
    """Create PostgreSQL schema"""
    print("\n" + "=" * 70)
    print("CREATING POSTGRESQL SCHEMA")
    print("=" * 70 + "\n")

    try:
        # Drop all tables if they exist
        Base.metadata.drop_all(bind=pg_engine)
        print("[OK] Dropped existing tables")

        # Create all tables
        Base.metadata.create_all(bind=pg_engine)
        print("[OK] Created all tables")

        return True
    except Exception as e:
        print(f"[ERROR] Schema creation failed: {str(e)}")
        return False


def migrate_table_data(sqlite_session, pg_session, table_name, model_class):
    """Migrate data from one table"""
    try:
        # Get all rows from SQLite
        rows = sqlite_session.query(model_class).all()

        if not rows:
            print(f"  {table_name:.<40} 0 rows (empty)")
            return True

        # Insert into PostgreSQL
        for row in rows:
            # Create new object with same data
            pg_session.merge(row)

        pg_session.commit()

        print(f"  {table_name:.<40} {len(rows):>10} rows migrated")
        return True

    except Exception as e:
        pg_session.rollback()
        print(f"  {table_name:.<40} [ERROR: {str(e)}]")
        return False


def migrate_all_data(sqlite_engine, pg_engine):
    """Migrate all data from SQLite to PostgreSQL"""
    print("\n" + "=" * 70)
    print("MIGRATING DATA")
    print("=" * 70 + "\n")

    from database.models import (
        SubscriptionPlan,
        Tenant,
        User,
        TenantSubscription,
        StripeCustomer,
        StripePaymentMethod,
        Invoice,
        UsageRecord,
        APIKey,
        AuditLog,
        Notification,
    )

    # Order matters due to foreign key constraints
    migration_order = [
        ("subscription_plans", SubscriptionPlan),
        ("tenants", Tenant),
        ("users", User),
        ("tenant_subscriptions", TenantSubscription),
        ("stripe_customers", StripeCustomer),
        ("stripe_payment_methods", StripePaymentMethod),
        ("invoices", Invoice),
        ("usage_records", UsageRecord),
        ("api_keys", APIKey),
        ("audit_logs", AuditLog),
        ("notifications", Notification),
    ]

    SqliteSession = sessionmaker(bind=sqlite_engine)
    PgSession = sessionmaker(bind=pg_engine)

    sqlite_session = SqliteSession()
    pg_session = PgSession()

    success_count = 0
    total_count = len(migration_order)

    try:
        for table_name, model_class in migration_order:
            if migrate_table_data(sqlite_session, pg_session, table_name, model_class):
                success_count += 1

        print(f"\n[OK] Migrated {success_count}/{total_count} tables")
        return success_count == total_count

    except Exception as e:
        print(f"\n[ERROR] Migration failed: {str(e)}")
        return False
    finally:
        sqlite_session.close()
        pg_session.close()


def verify_migration(sqlite_engine, pg_engine):
    """Verify data was migrated correctly"""
    print("\n" + "=" * 70)
    print("VERIFYING MIGRATION")
    print("=" * 70 + "\n")

    inspector = inspect(sqlite_engine)
    tables = inspector.get_table_names()

    SqliteSession = sessionmaker(bind=sqlite_engine)
    PgSession = sessionmaker(bind=pg_engine)

    sqlite_session = SqliteSession()
    pg_session = PgSession()

    all_match = True

    for table in tables:
        try:
            sqlite_count = sqlite_session.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            pg_count = pg_session.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

            if sqlite_count == pg_count:
                print(f"  {table:.<40} [OK] {pg_count} rows")
            else:
                print(f"  {table:.<40} [MISMATCH] SQLite: {sqlite_count}, PostgreSQL: {pg_count}")
                all_match = False
        except Exception as e:
            print(f"  {table:.<40} [ERROR: {str(e)}]")
            all_match = False

    sqlite_session.close()
    pg_session.close()

    return all_match


def main():
    """Main migration function"""
    print("\n" + "=" * 70)
    print("CATALYTIC COMPUTING SAAS - POSTGRESQL MIGRATION")
    print("=" * 70)

    # Get database URLs
    sqlite_url = get_sqlite_url()
    pg_url = get_postgresql_url()

    print(f"\nSource (SQLite): {sqlite_url}")
    print(f"Target (PostgreSQL): {pg_url[:50]}...")

    # Test PostgreSQL connection
    pg_engine = test_postgresql_connection(pg_url)

    # Create SQLite engine
    sqlite_engine = create_engine(sqlite_url, echo=False)

    # Backup SQLite database
    if not backup_sqlite(sqlite_url):
        print("\n[ERROR] Backup failed. Migration cancelled.")
        sys.exit(1)

    # Analyze SQLite data
    analyze_sqlite_data(sqlite_engine)

    # Confirm migration
    print("\n" + "=" * 70)
    response = input("\nProceed with migration? (y/N): ")

    if response.lower() != "y":
        print("Migration cancelled.")
        sys.exit(0)

    # Create PostgreSQL schema
    if not create_postgresql_schema(pg_engine):
        print("\n[ERROR] Schema creation failed. Migration cancelled.")
        sys.exit(1)

    # Migrate data
    if not migrate_all_data(sqlite_engine, pg_engine):
        print("\n[ERROR] Data migration failed.")
        sys.exit(1)

    # Verify migration
    if verify_migration(sqlite_engine, pg_engine):
        print("\n[OK] Migration verification passed!")
    else:
        print("\n[WARN] Migration verification found mismatches.")

    print("\n" + "=" * 70)
    print("MIGRATION COMPLETE")
    print("=" * 70)
    print("\nNext steps:")
    print("1. Update DATABASE_URL in .env to use PostgreSQL:")
    print(f"   DATABASE_URL={pg_url}")
    print("2. Restart backend: uvicorn api.saas_server:app --reload")
    print("3. Test application functionality")
    print("4. Run validation: python validate-deployment.py")
    print("\nBackup location: Check output above for backup file path")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
