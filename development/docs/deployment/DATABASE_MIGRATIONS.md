# Database Migration Procedures

## SaaS Platform - Database Migration Guide

**Last Updated**: 2025-10-06

---

## Table of Contents

1. [Overview](#overview)
2. [Migration Strategy](#migration-strategy)
3. [Pre-Migration Checklist](#pre-migration-checklist)
4. [Migration Procedures](#migration-procedures)
5. [Rollback Procedures](#rollback-procedures)
6. [Best Practices](#best-practices)

---

## Overview

### Current Database Schema

The Catalytic Computing SaaS platform uses the following database models:

- **Tenants**: Multi-tenant isolation
- **Users**: User authentication and authorization
- **Subscriptions**: Subscription plans and billing
- **API Logs**: API usage tracking
- **Tenant Lattices**: Lattice storage per tenant
- **Lattice Operations**: Operation history
- **Webhooks**: Webhook configurations
- **Webhook Deliveries**: Webhook delivery logs

### Migration Tools

**Primary**: SQLAlchemy ORM with manual migrations
**Alternative**: Alembic (if configured)

---

## Migration Strategy

### Zero-Downtime Migration Approach

1. **Backwards Compatible Changes First**
   - Add new columns (nullable or with defaults)
   - Create new tables
   - Add indexes

2. **Deploy Application**
   - Deploy application that works with both old and new schema
   - Gradually migrate data

3. **Complete Migration**
   - Remove old columns/tables after data migration
   - Deploy application using only new schema

### Migration Types

| Type | Downtime | Complexity | Example |
|------|----------|------------|---------|
| **Additive** | None | Low | Add new column, Add new table |
| **Modify** | Minimal | Medium | Change column type, Add NOT NULL |
| **Destructive** | Potential | High | Drop column, Drop table |

---

## Pre-Migration Checklist

### Before ANY Migration

- [ ] **Backup Database**
  ```bash
  # PostgreSQL
  pg_dump -Fc catalytic_saas > backups/pre_migration_$(date +%Y%m%d_%H%M%S).dump

  # SQLite
  sqlite3 catalytic_saas.db ".backup backups/pre_migration_$(date +%Y%m%d_%H%M%S).db"
  ```

- [ ] **Test Migration on Staging**
  - Apply migration to staging database
  - Verify application works
  - Test rollback procedure
  - Measure migration time

- [ ] **Verify Backup**
  ```bash
  # Test restore to temporary database
  ./scripts/test-restore.sh backup_file.dump
  ```

- [ ] **Plan Rollback**
  - Document rollback steps
  - Prepare rollback scripts
  - Test rollback on staging

- [ ] **Schedule Maintenance Window** (if needed)
  - Notify users
  - Update status page
  - Coordinate with team

- [ ] **Review Migration SQL**
  - Peer review migration script
  - Verify no destructive operations
  - Check for locking issues

---

## Migration Procedures

### Scenario 1: Add New Column (Zero Downtime)

**Example**: Add `phone_number` to `users` table

**Step 1: Create Migration**

```sql
-- migrations/001_add_user_phone.sql
ALTER TABLE users ADD COLUMN phone_number VARCHAR(20) NULL;
```

**Step 2: Apply Migration**

```bash
# PostgreSQL
psql ${DATABASE_URL} -f migrations/001_add_user_phone.sql

# Verify
psql ${DATABASE_URL} -c "\d users"
```

**Step 3: Deploy Application**

```python
# Update User model
class User(Base):
    # ... existing fields ...
    phone_number = Column(String(20), nullable=True)  # Nullable for backwards compatibility
```

```bash
# Deploy new version
kubectl set image deployment/catalytic-saas-api \
  catalytic-saas-api=${REGISTRY}/catalytic-saas-api:v1.1.0 \
  -n catalytic-saas
```

**Step 4: Backfill Data (if needed)**

```python
# scripts/backfill_phone_numbers.py
from database.models import User
from sqlalchemy.orm import sessionmaker

# Update users with phone numbers from external source
for user in session.query(User).filter(User.phone_number.is_(None)):
    user.phone_number = get_phone_number(user.email)
    session.commit()
```

---

### Scenario 2: Modify Column (Minimal Downtime)

**Example**: Change `email` from VARCHAR(100) to VARCHAR(255)

**Step 1: Check Data**

```sql
-- Verify no data will be truncated
SELECT MAX(LENGTH(email)) FROM users;
-- Result: 87 (safe to proceed)
```

**Step 2: Create Migration**

```sql
-- migrations/002_expand_email_length.sql

-- PostgreSQL
ALTER TABLE users ALTER COLUMN email TYPE VARCHAR(255);

-- SQLite (requires recreation)
BEGIN TRANSACTION;

-- Create new table
CREATE TABLE users_new (
  id INTEGER PRIMARY KEY,
  email VARCHAR(255) NOT NULL,
  -- ... other columns ...
);

-- Copy data
INSERT INTO users_new SELECT * FROM users;

-- Drop old table
DROP TABLE users;

-- Rename new table
ALTER TABLE users_new RENAME TO users;

COMMIT;
```

**Step 3: Apply Migration**

```bash
# PostgreSQL (fast, no downtime)
psql ${DATABASE_URL} -f migrations/002_expand_email_length.sql

# SQLite (requires brief downtime)
# 1. Stop application
kubectl scale deployment/catalytic-saas-api -n catalytic-saas --replicas=0

# 2. Apply migration
sqlite3 catalytic_saas.db < migrations/002_expand_email_length.sql

# 3. Restart application
kubectl scale deployment/catalytic-saas-api -n catalytic-saas --replicas=3
```

---

### Scenario 3: Add New Table (Zero Downtime)

**Example**: Add `api_keys` table

**Step 1: Create Migration**

```sql
-- migrations/003_add_api_keys_table.sql
CREATE TABLE api_keys (
  id SERIAL PRIMARY KEY,
  tenant_id INTEGER NOT NULL,
  key_hash VARCHAR(255) NOT NULL,
  key_prefix VARCHAR(20) NOT NULL,
  name VARCHAR(100),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_used_at TIMESTAMP,
  is_active BOOLEAN DEFAULT true,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

CREATE INDEX idx_api_keys_tenant ON api_keys(tenant_id);
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);
```

**Step 2: Apply Migration**

```bash
psql ${DATABASE_URL} -f migrations/003_add_api_keys_table.sql
```

**Step 3: Deploy Application with New Model**

```python
# database/models.py
class ApiKey(Base):
    __tablename__ = 'api_keys'

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey('tenants.id'), nullable=False)
    key_hash = Column(String(255), nullable=False)
    key_prefix = Column(String(20), nullable=False)
    name = Column(String(100))
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime)
    is_active = Column(Boolean, default=True)
```

---

### Scenario 4: Add NOT NULL Constraint (Two-Phase)

**Example**: Make `tenant_id` NOT NULL in `lattices` table

**Phase 1: Add Column as Nullable**

```sql
-- Already exists as nullable
ALTER TABLE lattices ADD COLUMN tenant_id INTEGER NULL;
```

**Phase 2: Backfill Data**

```python
# scripts/backfill_tenant_id.py
for lattice in session.query(Lattice).filter(Lattice.tenant_id.is_(None)):
    # Assign to appropriate tenant
    lattice.tenant_id = get_tenant_for_lattice(lattice.id)
    session.commit()
```

**Phase 3: Verify All Rows Have Value**

```sql
SELECT COUNT(*) FROM lattices WHERE tenant_id IS NULL;
-- Result: 0 (safe to proceed)
```

**Phase 4: Add NOT NULL Constraint**

```sql
-- migrations/004_lattices_tenant_not_null.sql
ALTER TABLE lattices ALTER COLUMN tenant_id SET NOT NULL;
```

```bash
# Apply migration
psql ${DATABASE_URL} -f migrations/004_lattices_tenant_not_null.sql
```

---

### Scenario 5: Drop Column (Backwards Compatible)

**Example**: Remove deprecated `legacy_id` column

**Step 1: Deploy Application Not Using Column**

```python
# Remove legacy_id from User model
class User(Base):
    # ... (no more legacy_id) ...
    pass
```

**Step 2: Wait for Full Deployment**

```bash
# Ensure all pods are running new version
kubectl rollout status deployment/catalytic-saas-api -n catalytic-saas
```

**Step 3: Drop Column**

```sql
-- migrations/005_drop_legacy_id.sql
ALTER TABLE users DROP COLUMN legacy_id;
```

```bash
# Apply migration
psql ${DATABASE_URL} -f migrations/005_drop_legacy_id.sql
```

---

### Scenario 6: Add Index (Production Safe)

**Example**: Add index to improve query performance

**Step 1: Check Index Impact**

```sql
-- Estimate index size
SELECT pg_size_pretty(pg_relation_size('users'));

-- Check table lock status
SELECT * FROM pg_locks WHERE relation = 'users'::regclass;
```

**Step 2: Create Index CONCURRENTLY** (PostgreSQL)

```sql
-- migrations/006_add_email_index.sql
CREATE INDEX CONCURRENTLY idx_users_email ON users(email);
```

```bash
# Apply migration (no locking)
psql ${DATABASE_URL} -f migrations/006_add_email_index.sql
```

**For SQLite** (requires brief lock):

```sql
CREATE INDEX idx_users_email ON users(email);
```

---

## Rollback Procedures

### Automatic Rollback Criteria

Execute rollback if:
- Migration fails with error
- Data integrity check fails
- Application errors after migration
- Performance degradation > 50%

### Rollback Methods

#### Method 1: SQL Rollback Script

```sql
-- rollback/005_drop_legacy_id_rollback.sql
ALTER TABLE users ADD COLUMN legacy_id INTEGER NULL;

-- Optionally restore data from backup
-- COPY users (id, legacy_id) FROM '/tmp/legacy_id_backup.csv';
```

#### Method 2: Database Restore

```bash
# Full database restore
./scripts/restore-database.sh production backup_20251006_120000.dump
```

#### Method 3: Point-in-Time Recovery (PostgreSQL)

```bash
# Restore to time before migration
pg_restore --time "2025-10-06 12:00:00" \
  -d catalytic_saas backup.dump
```

### Rollback Checklist

- [ ] Stop application (if needed)
  ```bash
  kubectl scale deployment/catalytic-saas-api -n catalytic-saas --replicas=0
  ```

- [ ] Execute rollback SQL or restore database
  ```bash
  psql ${DATABASE_URL} -f rollback/migration_rollback.sql
  ```

- [ ] Verify database state
  ```sql
  -- Check schema
  \d table_name

  -- Verify data
  SELECT COUNT(*) FROM table_name;
  ```

- [ ] Rollback application deployment
  ```bash
  kubectl rollout undo deployment/catalytic-saas-api -n catalytic-saas
  ```

- [ ] Run smoke tests
  ```bash
  cd tests/smoke && ./smoke_test_runner.sh
  ```

- [ ] Resume application
  ```bash
  kubectl scale deployment/catalytic-saas-api -n catalytic-saas --replicas=3
  ```

---

## Best Practices

### DO's ✅

1. **Always Backup Before Migration**
   ```bash
   # Automated backup in migration script
   pg_dump -Fc catalytic_saas > backups/pre_migration_$(date +%Y%m%d_%H%M%S).dump
   ```

2. **Test on Staging First**
   - Apply migration to staging
   - Verify application compatibility
   - Measure performance impact

3. **Use Transactions**
   ```sql
   BEGIN;
   -- migration SQL
   COMMIT;
   ```

4. **Add Columns as Nullable First**
   ```sql
   -- Phase 1: Add nullable
   ALTER TABLE users ADD COLUMN phone VARCHAR(20) NULL;

   -- Phase 2: Backfill data
   UPDATE users SET phone = ...;

   -- Phase 3: Make NOT NULL (later)
   ALTER TABLE users ALTER COLUMN phone SET NOT NULL;
   ```

5. **Create Indexes CONCURRENTLY** (PostgreSQL)
   ```sql
   CREATE INDEX CONCURRENTLY idx_name ON table(column);
   ```

6. **Version Migrations**
   - Migrations/001_initial.sql
   - Migrations/002_add_feature.sql
   - Track applied migrations in database

7. **Document Rollback Procedure**
   - Create rollback script for each migration
   - Test rollback on staging

### DON'Ts ❌

1. **Don't Drop Columns Immediately**
   - Mark as deprecated first
   - Remove references in code
   - Drop column in separate migration

2. **Don't Add NOT NULL Without Defaults**
   ```sql
   -- BAD: Will fail if any NULL values exist
   ALTER TABLE users ALTER COLUMN email SET NOT NULL;

   -- GOOD: Set default or backfill first
   UPDATE users SET email = 'unknown@example.com' WHERE email IS NULL;
   ALTER TABLE users ALTER COLUMN email SET NOT NULL;
   ```

3. **Don't Modify Large Tables During Peak Hours**
   - Schedule migrations during off-peak
   - Use maintenance windows for large changes

4. **Don't Mix Schema and Data Changes**
   ```sql
   -- BAD: Schema and data in same transaction
   BEGIN;
   ALTER TABLE users ADD COLUMN verified BOOLEAN DEFAULT false;
   UPDATE users SET verified = true WHERE email_verified_at IS NOT NULL;
   COMMIT;

   -- GOOD: Separate migrations
   -- Migration 1: Add column
   -- Migration 2: Backfill data
   ```

5. **Don't Forget Foreign Key Constraints**
   - Always add appropriate foreign keys
   - Use ON DELETE CASCADE carefully

---

## Migration Script Template

```bash
#!/bin/bash
# migrate.sh - Database migration script template

set -e  # Exit on error

MIGRATION_NAME="${1}"
MIGRATION_FILE="migrations/${MIGRATION_NAME}.sql"
ROLLBACK_FILE="rollback/${MIGRATION_NAME}_rollback.sql"
DATABASE_URL="${DATABASE_URL}"

if [ -z "${MIGRATION_NAME}" ]; then
  echo "Usage: ./migrate.sh <migration_name>"
  exit 1
fi

if [ ! -f "${MIGRATION_FILE}" ]; then
  echo "Migration file not found: ${MIGRATION_FILE}"
  exit 1
fi

echo "=========================================="
echo "Database Migration: ${MIGRATION_NAME}"
echo "=========================================="

# Step 1: Backup database
echo "Step 1: Creating backup..."
BACKUP_FILE="backups/pre_${MIGRATION_NAME}_$(date +%Y%m%d_%H%M%S).dump"
pg_dump -Fc ${DATABASE_URL} > ${BACKUP_FILE}
echo "✅ Backup created: ${BACKUP_FILE}"

# Step 2: Review migration
echo "Step 2: Reviewing migration SQL..."
cat ${MIGRATION_FILE}
echo ""
read -p "Apply this migration? (yes/no): " CONFIRM

if [ "${CONFIRM}" != "yes" ]; then
  echo "❌ Migration cancelled"
  exit 0
fi

# Step 3: Apply migration
echo "Step 3: Applying migration..."
START_TIME=$(date +%s)

if psql ${DATABASE_URL} -f ${MIGRATION_FILE}; then
  END_TIME=$(date +%s)
  DURATION=$((END_TIME - START_TIME))
  echo "✅ Migration applied successfully in ${DURATION} seconds"
else
  echo "❌ Migration failed!"

  # Attempt rollback
  if [ -f "${ROLLBACK_FILE}" ]; then
    echo "Attempting rollback..."
    psql ${DATABASE_URL} -f ${ROLLBACK_FILE}
    echo "✅ Rollback completed"
  else
    echo "⚠️  No rollback file found: ${ROLLBACK_FILE}"
    echo "   Restore from backup: ${BACKUP_FILE}"
  fi

  exit 1
fi

# Step 4: Verify migration
echo "Step 4: Verifying migration..."
psql ${DATABASE_URL} -c "\dt"  # List tables

echo "=========================================="
echo "Migration Complete!"
echo "=========================================="
echo "Backup: ${BACKUP_FILE}"
echo "Duration: ${DURATION} seconds"
```

### Usage

```bash
# Apply migration
./scripts/migrate.sh 007_add_api_keys

# Rollback if needed
psql ${DATABASE_URL} -f rollback/007_add_api_keys_rollback.sql
```

---

## SQLite to PostgreSQL Migration

If migrating from SQLite to PostgreSQL:

### Step 1: Export from SQLite

```bash
# Dump SQLite schema
sqlite3 catalytic_saas.db .schema > sqlite_schema.sql

# Export data
sqlite3 catalytic_saas.db <<EOF
.mode csv
.headers on
.output tenants.csv
SELECT * FROM tenants;
.output users.csv
SELECT * FROM users;
-- ... repeat for all tables ...
EOF
```

### Step 2: Create PostgreSQL Schema

```sql
-- Convert SQLite schema to PostgreSQL
-- Replace AUTOINCREMENT with SERIAL
-- Replace TEXT with VARCHAR
-- Add explicit constraints
```

### Step 3: Import Data

```bash
# Import data into PostgreSQL
psql ${DATABASE_URL} <<EOF
COPY tenants FROM '/path/to/tenants.csv' WITH CSV HEADER;
COPY users FROM '/path/to/users.csv' WITH CSV HEADER;
-- ... repeat for all tables ...
EOF
```

### Step 4: Verify Data Integrity

```sql
-- Compare record counts
SELECT 'tenants' as table, COUNT(*) FROM tenants
UNION ALL
SELECT 'users', COUNT(*) FROM users;
-- Compare with SQLite counts
```

---

**Last Updated**: 2025-10-06
**Maintained By**: Database Team & DevOps
**Review Before**: Each migration
