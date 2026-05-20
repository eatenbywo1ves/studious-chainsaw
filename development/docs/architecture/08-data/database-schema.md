# Data Architecture: Database Schema

## Entity Relationship Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Database Schema                                     │
│                                                                              │
│  ┌───────────────┐     ┌───────────────┐     ┌───────────────────────────┐ │
│  │    tenants    │     │     users     │     │      subscriptions        │ │
│  ├───────────────┤     ├───────────────┤     ├───────────────────────────┤ │
│  │ id (PK)       │──┐  │ id (PK)       │──┐  │ id (PK)                   │ │
│  │ name          │  │  │ tenant_id (FK)│◄─┘  │ user_id (FK)              │◄┘│
│  │ plan          │  │  │ email         │     │ tenant_id (FK)            │  │
│  │ created_at    │  │  │ password_hash │     │ stripe_subscription_id    │  │
│  └───────────────┘  │  │ is_active     │     │ status                    │  │
│                     │  │ created_at    │     │ current_period_end        │  │
│                     │  └───────────────┘     └───────────────────────────┘  │
│                     │                                                        │
│                     │  ┌───────────────┐     ┌───────────────────────────┐ │
│                     │  │  api_keys     │     │     analysis_jobs         │ │
│                     │  ├───────────────┤     ├───────────────────────────┤ │
│                     └─►│ id (PK)       │     │ id (PK)                   │ │
│                        │ tenant_id (FK)│     │ tenant_id (FK)            │ │
│                        │ user_id (FK)  │     │ user_id (FK)              │ │
│                        │ key_hash      │     │ status                    │ │
│                        │ name          │     │ job_type                  │ │
│                        │ last_used_at  │     │ input_data (JSONB)        │ │
│                        │ expires_at    │     │ result_data (JSONB)       │ │
│                        └───────────────┘     │ created_at                │ │
│                                              │ completed_at              │ │
│                                              └───────────────────────────┘ │
│                                                                              │
│  ┌───────────────┐     ┌───────────────┐     ┌───────────────────────────┐ │
│  │  audit_logs   │     │  rate_limits  │     │      invoices             │ │
│  ├───────────────┤     ├───────────────┤     ├───────────────────────────┤ │
│  │ id (PK)       │     │ id (PK)       │     │ id (PK)                   │ │
│  │ tenant_id     │     │ tenant_id     │     │ tenant_id (FK)            │ │
│  │ user_id       │     │ key           │     │ subscription_id (FK)      │ │
│  │ action        │     │ count         │     │ stripe_invoice_id         │ │
│  │ resource_type │     │ window_start  │     │ amount_cents              │ │
│  │ resource_id   │     │ window_end    │     │ status                    │ │
│  │ metadata      │     └───────────────┘     │ paid_at                   │ │
│  │ created_at    │                           └───────────────────────────┘ │
│  └───────────────┘                                                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Table Definitions

### tenants
```sql
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    plan VARCHAR(50) NOT NULL DEFAULT 'free',
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tenants_plan ON tenants(plan);
```

### users
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    email_verified BOOLEAN NOT NULL DEFAULT false,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_users_email UNIQUE (tenant_id, email)
);

CREATE INDEX idx_users_tenant_id ON users(tenant_id);
CREATE INDEX idx_users_email ON users(email);

-- Row-Level Security
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_users ON users
    FOR ALL
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
```

### subscriptions
```sql
CREATE TABLE subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    stripe_subscription_id VARCHAR(255) UNIQUE,
    stripe_customer_id VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'inactive',
    plan VARCHAR(50) NOT NULL DEFAULT 'free',
    current_period_start TIMESTAMPTZ,
    current_period_end TIMESTAMPTZ,
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_subscriptions_tenant_id ON subscriptions(tenant_id);
CREATE INDEX idx_subscriptions_user_id ON subscriptions(user_id);
CREATE INDEX idx_subscriptions_stripe_id ON subscriptions(stripe_subscription_id);
CREATE INDEX idx_subscriptions_status ON subscriptions(status);

ALTER TABLE subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE subscriptions FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_subscriptions ON subscriptions
    FOR ALL
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
```

### analysis_jobs
```sql
CREATE TABLE analysis_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    job_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    priority INTEGER NOT NULL DEFAULT 0,
    input_data JSONB NOT NULL DEFAULT '{}',
    result_data JSONB,
    error_message TEXT,
    backend VARCHAR(50),
    gpu_id INTEGER,
    execution_time_ms INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE INDEX idx_jobs_tenant_id ON analysis_jobs(tenant_id);
CREATE INDEX idx_jobs_user_id ON analysis_jobs(user_id);
CREATE INDEX idx_jobs_status ON analysis_jobs(status);
CREATE INDEX idx_jobs_created_at ON analysis_jobs(created_at DESC);
CREATE INDEX idx_jobs_pending ON analysis_jobs(status, priority DESC, created_at)
    WHERE status = 'pending';

-- JSONB indexes for query patterns
CREATE INDEX idx_jobs_input_data ON analysis_jobs USING GIN (input_data);
CREATE INDEX idx_jobs_result_data ON analysis_jobs USING GIN (result_data);

ALTER TABLE analysis_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE analysis_jobs FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_jobs ON analysis_jobs
    FOR ALL
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
```

### audit_logs
```sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    user_id UUID,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id UUID,
    old_value JSONB,
    new_value JSONB,
    ip_address INET,
    user_agent TEXT,
    request_id VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_tenant_id ON audit_logs(tenant_id);
CREATE INDEX idx_audit_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_action ON audit_logs(action);
CREATE INDEX idx_audit_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX idx_audit_created_at ON audit_logs(created_at DESC);

-- Partition by month for performance
CREATE TABLE audit_logs_partitioned (
    LIKE audit_logs INCLUDING ALL
) PARTITION BY RANGE (created_at);
```

## Indexes Strategy

| Table | Index | Type | Purpose |
|-------|-------|------|---------|
| users | tenant_id | B-tree | RLS filtering |
| users | email | B-tree | Login lookup |
| jobs | (status, priority, created_at) | B-tree | Queue ordering |
| jobs | input_data | GIN | JSONB queries |
| audit_logs | created_at | B-tree | Time-range queries |

## Data Retention

| Table | Retention | Archival |
|-------|-----------|----------|
| tenants | Forever | N/A |
| users | Account lifetime | Soft delete |
| subscriptions | Forever | N/A |
| analysis_jobs | 90 days | Cold storage |
| audit_logs | 1 year | Cold storage |

---
**Last Updated**: 2024-10-15
