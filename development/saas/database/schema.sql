-- Multi-Tenant Database Schema for Catalytic Computing SaaS
-- PostgreSQL with Row-Level Security (RLS)

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- TENANT MANAGEMENT
-- ============================================================================

-- Tenants table - Core tenant information
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    slug VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    domain VARCHAR(255),
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted')),
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ,
    CONSTRAINT unique_active_email UNIQUE (email, deleted_at)
);

-- Subscription Plans
CREATE TABLE subscription_plans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL,
    code VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    price_monthly DECIMAL(10, 2) NOT NULL,
    price_yearly DECIMAL(10, 2),
    features JSONB NOT NULL DEFAULT '{}',
    limits JSONB NOT NULL DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Default subscription plans data
INSERT INTO subscription_plans (name, code, price_monthly, price_yearly, features, limits) VALUES
('Free Tier', 'free', 0.00, 0.00,
    '{"lattices": 5, "api_calls": 1000, "path_finding": true, "basic_transforms": true}',
    '{"max_lattices": 5, "max_dimensions": 3, "max_lattice_size": 10, "api_calls_per_month": 1000}'),
('Starter', 'starter', 29.99, 299.99,
    '{"lattices": 50, "api_calls": 10000, "path_finding": true, "all_transforms": true, "community_detection": true}',
    '{"max_lattices": 50, "max_dimensions": 5, "max_lattice_size": 50, "api_calls_per_month": 10000}'),
('Professional', 'professional', 99.99, 999.99,
    '{"lattices": 500, "api_calls": 100000, "all_features": true, "priority_support": true, "gpu_acceleration": true}',
    '{"max_lattices": 500, "max_dimensions": 10, "max_lattice_size": 100, "api_calls_per_month": 100000}'),
('Enterprise', 'enterprise', 499.99, 4999.99,
    '{"unlimited_lattices": true, "unlimited_api_calls": true, "all_features": true, "dedicated_support": true, "sla": true, "custom_integration": true}',
    '{"max_lattices": -1, "max_dimensions": -1, "max_lattice_size": -1, "api_calls_per_month": -1}');

-- Tenant Subscriptions
CREATE TABLE tenant_subscriptions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    plan_id UUID NOT NULL REFERENCES subscription_plans(id),
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'trial', 'past_due', 'cancelled', 'expired')),
    trial_ends_at TIMESTAMPTZ,
    current_period_start TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    current_period_end TIMESTAMPTZ,
    cancel_at_period_end BOOLEAN DEFAULT false,
    cancelled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT one_active_subscription UNIQUE (tenant_id, status) WHERE status = 'active'
);

-- ============================================================================
-- AUTHENTICATION & AUTHORIZATION
-- ============================================================================

-- Users table - Tenant users
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    username VARCHAR(100),
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    role VARCHAR(50) DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    is_active BOOLEAN DEFAULT true,
    email_verified BOOLEAN DEFAULT false,
    last_login TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_email_per_tenant UNIQUE (tenant_id, email)
);

-- API Keys for programmatic access
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) NOT NULL UNIQUE,
    key_prefix VARCHAR(10) NOT NULL,
    permissions JSONB DEFAULT '[]',
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT true,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Session management
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- USAGE TRACKING & BILLING
-- ============================================================================

-- Usage metrics tracking
CREATE TABLE usage_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    metric_type VARCHAR(50) NOT NULL,
    metric_value BIGINT NOT NULL DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_metric_per_period UNIQUE (tenant_id, metric_type, period_start, period_end)
);

-- Detailed API call logs
CREATE TABLE api_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    api_key_id UUID REFERENCES api_keys(id),
    endpoint VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    status_code INTEGER,
    response_time_ms INTEGER,
    request_size_bytes INTEGER,
    response_size_bytes INTEGER,
    ip_address INET,
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Create index for fast log queries
CREATE INDEX idx_api_logs_tenant_created ON api_logs(tenant_id, created_at DESC);
CREATE INDEX idx_api_logs_endpoint ON api_logs(endpoint, created_at DESC);

-- Billing records
CREATE TABLE billing_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subscription_id UUID REFERENCES tenant_subscriptions(id),
    amount DECIMAL(10, 2) NOT NULL,
    currency VARCHAR(3) DEFAULT 'USD',
    description TEXT,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'paid', 'failed', 'refunded')),
    payment_method VARCHAR(50),
    invoice_number VARCHAR(100) UNIQUE,
    due_date DATE,
    paid_at TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- LATTICE RESOURCE MANAGEMENT
-- ============================================================================

-- Stored lattices per tenant
CREATE TABLE tenant_lattices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255),
    dimensions INTEGER NOT NULL CHECK (dimensions > 0 AND dimensions <= 10),
    size INTEGER NOT NULL CHECK (size > 0),
    vertices INTEGER NOT NULL,
    edges INTEGER NOT NULL,
    memory_kb DECIMAL(10, 2),
    memory_reduction DECIMAL(10, 2),
    metadata JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_accessed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Lattice operations history
CREATE TABLE lattice_operations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    lattice_id UUID REFERENCES tenant_lattices(id) ON DELETE CASCADE,
    operation_type VARCHAR(50) NOT NULL,
    parameters JSONB DEFAULT '{}',
    result JSONB DEFAULT '{}',
    execution_time_ms INTEGER,
    status VARCHAR(20) DEFAULT 'success',
    error_message TEXT,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================================

-- Enable RLS on all tenant-scoped tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_lattices ENABLE ROW LEVEL SECURITY;
ALTER TABLE lattice_operations ENABLE ROW LEVEL SECURITY;

-- Create application role
CREATE ROLE app_user;

-- RLS Policies for tenant isolation
CREATE POLICY tenant_isolation_users ON users
    FOR ALL TO app_user
    USING (tenant_id = current_setting('app.tenant_id')::UUID);

CREATE POLICY tenant_isolation_api_keys ON api_keys
    FOR ALL TO app_user
    USING (tenant_id = current_setting('app.tenant_id')::UUID);

CREATE POLICY tenant_isolation_usage_metrics ON usage_metrics
    FOR ALL TO app_user
    USING (tenant_id = current_setting('app.tenant_id')::UUID);

CREATE POLICY tenant_isolation_api_logs ON api_logs
    FOR ALL TO app_user
    USING (tenant_id = current_setting('app.tenant_id')::UUID);

CREATE POLICY tenant_isolation_billing_records ON billing_records
    FOR ALL TO app_user
    USING (tenant_id = current_setting('app.tenant_id')::UUID);

CREATE POLICY tenant_isolation_tenant_lattices ON tenant_lattices
    FOR ALL TO app_user
    USING (tenant_id = current_setting('app.tenant_id')::UUID);

CREATE POLICY tenant_isolation_lattice_operations ON lattice_operations
    FOR ALL TO app_user
    USING (tenant_id = current_setting('app.tenant_id')::UUID);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

CREATE INDEX idx_tenants_slug ON tenants(slug) WHERE status = 'active';
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_tenant_id ON users(tenant_id);
CREATE INDEX idx_api_keys_tenant_id ON api_keys(tenant_id);
CREATE INDEX idx_api_keys_key_prefix ON api_keys(key_prefix);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);
CREATE INDEX idx_usage_metrics_tenant_period ON usage_metrics(tenant_id, period_start, period_end);
CREATE INDEX idx_billing_records_tenant ON billing_records(tenant_id, created_at DESC);
CREATE INDEX idx_tenant_lattices_tenant ON tenant_lattices(tenant_id, is_active);
CREATE INDEX idx_lattice_operations_tenant ON lattice_operations(tenant_id, created_at DESC);

-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Auto-update updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_tenants_updated_at BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tenant_subscriptions_updated_at BEFORE UPDATE ON tenant_subscriptions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_api_keys_updated_at BEFORE UPDATE ON api_keys
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tenant_lattices_updated_at BEFORE UPDATE ON tenant_lattices
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

-- Get current tenant's usage for a metric type
CREATE OR REPLACE FUNCTION get_tenant_usage(
    p_tenant_id UUID,
    p_metric_type VARCHAR,
    p_period_start TIMESTAMPTZ,
    p_period_end TIMESTAMPTZ
) RETURNS BIGINT AS $$
DECLARE
    v_usage BIGINT;
BEGIN
    SELECT COALESCE(SUM(metric_value), 0) INTO v_usage
    FROM usage_metrics
    WHERE tenant_id = p_tenant_id
      AND metric_type = p_metric_type
      AND period_start >= p_period_start
      AND period_end <= p_period_end;

    RETURN v_usage;
END;
$$ LANGUAGE plpgsql;

-- Check if tenant has exceeded plan limits
CREATE OR REPLACE FUNCTION check_plan_limit(
    p_tenant_id UUID,
    p_limit_key VARCHAR
) RETURNS BOOLEAN AS $$
DECLARE
    v_limit_value INTEGER;
    v_current_usage BIGINT;
BEGIN
    -- Get the limit from subscription plan
    SELECT (sp.limits->p_limit_key)::INTEGER INTO v_limit_value
    FROM tenant_subscriptions ts
    JOIN subscription_plans sp ON sp.id = ts.plan_id
    WHERE ts.tenant_id = p_tenant_id
      AND ts.status = 'active';

    -- -1 means unlimited
    IF v_limit_value = -1 THEN
        RETURN FALSE;
    END IF;

    -- Get current usage based on limit type
    IF p_limit_key = 'max_lattices' THEN
        SELECT COUNT(*) INTO v_current_usage
        FROM tenant_lattices
        WHERE tenant_id = p_tenant_id AND is_active = true;
    ELSIF p_limit_key = 'api_calls_per_month' THEN
        v_current_usage := get_tenant_usage(
            p_tenant_id,
            'api_calls',
            date_trunc('month', CURRENT_TIMESTAMP),
            date_trunc('month', CURRENT_TIMESTAMP) + interval '1 month'
        );
    END IF;

    RETURN v_current_usage >= v_limit_value;
END;
$$ LANGUAGE plpgsql;