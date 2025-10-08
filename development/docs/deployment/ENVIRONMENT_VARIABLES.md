# Environment Variables Documentation

## SaaS Platform - Configuration Reference

**Last Updated**: 2025-10-06

---

## Table of Contents

1. [Overview](#overview)
2. [Required Variables](#required-variables)
3. [Optional Variables](#optional-variables)
4. [Environment-Specific Configuration](#environment-specific-configuration)
5. [Security Best Practices](#security-best-practices)
6. [Validation](#validation)

---

## Overview

This document lists all environment variables used by the Catalytic Computing SaaS platform. Environment variables are used for configuration that varies between environments (development, staging, production) and for sensitive data (secrets, API keys).

### Configuration Priority

1. **Environment Variables** (highest priority)
2. **Config Files** (`.env` files)
3. **Default Values** (hardcoded in application)

---

## Required Variables

### Database Configuration

#### `DATABASE_URL`
- **Type**: String (connection string)
- **Required**: Yes
- **Description**: Database connection string
- **Format**:
  - PostgreSQL: `postgresql://user:password@host:port/database`
  - SQLite: `sqlite:///./catalytic_saas.db`
- **Example**:
  ```bash
  # PostgreSQL
  export DATABASE_URL="postgresql://catalytic:SecurePass123@db.example.com:5432/catalytic_saas"

  # SQLite
  export DATABASE_URL="sqlite:///./catalytic_saas.db"
  ```
- **Kubernetes Secret**: `database-credentials.url`

---

### Authentication & Security

#### `JWT_SECRET`
- **Type**: String
- **Required**: Yes
- **Description**: Secret key for signing JWT tokens
- **Format**: Random string, minimum 32 characters
- **Example**:
  ```bash
  export JWT_SECRET="your-super-secret-jwt-key-minimum-32-characters-long-please"
  ```
- **Generation**:
  ```bash
  # Generate secure random key
  python -c "import secrets; print(secrets.token_urlsafe(64))"
  ```
- **Kubernetes Secret**: `jwt-secret.secret`
- **Security**: ⚠️ CRITICAL - Never commit to git, rotate every 90 days

#### `JWT_ALGORITHM`
- **Type**: String
- **Required**: No
- **Default**: `HS256`
- **Description**: Algorithm for JWT signing
- **Options**: `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`
- **Example**:
  ```bash
  export JWT_ALGORITHM="HS256"
  ```

#### `ACCESS_TOKEN_EXPIRE_MINUTES`
- **Type**: Integer
- **Required**: No
- **Default**: `60`
- **Description**: Access token expiration time in minutes
- **Recommended**: 15-60 minutes for production
- **Example**:
  ```bash
  export ACCESS_TOKEN_EXPIRE_MINUTES=30
  ```

---

### Redis Configuration (Optional but Recommended)

#### `REDIS_URL`
- **Type**: String (connection string)
- **Required**: No (required for token blacklist and rate limiting)
- **Description**: Redis connection string for caching and session management
- **Format**: `redis://[:password]@host:port/database`
- **Example**:
  ```bash
  export REDIS_URL="redis://:MyRedisPassword@redis.example.com:6379/0"
  ```
- **Kubernetes Secret**: `redis-credentials.url`

#### `REDIS_TOKEN_BLACKLIST_TTL`
- **Type**: Integer
- **Required**: No
- **Default**: `3600` (1 hour)
- **Description**: TTL for blacklisted tokens in Redis (seconds)
- **Example**:
  ```bash
  export REDIS_TOKEN_BLACKLIST_TTL=3600
  ```

---

### Rate Limiting

#### `RATE_LIMIT_PER_MINUTE`
- **Type**: Integer
- **Required**: No
- **Default**: `100`
- **Description**: Maximum requests per minute per IP address
- **Recommended**: 100 for production, 1000 for staging
- **Example**:
  ```bash
  export RATE_LIMIT_PER_MINUTE=100
  ```

#### `RATE_LIMIT_STORAGE`
- **Type**: String
- **Required**: No
- **Default**: `memory`
- **Options**: `memory`, `redis`
- **Description**: Backend for rate limit storage
- **Example**:
  ```bash
  export RATE_LIMIT_STORAGE="redis"  # Use Redis for distributed rate limiting
  ```

---

### Stripe Integration (Payment Processing)

#### `STRIPE_API_KEY`
- **Type**: String
- **Required**: Yes (if using Stripe)
- **Description**: Stripe API secret key
- **Format**: `sk_live_...` (production) or `sk_test_...` (development)
- **Example**:
  ```bash
  export STRIPE_API_KEY="sk_live_51AbC..."
  ```
- **Kubernetes Secret**: `stripe-secrets.api-key`
- **Security**: ⚠️ CRITICAL - Never commit to git

#### `STRIPE_WEBHOOK_SECRET`
- **Type**: String
- **Required**: Yes (if using Stripe webhooks)
- **Description**: Stripe webhook signing secret
- **Format**: `whsec_...`
- **Example**:
  ```bash
  export STRIPE_WEBHOOK_SECRET="whsec_1234567890abcdef..."
  ```
- **Kubernetes Secret**: `stripe-secrets.webhook-secret`
- **Security**: ⚠️ CRITICAL - Verify all webhook signatures

#### `STRIPE_PRICE_ID_STARTER`
- **Type**: String
- **Required**: No
- **Description**: Stripe Price ID for Starter plan
- **Example**:
  ```bash
  export STRIPE_PRICE_ID_STARTER="price_1ABC..."
  ```

#### `STRIPE_PRICE_ID_PROFESSIONAL`
- **Type**: String
- **Required**: No
- **Description**: Stripe Price ID for Professional plan
- **Example**:
  ```bash
  export STRIPE_PRICE_ID_PROFESSIONAL="price_1DEF..."
  ```

#### `STRIPE_PRICE_ID_ENTERPRISE`
- **Type**: String
- **Required**: No
- **Description**: Stripe Price ID for Enterprise plan
- **Example**:
  ```bash
  export STRIPE_PRICE_ID_ENTERPRISE="price_1GHI..."
  ```

---

### CORS Configuration

#### `ALLOWED_ORIGINS`
- **Type**: String (comma-separated)
- **Required**: No
- **Default**: `http://localhost:3000`
- **Description**: Allowed origins for CORS
- **Format**: Comma-separated list of URLs
- **Example**:
  ```bash
  export ALLOWED_ORIGINS="https://app.example.com,https://www.example.com,https://admin.example.com"
  ```

---

### Application Settings

#### `ENVIRONMENT`
- **Type**: String
- **Required**: No
- **Default**: `development`
- **Options**: `development`, `staging`, `production`
- **Description**: Application environment
- **Example**:
  ```bash
  export ENVIRONMENT="production"
  ```

#### `DEBUG`
- **Type**: Boolean
- **Required**: No
- **Default**: `false` (production), `true` (development)
- **Description**: Enable debug mode
- **Example**:
  ```bash
  export DEBUG=false  # Production should always be false
  ```

#### `LOG_LEVEL`
- **Type**: String
- **Required**: No
- **Default**: `INFO`
- **Options**: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`
- **Description**: Logging level
- **Example**:
  ```bash
  export LOG_LEVEL="INFO"
  ```

#### `MAX_LATTICES_PER_TENANT`
- **Type**: Integer
- **Required**: No
- **Default**: `100`
- **Description**: Maximum number of lattices per tenant
- **Example**:
  ```bash
  export MAX_LATTICES_PER_TENANT=100
  ```

#### `LATTICE_MEMORY_OPTIMIZATION`
- **Type**: Boolean
- **Required**: No
- **Default**: `true`
- **Description**: Enable memory optimization for lattices
- **Example**:
  ```bash
  export LATTICE_MEMORY_OPTIMIZATION=true
  ```

#### `PARALLEL_CORES`
- **Type**: Integer
- **Required**: No
- **Default**: `12`
- **Description**: Number of parallel cores for processing
- **Recommended**: Match CPU cores available
- **Example**:
  ```bash
  export PARALLEL_CORES=16
  ```

---

### Monitoring & Metrics

#### `METRICS_PORT`
- **Type**: Integer
- **Required**: No
- **Default**: `8082`
- **Description**: Port for Prometheus metrics endpoint
- **Example**:
  ```bash
  export METRICS_PORT=8082
  ```

#### `PROMETHEUS_ENABLED`
- **Type**: Boolean
- **Required**: No
- **Default**: `true`
- **Description**: Enable Prometheus metrics collection
- **Example**:
  ```bash
  export PROMETHEUS_ENABLED=true
  ```

---

### Email Configuration (Optional)

#### `SMTP_HOST`
- **Type**: String
- **Required**: No
- **Description**: SMTP server hostname
- **Example**:
  ```bash
  export SMTP_HOST="smtp.sendgrid.net"
  ```

#### `SMTP_PORT`
- **Type**: Integer
- **Required**: No
- **Default**: `587`
- **Description**: SMTP server port
- **Example**:
  ```bash
  export SMTP_PORT=587
  ```

#### `SMTP_USER`
- **Type**: String
- **Required**: No
- **Description**: SMTP username
- **Example**:
  ```bash
  export SMTP_USER="apikey"
  ```

#### `SMTP_PASSWORD`
- **Type**: String
- **Required**: No
- **Description**: SMTP password
- **Example**:
  ```bash
  export SMTP_PASSWORD="SG.1234567890..."
  ```
- **Security**: ⚠️ Sensitive - Store in secrets

#### `EMAIL_FROM`
- **Type**: String
- **Required**: No
- **Default**: `noreply@example.com`
- **Description**: Default sender email address
- **Example**:
  ```bash
  export EMAIL_FROM="noreply@catalytic.ai"
  ```

---

## Optional Variables

### Feature Flags

#### `ENABLE_WEBHOOKS`
- **Type**: Boolean
- **Default**: `true`
- **Description**: Enable webhook functionality
- **Example**:
  ```bash
  export ENABLE_WEBHOOKS=true
  ```

#### `ENABLE_GPU_ACCELERATION`
- **Type**: Boolean
- **Default**: `false` (auto-detected)
- **Description**: Enable GPU acceleration if available
- **Example**:
  ```bash
  export ENABLE_GPU_ACCELERATION=true
  ```

#### `ENABLE_API_DOCS`
- **Type**: Boolean
- **Default**: `true` (dev), `false` (production)
- **Description**: Enable /docs endpoint (Swagger UI)
- **Example**:
  ```bash
  export ENABLE_API_DOCS=false  # Disable in production for security
  ```

---

### Performance Tuning

#### `CACHE_SIZE`
- **Type**: Integer
- **Default**: `1024`
- **Description**: Number of cache entries
- **Example**:
  ```bash
  export CACHE_SIZE=4096
  ```

#### `CACHE_TTL_SECONDS`
- **Type**: Integer
- **Default**: `300` (5 minutes)
- **Description**: Cache time-to-live in seconds
- **Example**:
  ```bash
  export CACHE_TTL_SECONDS=300
  ```

#### `WORKER_PROCESSES`
- **Type**: Integer
- **Default**: `4`
- **Description**: Number of Uvicorn worker processes
- **Recommended**: `(2 * CPU_CORES) + 1`
- **Example**:
  ```bash
  export WORKER_PROCESSES=9  # For 4 CPU cores
  ```

---

## Environment-Specific Configuration

### Development Environment

```bash
# .env.development
ENVIRONMENT=development
DEBUG=true
LOG_LEVEL=DEBUG

# Database (SQLite for simplicity)
DATABASE_URL=sqlite:///./catalytic_saas_dev.db

# Auth (weak secret OK for dev)
JWT_SECRET=dev-secret-key-not-for-production
ACCESS_TOKEN_EXPIRE_MINUTES=1440  # 24 hours for dev

# No Redis required (in-memory rate limiting)
RATE_LIMIT_STORAGE=memory
RATE_LIMIT_PER_MINUTE=1000  # High limit for dev

# Stripe (test mode)
STRIPE_API_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_test_...

# CORS (allow localhost)
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8000

# Features
ENABLE_API_DOCS=true
ENABLE_WEBHOOKS=true
```

### Staging Environment

```bash
# .env.staging
ENVIRONMENT=staging
DEBUG=false
LOG_LEVEL=INFO

# Database (PostgreSQL)
DATABASE_URL=postgresql://user:pass@staging-db:5432/catalytic_saas_staging

# Auth (strong secret)
JWT_SECRET=<generate-strong-secret>
ACCESS_TOKEN_EXPIRE_MINUTES=60

# Redis
REDIS_URL=redis://:pass@staging-redis:6379/0
RATE_LIMIT_STORAGE=redis
RATE_LIMIT_PER_MINUTE=200

# Stripe (test mode)
STRIPE_API_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_test_...

# CORS
ALLOWED_ORIGINS=https://staging.example.com

# Features
ENABLE_API_DOCS=true
ENABLE_WEBHOOKS=true
```

### Production Environment

```bash
# .env.production (stored in Kubernetes secrets!)
ENVIRONMENT=production
DEBUG=false
LOG_LEVEL=INFO

# Database (managed PostgreSQL)
DATABASE_URL=postgresql://user:pass@prod-db.rds.amazonaws.com:5432/catalytic_saas

# Auth (rotated regularly)
JWT_SECRET=<strong-production-secret>
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Redis (managed Redis cluster)
REDIS_URL=redis://:pass@prod-redis.cache.amazonaws.com:6379/0
RATE_LIMIT_STORAGE=redis
RATE_LIMIT_PER_MINUTE=100

# Stripe (live mode)
STRIPE_API_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...

# CORS (production domains only)
ALLOWED_ORIGINS=https://app.example.com,https://www.example.com

# Features
ENABLE_API_DOCS=false  # Disable for security
ENABLE_WEBHOOKS=true

# Performance
CACHE_SIZE=4096
WORKER_PROCESSES=9
PARALLEL_CORES=16
```

---

## Security Best Practices

### Secret Management

1. **Never Commit Secrets**
   ```bash
   # Add to .gitignore
   .env
   .env.*
   !.env.example
   ```

2. **Use Environment-Specific Secrets**
   - Different secrets for dev, staging, production
   - Rotate production secrets every 90 days

3. **Use Secret Management Tools**
   - Kubernetes Secrets
   - AWS Secrets Manager
   - HashiCorp Vault
   - Azure Key Vault

4. **Encrypt Secrets at Rest**
   - Enable Kubernetes secret encryption
   - Use cloud provider encryption

### Access Control

1. **Limit Access**
   - Only authorized personnel can access production secrets
   - Use RBAC for Kubernetes secrets

2. **Audit Access**
   - Log all secret access
   - Monitor for unauthorized access

3. **Rotation**
   ```bash
   # Rotate JWT secret
   NEW_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(64))")
   kubectl create secret generic jwt-secret-new \
     --from-literal=secret="${NEW_SECRET}" \
     -n catalytic-saas

   # Update deployment to use new secret
   # Gradually rollout
   # Delete old secret after full rollout
   ```

---

## Validation

### Environment Variable Checker

```python
#!/usr/bin/env python3
"""
validate_env.py - Validate all required environment variables
"""

import os
import sys
from typing import List, Tuple

def check_required_vars() -> List[Tuple[str, bool, str]]:
    """Check all required environment variables"""

    required_vars = {
        'DATABASE_URL': 'Database connection string',
        'JWT_SECRET': 'JWT signing secret',
    }

    results = []

    for var, description in required_vars.items():
        value = os.getenv(var)
        is_set = value is not None and value != ''
        results.append((var, is_set, description))

    return results

def check_optional_vars() -> List[Tuple[str, bool, str, str]]:
    """Check optional environment variables and their defaults"""

    optional_vars = {
        'REDIS_URL': ('Redis connection string', 'None'),
        'RATE_LIMIT_PER_MINUTE': ('Rate limit per minute', '100'),
        'ENVIRONMENT': ('Application environment', 'development'),
        'LOG_LEVEL': ('Logging level', 'INFO'),
    }

    results = []

    for var, (description, default) in optional_vars.items():
        value = os.getenv(var, default)
        is_set = os.getenv(var) is not None
        results.append((var, is_set, description, value))

    return results

def validate_secrets():
    """Validate secret strength"""

    jwt_secret = os.getenv('JWT_SECRET', '')

    if len(jwt_secret) < 32:
        print(f"⚠️  WARNING: JWT_SECRET is too short ({len(jwt_secret)} chars, should be >= 32)")

    if jwt_secret in ['dev-secret', 'changeme', 'secret']:
        print(f"⚠️  WARNING: JWT_SECRET appears to be a default/weak value")

if __name__ == '__main__':
    print("Environment Variable Validation")
    print("=" * 80)

    # Check required
    print("\nRequired Variables:")
    print("-" * 80)
    required_results = check_required_vars()
    all_required_set = True

    for var, is_set, description in required_results:
        status = "✅" if is_set else "❌"
        print(f"{status} {var:30} - {description}")
        if not is_set:
            all_required_set = False

    # Check optional
    print("\nOptional Variables:")
    print("-" * 80)
    optional_results = check_optional_vars()

    for var, is_set, description, value in optional_results:
        status = "✅" if is_set else "⚪"
        print(f"{status} {var:30} - {description:40} (using: {value})")

    # Validate secrets
    print("\nSecret Validation:")
    print("-" * 80)
    validate_secrets()

    # Summary
    print("\n" + "=" * 80)
    if all_required_set:
        print("✅ All required environment variables are set!")
        sys.exit(0)
    else:
        print("❌ Some required environment variables are missing!")
        sys.exit(1)
```

### Usage

```bash
# Validate environment
python scripts/validate_env.py

# Validate before deployment
kubectl exec -it deployment/catalytic-saas-api -n catalytic-saas -- \
  python scripts/validate_env.py
```

---

## Kubernetes ConfigMap and Secret Examples

### ConfigMap for Non-Sensitive Config

```yaml
# kubernetes/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: catalytic-saas
data:
  ENVIRONMENT: "production"
  LOG_LEVEL: "INFO"
  RATE_LIMIT_PER_MINUTE: "100"
  MAX_LATTICES_PER_TENANT: "100"
  ALLOWED_ORIGINS: "https://app.example.com,https://www.example.com"
  ENABLE_API_DOCS: "false"
  ENABLE_WEBHOOKS: "true"
```

### Secrets for Sensitive Data

```yaml
# kubernetes/secrets.yaml.example
apiVersion: v1
kind: Secret
metadata:
  name: database-credentials
  namespace: catalytic-saas
type: Opaque
stringData:
  url: "postgresql://user:password@host:5432/catalytic_saas"

---
apiVersion: v1
kind: Secret
metadata:
  name: jwt-secret
  namespace: catalytic-saas
type: Opaque
stringData:
  secret: "your-super-secret-jwt-key-here"

---
apiVersion: v1
kind: Secret
metadata:
  name: stripe-secrets
  namespace: catalytic-saas
type: Opaque
stringData:
  api-key: "sk_live_..."
  webhook-secret: "whsec_..."
```

### Deployment Using ConfigMap and Secrets

```yaml
# kubernetes/deployment.yaml (excerpt)
spec:
  containers:
  - name: catalytic-saas-api
    image: registry/catalytic-saas-api:1.0.0
    envFrom:
    - configMapRef:
        name: app-config
    env:
    - name: DATABASE_URL
      valueFrom:
        secretKeyRef:
          name: database-credentials
          key: url
    - name: JWT_SECRET
      valueFrom:
        secretKeyRef:
          name: jwt-secret
          key: secret
    - name: STRIPE_API_KEY
      valueFrom:
        secretKeyRef:
          name: stripe-secrets
          key: api-key
```

---

**Last Updated**: 2025-10-06
**Maintained By**: DevOps Team
**Review Frequency**: Quarterly or when adding new variables
