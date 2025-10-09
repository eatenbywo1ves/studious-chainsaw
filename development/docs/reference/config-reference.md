# Configuration Reference

**Last Updated:** 2025-10-08
**Applies To:** All services (SaaS, GPU, GhidraGo, Security)

---

## 🎯 Overview

This document provides a comprehensive reference for all configuration options across the Catalytic Computing platform. Configuration is managed through **environment variables** and **configuration files**.

---

## 📝 Environment Variables

### Core Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DEPLOYMENT_ENV` | Environment (development/staging/production) | `development` | ✅ Yes |
| `PORT` | HTTP server port | `8000` | No |
| `LOG_LEVEL` | Logging verbosity (DEBUG/INFO/WARNING/ERROR) | `INFO` | No |

---

### Database Configuration (PostgreSQL)

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://postgres:postgres@localhost:5432/saas` | ✅ Yes |
| `DB_POOL_SIZE` | Connection pool size | `20` | No |
| `DB_MAX_OVERFLOW` | Pool overflow limit | `10` | No |
| `DB_ECHO` | Log SQL queries (true/false) | `false` | No |

**Example:**
```bash
DATABASE_URL=postgresql://user:pass@host:5432/dbname
DB_POOL_SIZE=40
DB_MAX_OVERFLOW=20
```

---

### Redis Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `REDIS_HOST` | Redis server hostname | `localhost` | ✅ Yes |
| `REDIS_PORT` | Redis server port | `6379` | No |
| `REDIS_PASSWORD` | Redis authentication password | *(none)* | ⚠️ Prod only |
| `REDIS_DB` | Redis database number | `0` | No |
| `REDIS_POOL_SIZE` | Connection pool size (auto-sized by env) | *varies* | No |

**Environment-Aware Pool Sizing:**
- Development: 20 connections
- Staging: 60 connections
- Production: 160 connections

**Example:**
```bash
REDIS_HOST=redis.example.com
REDIS_PORT=6379
REDIS_PASSWORD=your_secure_password
REDIS_DB=0
```

---

### JWT Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `JWT_ALGORITHM` | Signing algorithm | `RS256` | ✅ Yes |
| `JWT_PRIVATE_KEY_PATH` | Path to RSA private key | `keys/jwt-private.pem` | ✅ Yes |
| `JWT_PUBLIC_KEY_PATH` | Path to RSA public key | `keys/jwt-public.pem` | ✅ Yes |
| `JWT_AUDIENCE` | Token audience | `your-api` | ✅ Yes |
| `JWT_ISSUER` | Token issuer | `your-auth-service` | ✅ Yes |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | Access token lifetime | `30` | No |
| `JWT_REFRESH_TOKEN_EXPIRE_DAYS` | Refresh token lifetime | `7` | No |

**Security Notes:**
- ✅ **Always use RS256** (asymmetric) in production
- ❌ **Never use HS256** (symmetric) - vulnerable to signature forgery
- 🔒 Keep private keys secure (never commit to git)

**Example:**
```bash
JWT_ALGORITHM=RS256
JWT_PRIVATE_KEY_PATH=/secure/keys/jwt-private.pem
JWT_PUBLIC_KEY_PATH=/secure/keys/jwt-public.pem
JWT_AUDIENCE=my-api
JWT_ISSUER=my-auth-service
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7
```

---

### Stripe Configuration (Payments)

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `STRIPE_API_KEY` | Stripe secret key | *(none)* | ✅ Yes |
| `STRIPE_PUBLISHABLE_KEY` | Stripe publishable key | *(none)* | ✅ Yes |
| `STRIPE_WEBHOOK_SECRET` | Webhook signing secret | *(none)* | ✅ Yes |
| `STRIPE_SUCCESS_URL` | Payment success redirect | `http://localhost:3000/success` | No |
| `STRIPE_CANCEL_URL` | Payment cancel redirect | `http://localhost:3000/cancel` | No |

**Example:**
```bash
STRIPE_API_KEY=sk_test_...
STRIPE_PUBLISHABLE_KEY=pk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_SUCCESS_URL=https://yourapp.com/payment/success
STRIPE_CANCEL_URL=https://yourapp.com/payment/cancel
```

---

### Email Configuration (SendGrid)

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SENDGRID_API_KEY` | SendGrid API key | *(none)* | ✅ Yes |
| `SENDGRID_FROM_EMAIL` | Default sender email | `noreply@example.com` | ✅ Yes |
| `SENDGRID_FROM_NAME` | Default sender name | `Your App` | No |

**Example:**
```bash
SENDGRID_API_KEY=SG.xxx...
SENDGRID_FROM_EMAIL=noreply@yourapp.com
SENDGRID_FROM_NAME="Your App Team"
```

---

### GPU Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `USE_GPU` | Enable GPU acceleration (true/false) | `true` | No |
| `CUDA_VISIBLE_DEVICES` | GPU device IDs (comma-separated) | `0` | No |
| `PYTORCH_CUDA_ALLOC_CONF` | PyTorch CUDA memory config | `max_split_size_mb:512` | No |
| `GPU_BATCH_SIZE` | Default batch size for GPU operations | `32` | No |

**Example:**
```bash
USE_GPU=true
CUDA_VISIBLE_DEVICES=0,1  # Use first two GPUs
PYTORCH_CUDA_ALLOC_CONF=max_split_size_mb:512
GPU_BATCH_SIZE=64
```

---

### Rate Limiting

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `RATE_LIMIT_ENABLED` | Enable rate limiting (true/false) | `true` | No |
| `RATE_LIMIT_REQUESTS` | Requests per window | `100` | No |
| `RATE_LIMIT_WINDOW` | Time window (seconds) | `60` | No |

**Example:**
```bash
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60
```

---

### Security Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `ALLOWED_HOSTS` | Comma-separated allowed hostnames | `localhost,127.0.0.1` | ⚠️ Prod |
| `CORS_ORIGINS` | Allowed CORS origins (comma-separated) | `http://localhost:3000` | No |
| `HTTPS_ONLY` | Enforce HTTPS (true/false) | `false` | ⚠️ Prod |
| `SECURE_COOKIES` | Use secure cookies (true/false) | `false` | ⚠️ Prod |

**Example (Production):**
```bash
ALLOWED_HOSTS=yourapp.com,www.yourapp.com
CORS_ORIGINS=https://yourapp.com,https://www.yourapp.com
HTTPS_ONLY=true
SECURE_COOKIES=true
```

---

### Monitoring Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `PROMETHEUS_ENABLED` | Enable Prometheus metrics (true/false) | `true` | No |
| `PROMETHEUS_PORT` | Prometheus metrics port | `9090` | No |
| `GRAFANA_ENABLED` | Enable Grafana dashboards (true/false) | `true` | No |
| `GRAFANA_PORT` | Grafana dashboard port | `3000` | No |

**Example:**
```bash
PROMETHEUS_ENABLED=true
PROMETHEUS_PORT=9090
GRAFANA_ENABLED=true
GRAFANA_PORT=3000
```

---

## 📁 Configuration Files

### .env File Structure

```bash
# development/.env

# ============================================
# CORE CONFIGURATION
# ============================================
DEPLOYMENT_ENV=production
PORT=8000
LOG_LEVEL=INFO

# ============================================
# DATABASE
# ============================================
DATABASE_URL=postgresql://user:pass@localhost:5432/saas
DB_POOL_SIZE=40
DB_MAX_OVERFLOW=20

# ============================================
# REDIS
# ============================================
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your_secure_password
REDIS_DB=0

# ============================================
# JWT AUTHENTICATION
# ============================================
JWT_ALGORITHM=RS256
JWT_PRIVATE_KEY_PATH=keys/jwt-private.pem
JWT_PUBLIC_KEY_PATH=keys/jwt-public.pem
JWT_AUDIENCE=my-api
JWT_ISSUER=my-auth-service
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# ============================================
# STRIPE PAYMENTS
# ============================================
STRIPE_API_KEY=sk_test_...
STRIPE_PUBLISHABLE_KEY=pk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...

# ============================================
# EMAIL (SENDGRID)
# ============================================
SENDGRID_API_KEY=SG.xxx...
SENDGRID_FROM_EMAIL=noreply@yourapp.com
SENDGRID_FROM_NAME="Your App Team"

# ============================================
# GPU CONFIGURATION
# ============================================
USE_GPU=true
CUDA_VISIBLE_DEVICES=0
PYTORCH_CUDA_ALLOC_CONF=max_split_size_mb:512
GPU_BATCH_SIZE=32

# ============================================
# SECURITY
# ============================================
ALLOWED_HOSTS=yourapp.com
CORS_ORIGINS=https://yourapp.com
HTTPS_ONLY=true
SECURE_COOKIES=true
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60
```

---

## 🌍 Environment-Specific Configurations

### Development (.env.development)
```bash
DEPLOYMENT_ENV=development
DATABASE_URL=sqlite:///./dev.db  # SQLite for local dev
REDIS_HOST=localhost
REDIS_PASSWORD=  # No password needed locally
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60  # Longer for dev
LOG_LEVEL=DEBUG
HTTPS_ONLY=false
```

### Staging (.env.staging)
```bash
DEPLOYMENT_ENV=staging
DATABASE_URL=postgresql://user:pass@staging-db:5432/saas
REDIS_HOST=staging-redis
REDIS_PASSWORD=staging_password
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
LOG_LEVEL=INFO
HTTPS_ONLY=true
```

### Production (.env.production)
```bash
DEPLOYMENT_ENV=production
DATABASE_URL=postgresql://user:pass@prod-db:5432/saas
REDIS_HOST=prod-redis.cluster
REDIS_PASSWORD=strong_production_password
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15  # Shorter for security
LOG_LEVEL=WARNING
HTTPS_ONLY=true
SECURE_COOKIES=true
ALLOWED_HOSTS=yourapp.com,www.yourapp.com
```

---

## 🔒 Security Best Practices

### Secret Management

**❌ DON'T:**
```bash
# Never commit secrets to git
JWT_PRIVATE_KEY_PATH=keys/jwt-private.pem  # File committed to repo
STRIPE_API_KEY=sk_live_abc123...           # Hardcoded in .env
```

**✅ DO:**
```bash
# Use environment variables from secure vaults
JWT_PRIVATE_KEY_PATH=/run/secrets/jwt-private-key  # Docker secret
STRIPE_API_KEY=${STRIPE_API_KEY}                   # From vault/K8s secret
```

### Key Rotation
```bash
# Generate new JWT keys
openssl genrsa -out jwt-private.pem 4096
openssl rsa -in jwt-private.pem -pubout -out jwt-public.pem

# Update environment variables
JWT_PRIVATE_KEY_PATH=/path/to/new/jwt-private.pem
JWT_PUBLIC_KEY_PATH=/path/to/new/jwt-public.pem

# Restart services
docker compose restart
```

---

## 📊 Configuration Validation

### Startup Checks
```python
# Validate configuration on startup
def validate_config():
    required_vars = [
        "DATABASE_URL",
        "REDIS_HOST",
        "JWT_PRIVATE_KEY_PATH",
        "JWT_PUBLIC_KEY_PATH"
    ]

    missing = [var for var in required_vars if not os.getenv(var)]

    if missing:
        raise ConfigurationError(f"Missing required variables: {missing}")

    if os.getenv("DEPLOYMENT_ENV") == "production":
        if not os.getenv("REDIS_PASSWORD"):
            raise ConfigurationError("Redis password required in production")
```

### Health Checks
```bash
# Check configuration health
curl http://localhost:8000/health

# Response
{
  "status": "healthy",
  "database": "connected",
  "redis": "connected",
  "config": {
    "deployment_env": "production",
    "jwt_algorithm": "RS256",
    "rate_limiting": "enabled"
  }
}
```

---

## 🎯 Quick Reference

**Most Common Configurations:**

| Use Case | Key Variables |
|----------|---------------|
| Local Development | `DEPLOYMENT_ENV=development`, `DATABASE_URL=sqlite:///./dev.db` |
| Staging Deployment | `DEPLOYMENT_ENV=staging`, full PostgreSQL + Redis config |
| Production Deployment | `DEPLOYMENT_ENV=production`, HTTPS + security configs |
| GPU Computing | `USE_GPU=true`, `CUDA_VISIBLE_DEVICES=0` |
| Payment Integration | `STRIPE_API_KEY`, `STRIPE_WEBHOOK_SECRET` |
| Email Notifications | `SENDGRID_API_KEY`, `SENDGRID_FROM_EMAIL` |

---

## 📚 Related Documentation

- **Environment Configuration Guide:** [ENV_CONFIGURATION_GUIDE.md](../guides/ENV_CONFIGURATION_GUIDE.md)
- **Deployment Guide:** [PRODUCTION_DEPLOYMENT_GUIDE.md](../PRODUCTION_DEPLOYMENT_GUIDE.md)
- **Environment Variables (Deployment):** [ENVIRONMENT_VARIABLES.md](../deployment/ENVIRONMENT_VARIABLES.md)
- **SaaS Architecture:** [saas-architecture.md](../architecture/saas-architecture.md)

---

**Navigation:** [← Index](../INDEX.md) | [Deployment Guide →](../PRODUCTION_DEPLOYMENT_GUIDE.md)
