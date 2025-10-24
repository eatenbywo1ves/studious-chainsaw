# Configuration System - Quick Start Guide

## ✅ Installation Complete!

The Pydantic configuration system is now set up and ready to use.

## Test Verification

```bash
$ python -c "from shared.config import get_settings; print('Config loaded:', get_settings().app.env.value)"
Config loaded: development
```

## Immediate Usage

### 1. Basic Usage

```python
from shared.config import get_settings

# Get settings instance (cached)
settings = get_settings()

# Access configuration with autocomplete
print(settings.database.url)         # sqlite:///./catalytic_saas.db
print(settings.redis.host)            # localhost
print(settings.app.env.value)         # development
print(settings.security.security_level.value)  # enhanced
```

### 2. Environment Variables

Create or update your `.env` file:

```bash
# Copy the example
cp .env.example .env

# Edit with your values
nano .env
```

Key variables:
```bash
APP_ENV=development
DATABASE_URL=sqlite:///./catalytic.db
REDIS_HOST=localhost
REDIS_PORT=6379
JWT_SECRET_KEY=your_secret_key_here
```

### 3. Replace os.getenv() Calls

**Before:**
```python
import os
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./db.sqlite")
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
```

**After:**
```python
from shared.config import get_settings

settings = get_settings()
database_url = settings.database.url
redis_host = settings.redis.host
redis_port = settings.redis.port  # Already an int!
```

### 4. Accessing Secrets

Secrets are stored as `SecretStr` and never logged:

```python
from shared.config import get_settings

settings = get_settings()

# Get the actual secret value when needed
jwt_secret = settings.auth.secret_key.get_secret_value()
redis_password = settings.redis.password.get_secret_value() if settings.redis.password else None
```

### 5. Environment Detection

```python
from shared.config import get_settings, Environment

settings = get_settings()

if settings.app.env == Environment.PRODUCTION:
    # Production-specific code
    enable_monitoring()
elif settings.app.env == Environment.DEVELOPMENT:
    # Development-specific code
    enable_debug_tools()
```

## Next Steps

### Priority 1: Migrate Database Connection (High Impact)

**File:** `development/saas/database/connection.py`

**Current:**
```python
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    DATABASE_URL = f"sqlite:///{sqlite_path}"

engine = create_engine(
    DATABASE_URL,
    pool_size=20,
    max_overflow=40,
)
```

**Migrated:**
```python
from shared.config import get_settings

settings = get_settings()

if settings.database.is_sqlite:
    engine = create_engine(
        settings.database.url,
        connect_args={"check_same_thread": False},
    )
else:
    engine = create_engine(
        settings.database.url,
        pool_size=settings.database.pool_size,
        max_overflow=settings.database.max_overflow,
        pool_pre_ping=settings.database.pool_pre_ping,
    )
```

### Priority 2: Migrate JWT Auth (Security Critical)

**File:** `development/saas/auth/jwt_auth.py`

**Lines to replace:**
```python
# Line 24-27
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))  # ❌ DANGEROUS
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "RS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "30"))
```

**With:**
```python
from shared.config import get_settings

settings = get_settings()
# If JWT_SECRET_KEY is missing in production, app won't start! ✅
JWT_ALGORITHM = settings.auth.algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = settings.auth.access_token_expire_minutes
REFRESH_TOKEN_EXPIRE_DAYS = settings.auth.refresh_token_expire_days
```

### Priority 3: Migrate Redis Connection

**File:** `development/saas/auth/jwt_auth.py` (lines 69-75)

**Current:**
```python
redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", "6379")),
    password=os.getenv("REDIS_PASSWORD"),
)
```

**Migrated:**
```python
from shared.config import get_settings

settings = get_settings()

# Use the pre-built connection URL
redis_client = redis.from_url(settings.redis.connection_url)

# Or manual configuration
redis_client = redis.Redis(
    host=settings.redis.host,
    port=settings.redis.port,
    db=settings.redis.db,
    password=settings.redis.password.get_secret_value() if settings.redis.password else None,
    max_connections=settings.redis.max_connections,
)
```

## Configuration Domains

All configuration is organized into logical groups:

| Domain | Access Path | Purpose |
|--------|------------|---------|
| App | `settings.app.*` | Application-level settings |
| Database | `settings.database.*` | Database connection config |
| Redis | `settings.redis.*` | Redis connection & circuit breaker |
| Auth | `settings.auth.*` | JWT, sessions, CSRF |
| Security | `settings.security.*` | Rate limiting, DDoS, encryption |
| CORS | `settings.cors.*` | Cross-origin configuration |
| Email | `settings.email.*` | Email provider settings |
| Stripe | `settings.stripe.*` | Payment configuration |

## Benefits You Get Now

### ✅ Type Safety
- IDE autocomplete for all config
- Mypy/Pyright type checking
- No more `int(os.getenv(...))` errors

### ✅ Validation
- Invalid config caught at startup
- Required fields enforced
- Value bounds checked (e.g., port 1-65535)

### ✅ Security
- Secrets never logged (`SecretStr`)
- Production requires JWT secret (no random defaults)
- PostgreSQL enforced in production (no SQLite)

### ✅ Documentation
- Self-documenting config
- `.env.example` auto-generated
- Type hints show what's expected

### ✅ Testing
- Easy to override config in tests
- No global state pollution
- Isolated test environments

## Common Patterns

### Pattern 1: Connection URLs

```python
from shared.config import get_settings

settings = get_settings()

# Database
db_url = settings.database.url  # Full connection string

# Redis
redis_url = settings.redis.connection_url  # redis://password@host:port/db
```

### Pattern 2: Environment-Specific Behavior

```python
from shared.config import get_settings, Environment

settings = get_settings()

# Check environment
is_prod = settings.app.env == Environment.PRODUCTION
is_dev = settings.app.env == Environment.DEVELOPMENT

# Use appropriate log level
log_level = logging.getLevelName(settings.app.log_level.value)
```

### Pattern 3: Feature Flags

```python
from shared.config import get_settings

settings = get_settings()

if settings.security.rate_limit_enabled:
    app.add_middleware(RateLimitMiddleware, 
        rate=settings.security.rate_limit_per_minute)

if settings.security.ddos_protection_enabled:
    app.add_middleware(DDoSProtectionMiddleware,
        block_duration=settings.security.ddos_block_duration_minutes)
```

## Troubleshooting

### Error: "field required"

You're missing an environment variable. Check the error message:

```
pydantic.ValidationError: 1 validation error for Settings
auth -> secret_key
  Field required
```

Solution: Set `JWT_SECRET_KEY` in your `.env` file.

### Error: "SecretStr is not subscriptable"

Don't use the SecretStr directly:

```python
# ❌ Wrong
password = settings.redis.password

# ✅ Correct
password = settings.redis.password.get_secret_value() if settings.redis.password else None
```

### Settings Not Updating

Settings are cached. Clear cache to reload:

```python
from shared.config import get_settings

get_settings.cache_clear()
settings = get_settings()  # Fresh load
```

## Files Created

```
development/
├── .env.example              # Template with all variables
└── shared/
    └── config/
        ├── __init__.py       # Public API
        ├── settings.py       # Configuration classes
        ├── test_config.py    # Test suite
        ├── README.md         # Full documentation
        ├── MIGRATION_GUIDE.md # Detailed migration steps
        └── QUICK_START.md    # This file
```

## Resources

- **Full Documentation**: `shared/config/README.md`
- **Migration Guide**: `shared/config/MIGRATION_GUIDE.md`
- **Configuration Template**: `.env.example`
- **Tests**: `shared/config/test_config.py`
- **Pydantic Docs**: https://docs.pydantic.dev/latest/concepts/pydantic_settings/

## Support

If you encounter issues:

1. Check `.env.example` for required variables
2. Review error messages carefully (Pydantic is verbose)
3. Run tests: `pytest shared/config/test_config.py -v`
4. Check migration guide for your specific use case

---

**Status:** ✅ Configuration system installed and tested  
**Next Action:** Begin migrating files (start with database/connection.py)  
**Estimated Migration Time:** 13 days for complete migration (per roadmap)
