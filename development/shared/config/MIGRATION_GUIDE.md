# Configuration System Migration Guide

This guide shows how to migrate from scattered `os.getenv()` calls to the new Pydantic-based configuration system.

## Benefits of Migration

1. **Type Safety**: Get IDE autocomplete and type checking
2. **Validation**: Catch configuration errors at startup, not runtime
3. **Documentation**: Self-documenting configuration
4. **Security**: Secrets never appear in logs
5. **Testing**: Easy to override config for tests

## Before and After Examples

### Example 1: Database Configuration

**Before (database/connection.py):**
```python
import os
from sqlalchemy import create_engine

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    DATABASE_URL = f"sqlite:///./catalytic.db"

engine = create_engine(
    DATABASE_URL,
    pool_size=20,
    max_overflow=40,
)
```

**After:**
```python
from shared.config import get_settings

settings = get_settings()

engine = create_engine(
    settings.database.url,
    pool_size=settings.database.pool_size,
    max_overflow=settings.database.max_overflow,
)

# Type-safe access
if settings.database.is_postgresql:
    print("Using PostgreSQL with connection pooling")
```

### Example 2: JWT Authentication

**Before (auth/jwt_auth.py):**
```python
import os
import secrets

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "RS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
```

**After:**
```python
from shared.config import get_settings

settings = get_settings()

# Settings are already validated - if JWT_SECRET_KEY is missing in production,
# the application won't even start!

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(
        minutes=settings.auth.access_token_expire_minutes
    )
    to_encode.update({"exp": expire})
    
    # Get secret value (only when needed)
    secret = settings.auth.jwt_secret_key.get_secret_value()
    
    return jwt.encode(
        to_encode,
        secret,
        algorithm=settings.auth.jwt_algorithm
    )
```

### Example 3: Redis Connection

**Before:**
```python
import os
import redis

redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", "6379")),
    db=0,
    password=os.getenv("REDIS_PASSWORD"),
)
```

**After:**
```python
from shared.config import get_settings
import redis

settings = get_settings()

redis_client = redis.Redis(
    host=settings.redis.host,
    port=settings.redis.port,
    db=settings.redis.db,
    password=settings.redis.password.get_secret_value() if settings.redis.password else None,
    max_connections=settings.redis.max_connections,
    socket_timeout=settings.redis.socket_timeout,
)

# Or use the connection URL
redis_client = redis.from_url(settings.redis.connection_url)
```

### Example 4: CORS Configuration

**Before (api/saas_server.py):**
```python
import os

allowed_origins = os.getenv(
    "CORS_ALLOWED_ORIGINS",
    "http://localhost:3000,http://localhost:3001"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**After:**
```python
from shared.config import get_settings

settings = get_settings()

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors.allowed_origins,  # Already parsed to list
    allow_credentials=settings.cors.allow_credentials,
    allow_methods=settings.cors.allow_methods,
    allow_headers=settings.cors.allow_headers,
    max_age=settings.cors.max_age,
)
```

### Example 5: Environment-Specific Logic

**Before:**
```python
import os

if os.getenv("DEPLOYMENT_ENV") == "production":
    # production logic
    log_level = logging.INFO
else:
    # development logic
    log_level = logging.DEBUG
```

**After:**
```python
from shared.config import get_settings, Environment

settings = get_settings()

if settings.app.env == Environment.PRODUCTION:
    # production logic (type-safe enum comparison)
    log_level = logging.INFO
else:
    # development logic
    log_level = logging.DEBUG

# Or even better, just use:
log_level = logging.getLevelName(settings.app.log_level.value)
```

## Migration Checklist

For each file that uses `os.getenv()`:

- [ ] Import settings: `from shared.config import get_settings`
- [ ] Get settings instance: `settings = get_settings()`
- [ ] Replace `os.getenv("KEY", "default")` with `settings.domain.key`
- [ ] Remove type conversions like `int()`, `bool()` (handled by Pydantic)
- [ ] Use `.get_secret_value()` for SecretStr fields
- [ ] Remove default value generation (e.g., `secrets.token_urlsafe()`)
- [ ] Test that validation catches missing required values

## Testing with Custom Configuration

**Override configuration in tests:**

```python
import pytest
from shared.config import Settings, get_settings

@pytest.fixture
def test_settings():
    """Provide test-specific configuration"""
    return Settings(
        app={"env": "testing", "debug": True},
        database={"url": "sqlite:///:memory:"},
        redis={"host": "localhost", "port": 6379},
        auth={"jwt_secret_key": "test_secret_key_123"},
    )

def test_something(test_settings, monkeypatch):
    """Test with custom config"""
    # Clear cache and set test settings
    get_settings.cache_clear()
    monkeypatch.setattr("shared.config.settings.get_settings", lambda: test_settings)
    
    # Now your code uses test_settings
    settings = get_settings()
    assert settings.app.env == "testing"
```

## Handling Backward Compatibility

If you need to support both old and new configuration during migration:

```python
from shared.config import get_settings
import os

def get_database_url() -> str:
    """Get database URL with backward compatibility"""
    try:
        settings = get_settings()
        return settings.database.url
    except Exception:
        # Fallback to old method
        return os.getenv("DATABASE_URL", "sqlite:///./catalytic.db")
```

## Common Pitfalls

### ❌ Don't: Access secrets without get_secret_value()

```python
# This won't work - SecretStr doesn't convert to string automatically
password = settings.redis.password  # SecretStr object
redis.Redis(password=password)  # ERROR
```

### ✅ Do: Use get_secret_value()

```python
password = settings.redis.password.get_secret_value() if settings.redis.password else None
redis.Redis(password=password)  # OK
```

### ❌ Don't: Modify settings at runtime

```python
settings = get_settings()
settings.app.debug = True  # This won't work - settings are immutable
```

### ✅ Do: Create new Settings instance for different config

```python
test_settings = Settings(app={"debug": True})
```

### ❌ Don't: Import settings at module level in circular dependencies

```python
# module_a.py
from shared.config import get_settings
settings = get_settings()  # May cause issues if circular

from module_b import something  # Imports module_a
```

### ✅ Do: Import settings in functions or use lazy loading

```python
# module_a.py
from shared.config import get_settings

def my_function():
    settings = get_settings()  # Lazy loading
    # use settings
```

## Priority Migration Order

Migrate in this order for maximum impact:

1. **Database configuration** (connection.py) - Critical for stability
2. **Authentication** (jwt_auth.py) - Critical for security
3. **Redis connection** - Eliminates duplication
4. **API server** (saas_server.py) - Central entry point
5. **Middleware** - Affects all requests
6. **Remaining modules** - As time permits

## Validation Benefits

The new system catches errors at startup:

```bash
# Before: Errors discovered at runtime
$ python api/saas_server.py
# ... starts successfully ...
# Later: "invalid database URL" when first query runs

# After: Errors discovered immediately
$ python api/saas_server.py
pydantic.error_wrappers.ValidationError: 1 validation error for Settings
database -> url
  DATABASE_URL cannot be empty (type=value_error)
```

## Getting Help

- Configuration reference: `shared/config/settings.py`
- Example configuration: `.env.example`
- Tests: `shared/config/test_config.py`
- Pydantic docs: https://pydantic-docs.helpmanual.io/

## Next Steps

1. Review `.env.example` and create your `.env` file
2. Install Pydantic if not already installed: `pip install pydantic`
3. Run tests: `pytest shared/config/test_config.py -v`
4. Start migrating files (begin with database/connection.py)
5. Update imports and remove `os.getenv()` calls
6. Test thoroughly in development before deploying
