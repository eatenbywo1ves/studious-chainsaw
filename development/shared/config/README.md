# Centralized Configuration System

Type-safe, validated configuration management using Pydantic BaseSettings.

## Quick Start

```python
from shared.config import get_settings

# Get settings instance (cached, loaded once)
settings = get_settings()

# Access configuration with full IDE autocomplete
print(f"Database: {settings.database.url}")
print(f"Redis: {settings.redis.host}:{settings.redis.port}")
print(f"Environment: {settings.app.env.value}")

# Secrets are protected
jwt_secret = settings.auth.jwt_secret_key.get_secret_value()
```

## Features

✅ **Type Safety**: Full IDE autocomplete and type checking  
✅ **Validation**: Catch errors at startup, not runtime  
✅ **Security**: Secrets never logged (using SecretStr)  
✅ **Documentation**: Self-documenting configuration  
✅ **Testing**: Easy to override for tests  
✅ **Environment Support**: Development, staging, production  
✅ **Fail Fast**: Missing required config prevents startup  

## Configuration Domains

The configuration is organized into logical domains:

### Application (`settings.app`)
- Environment (development/staging/production)
- Debug mode
- Logging level
- Server host/port
- Frontend/backend URLs

### Database (`settings.database`)
- Connection URL
- Pool size and overflow
- Pre-ping enabled
- SQLite vs PostgreSQL detection

### Redis (`settings.redis`)
- Host, port, password
- Connection pool settings
- Circuit breaker configuration
- Timeouts

### Authentication (`settings.auth`)
- JWT secret key (REQUIRED in production)
- JWT algorithm (RS256/HS256)
- RSA key paths
- Token expiration settings
- Session configuration
- CSRF protection

### Security (`settings.security`)
- Security level (basic/enhanced/strict)
- Encryption key paths
- Rate limiting
- DDoS protection

### CORS (`settings.cors`)
- Allowed origins
- Credentials, methods, headers
- Max age

### Email (`settings.email`)
- SendGrid, AWS SES, or SMTP
- From address and name
- Auto-detection of provider

### Stripe (`settings.stripe`)
- API keys
- Webhook secret
- Test vs live mode detection

## Environment Variables

All configuration can be set via environment variables. See `.env.example` for complete list.

### Naming Convention

Environment variables use prefixes for organization:

- `APP_*` - Application settings
- `DATABASE_*` - Database configuration
- `REDIS_*` - Redis configuration
- `JWT_*` - JWT/auth configuration
- `CORS_*` - CORS configuration
- `STRIPE_*` - Stripe configuration

Example:
```bash
APP_ENV=production
DATABASE_URL=postgresql://user:pass@localhost/db
REDIS_HOST=redis.example.com
JWT_SECRET_KEY=super_secret_key_here
```

## Required Configuration

### Development
Minimal requirements (has sensible defaults):
```bash
# Optional - defaults to SQLite
DATABASE_URL=sqlite:///./catalytic.db

# Optional - defaults to localhost
REDIS_HOST=localhost
```

### Production
Required configuration:
```bash
# REQUIRED - no default in production
JWT_SECRET_KEY=your_secret_key_here

# REQUIRED - PostgreSQL only in production
DATABASE_URL=postgresql://user:pass@host/database

# REQUIRED - secure Redis
REDIS_PASSWORD=your_redis_password

# REQUIRED - encryption keys
API_ENCRYPTION_KEY_PATH=/path/to/api.key
DB_ENCRYPTION_KEY_PATH=/path/to/db.key
```

## Examples

### Environment Detection

```python
from shared.config import get_settings, Environment

settings = get_settings()

if settings.app.env == Environment.PRODUCTION:
    # Production-specific logic
    enable_monitoring()
elif settings.app.env == Environment.DEVELOPMENT:
    # Development-specific logic
    enable_debug_toolbar()
```

### Accessing Secrets

```python
from shared.config import get_settings

settings = get_settings()

# SecretStr fields must use get_secret_value()
redis_password = settings.redis.password.get_secret_value()
jwt_secret = settings.auth.jwt_secret_key.get_secret_value()
```

### Conditional Configuration

```python
from shared.config import get_settings

settings = get_settings()

# Database type detection
if settings.database.is_sqlite:
    print("Using SQLite for development")
elif settings.database.is_postgresql:
    print("Using PostgreSQL for production")

# Email provider detection
if settings.email.provider == "sendgrid":
    # Use SendGrid
    send_via_sendgrid()
elif settings.email.provider == "ses":
    # Use AWS SES
    send_via_ses()
```

### Testing with Custom Config

```python
import pytest
from shared.config import Settings

@pytest.fixture
def test_settings():
    return Settings(
        app={"env": "testing", "debug": True},
        database={"url": "sqlite:///:memory:"},
        auth={"jwt_secret_key": "test_secret"},
    )

def test_something(test_settings):
    # Use test_settings in your test
    assert test_settings.app.env == "testing"
```

## Validation Examples

The configuration system validates all settings on startup:

```python
# ❌ This will FAIL at startup (production requires PostgreSQL)
DEPLOYMENT_ENV=production
DATABASE_URL=sqlite:///./db.sqlite

# ❌ This will FAIL (invalid port)
REDIS_PORT=99999

# ❌ This will FAIL (JWT secret required in production)
DEPLOYMENT_ENV=production
JWT_SECRET_KEY=  # Empty

# ✅ This will SUCCEED
DEPLOYMENT_ENV=production
DATABASE_URL=postgresql://user:pass@host/db
REDIS_PORT=6379
JWT_SECRET_KEY=actual_secret_key_here
```

## Migration Guide

See [MIGRATION_GUIDE.md](./MIGRATION_GUIDE.md) for detailed instructions on migrating from `os.getenv()` to the new configuration system.

## API Reference

### Main Functions

#### `get_settings() -> Settings`
Returns cached Settings instance. Use this in application code.

```python
from shared.config import get_settings

settings = get_settings()
```

#### `get_config() -> Settings`
Alias for `get_settings()`.

### Settings Properties

All settings are immutable after initialization. Access them via dot notation:

```python
settings.app.env           # Application environment
settings.app.debug         # Debug mode
settings.app.log_level     # Logging level

settings.database.url      # Database URL
settings.database.is_sqlite     # True if SQLite
settings.database.is_postgresql # True if PostgreSQL

settings.redis.host        # Redis host
settings.redis.connection_url  # Full Redis URL

settings.auth.jwt_algorithm           # JWT algorithm
settings.auth.access_token_expire_minutes  # Token TTL

settings.security.security_level      # Security level enum
settings.cors.allowed_origins         # List of origins
settings.email.provider              # Auto-detected provider
settings.stripe.is_test_mode         # Test vs live
```

## File Structure

```
shared/config/
├── __init__.py           # Public exports
├── settings.py           # Main configuration classes
├── test_config.py        # Comprehensive tests
├── MIGRATION_GUIDE.md    # Migration instructions
└── README.md             # This file
```

## Testing

Run the test suite:

```bash
# Run all tests
pytest shared/config/test_config.py -v

# Run specific test class
pytest shared/config/test_config.py::TestAuthConfig -v

# Run with coverage
pytest shared/config/test_config.py --cov=shared.config --cov-report=html
```

## Troubleshooting

### "Settings object has no attribute X"

Make sure you're accessing the right domain:

```python
# ❌ Wrong
settings.jwt_secret_key

# ✅ Correct
settings.auth.jwt_secret_key
```

### "ValidationError: field required"

You're missing a required environment variable:

```bash
# Read the error message carefully
pydantic.error_wrappers.ValidationError: 1 validation error for Settings
auth -> jwt_secret_key
  JWT_SECRET_KEY is REQUIRED in production

# Set the variable
export JWT_SECRET_KEY="your_secret_here"
```

### "SecretStr is not JSON serializable"

Don't try to serialize SecretStr directly:

```python
# ❌ Wrong
json.dumps({"password": settings.redis.password})

# ✅ Correct
json.dumps({"password": settings.redis.password.get_secret_value()})
```

### Settings not updating

Settings are cached. Clear cache to reload:

```python
from shared.config import get_settings

# Clear cache
get_settings.cache_clear()

# Get fresh settings
settings = get_settings()
```

## Best Practices

1. **Import once per module**: Get settings at module level or in functions
2. **Use type hints**: Leverage IDE autocomplete
3. **Validate early**: Let Pydantic catch errors at startup
4. **Document overrides**: If you override in tests, document why
5. **Keep secrets secret**: Never log SecretStr values
6. **Environment-specific .env**: Use `.env.development`, `.env.production`

## Contributing

When adding new configuration:

1. Add to appropriate domain class in `settings.py`
2. Add validator if needed (see existing examples)
3. Add tests in `test_config.py`
4. Update `.env.example` with new variable
5. Document in this README

## Resources

- [Pydantic Documentation](https://pydantic-docs.helpmanual.io/)
- [BaseSettings](https://pydantic-docs.helpmanual.io/usage/settings/)
- [Environment Variables](https://pydantic-docs.helpmanual.io/usage/settings/#environment-variable-names)
