# Reference Documentation

Technical reference materials, API documentation, and configuration guides.

## API Documentation

### [OpenAPI Specification](../openapi.yaml)
Complete OpenAPI 3.0 specification for all REST APIs:
- Authentication endpoints
- Tenant management
- Subscription services
- Webhook handlers

### [API README](../api/README.md)
API documentation overview and getting started guide.

---

## Configuration Reference

### [Configuration Reference](./config-reference.md)
Comprehensive configuration documentation:
- Environment variables
- Configuration files
- Default values
- Best practices

---

## Database Reference

### Schema Documentation
- PostgreSQL database schema
- SQLite development schema
- Migration procedures
- Indexing strategy

### [Database Migrations](../deployment/DATABASE_MIGRATIONS.md)
Database migration guide and procedures.

---

## Redis Reference

### Cache Configuration
- Redis connection pooling
- Key naming conventions
- TTL strategies
- Memory optimization

Related guides:
- [Redis Pool Optimization](../guides/REDIS_POOL_OPTIMIZATION_GUIDE.md)
- [Redis Production Guide](../guides/REDIS_PRODUCTION_GUIDE.md)

---

## Security Reference

### Authentication
- JWT token structure
- Token blacklist management
- Password hashing (bcrypt)
- Session management

### API Security
- Rate limiting configuration
- CORS policies
- Security headers
- Input validation

---

## GPU & CUDA Reference

### CUDA Configuration
- CUDA version compatibility
- Device selection
- Memory management
- Error handling

### Supported Backends
- PyTorch GPU operations
- CuPy array operations
- CPU fallback behavior

---

## Monitoring Reference

### Metrics Catalog
See [Metrics Catalog](../monitoring/metrics_catalog.md) for complete list of metrics.

### Dashboard Reference
See [Dashboard Guide](../monitoring/dashboard_guide.md) for Grafana dashboards.

---

## Reference by Component

### SaaS Platform
- [Environment Variables](../deployment/ENVIRONMENT_VARIABLES.md)
- [API Endpoints](../api/README.md)
- [Database Schema](../deployment/DATABASE_MIGRATIONS.md)

### GhidraGo
- [GhidraGo Specification](../specifications/GHIDRAGO_SPECIFICATION.md)
- [Ghidra Extensions](../specifications/GHIDRA_EXTENSIONS_SUMMARY.md)

### Security Tools
- [D3FEND Mappings](../specifications/DEFENSIVE_SECURITY_AGENT_ARCHITECTURE.md)
- [Security Architecture](../architecture/security-architecture.md)

---

## Quick Reference Cards

### Environment Variables Quick Reference

```bash
# Core Settings
PORT=8000
DEPLOYMENT_ENV=production

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/db

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your-password

# Security
JWT_SECRET_KEY=your-secret-key
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# GPU
CUDA_VISIBLE_DEVICES=0
```

### Redis Pool Configuration

```python
# Recommended production settings
pool_size = 100  # per worker
max_overflow = 50
pool_timeout = 30
```

### Common API Endpoints

```
POST   /auth/register          # Create account
POST   /auth/login            # Get JWT token
GET    /auth/me               # Current user
GET    /tenants               # List tenants
POST   /subscriptions/create  # Create subscription
```

---

## Using Reference Documentation

### For New Developers
1. Start with [API README](../api/README.md)
2. Review [Environment Variables](../deployment/ENVIRONMENT_VARIABLES.md)
3. Check [Quick Start Guides](../quickstart/)

### For Configuration
1. See [Configuration Reference](./config-reference.md)
2. Review environment-specific settings
3. Check security best practices

### For Troubleshooting
1. Check [Monitoring Runbooks](../monitoring/runbooks/)
2. Review error codes in API docs
3. Check configuration values

---

**Navigation:** [← Back to Index](../INDEX.md) | [Development Root](../../)
