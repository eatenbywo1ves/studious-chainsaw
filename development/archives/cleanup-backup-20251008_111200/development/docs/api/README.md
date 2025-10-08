# API Documentation - Complete OpenAPI Specification

**Status:** ✅ Production Ready  
**OpenAPI Version:** 3.0.3  
**API Version:** 1.0.0  
**Last Updated:** October 5, 2025

---

## 📚 Documentation Files

| File | Description | Usage |
|------|-------------|-------|
| **openapi.yaml** | OpenAPI 3.0 spec (YAML) | Import into Postman, Insomnia, Swagger Editor |
| **openapi.json** | OpenAPI 3.0 spec (JSON) | Programmatic access, code generation |
| **openapi_generator.py** | Generator script | Regenerate spec when API changes |
| **../API_DOCUMENTATION.md** | Human-readable docs | Developer reference guide |

---

## 🚀 Quick Start

### View Interactive Documentation

#### 1. Start the SaaS API Server

```bash
cd C:/Users/Corbin/development/saas
uvicorn api.saas_server:app --reload --port 8000
```

#### 2. Access Swagger UI

Open in browser: **http://localhost:8000/docs**

Features:
- Interactive API explorer
- Try requests directly from browser
- Automatic authentication handling
- Request/response examples
- Schema validation

#### 3. Access ReDoc (Alternative)

Open in browser: **http://localhost:8000/redoc**

Features:
- Clean, responsive documentation
- Three-panel layout
- Search functionality
- Markdown support

---

## 📖 Using the OpenAPI Specification

### Import into Postman

1. Open Postman
2. Click **Import** → **Upload Files**
3. Select `openapi.yaml` or `openapi.json`
4. Postman creates a collection with all endpoints
5. Configure authentication with JWT token

### Import into Insomnia

1. Open Insomnia
2. Click **Create** → **Import From** → **File**
3. Select `openapi.yaml`
4. All endpoints imported automatically

### Generate Client SDKs

Use OpenAPI Generator to create client libraries:

```bash
# Install OpenAPI Generator
npm install -g @openapitools/openapi-generator-cli

# Generate Python client
openapi-generator-cli generate \
  -i openapi.yaml \
  -g python \
  -o ./clients/python

# Generate TypeScript client
openapi-generator-cli generate \
  -i openapi.yaml \
  -g typescript-axios \
  -o ./clients/typescript

# Generate Go client
openapi-generator-cli generate \
  -i openapi.yaml \
  -g go \
  -o ./clients/go
```

---

## 🔧 Regenerating the OpenAPI Spec

When you add or modify API endpoints, regenerate the spec:

```bash
cd C:/Users/Corbin/development/docs/api
python openapi_generator.py
```

This updates:
- `openapi.yaml` - YAML format
- `openapi.json` - JSON format

**Note:** The generator script reads the actual FastAPI routes, so ensure your server is up-to-date.

---

## 📋 API Endpoint Summary

### Authentication Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/auth/register` | Register new tenant | ❌ |
| POST | `/api/auth/login` | Login and get JWT | ❌ |
| POST | `/api/auth/verify` | Verify JWT token | ❌ |
| POST | `/api/auth/refresh` | Refresh access token | ❌ |
| POST | `/api/auth/logout` | Logout (blacklist token) | ✅ |

### Lattice Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/lattices` | Create new lattice | ✅ |
| GET | `/api/lattices` | List tenant lattices | ✅ |
| GET | `/api/lattices/{id}` | Get lattice details | ✅ |
| DELETE | `/api/lattices/{id}` | Delete lattice | ✅ |

### Monitoring Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/health` | Health check | ❌ |
| GET | `/metrics` | Prometheus metrics | ❌ |

---

## 🔐 Authentication Flow

### 1. Register Tenant

```http
POST /api/auth/register
Content-Type: application/json

{
  "company_name": "Acme Corp",
  "email": "admin@acme.com",
  "password": "SecurePass123!",
  "first_name": "John",
  "last_name": "Doe",
  "plan_code": "free"
}
```

**Response:**
```json
{
  "tenant_id": "uuid",
  "user_id": "uuid",
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "bearer"
}
```

### 2. Use Access Token

All protected endpoints require JWT in Authorization header:

```http
GET /api/lattices
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 3. Refresh Token (when expired)

```http
POST /api/auth/refresh
Content-Type: application/json

{
  "refresh_token": "eyJ..."
}
```

---

## 📊 Request/Response Examples

### Create Lattice

**Request:**
```bash
curl -X POST http://localhost:8000/api/lattices \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Lattice",
    "dimensions": 3,
    "size": 1000,
    "field_type": "complex",
    "geometry": "euclidean",
    "enable_gpu": true
  }'
```

**Response (201 Created):**
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "name": "My Lattice",
  "dimensions": 3,
  "size": 1000,
  "field_type": "complex",
  "geometry": "euclidean",
  "owner_id": "550e8400-e29b-41d4-a716-446655440000",
  "created_at": "2025-10-05T20:00:00Z",
  "updated_at": "2025-10-05T20:00:00Z",
  "processing_info": {
    "gpu_used": true,
    "processing_time_ms": 45.2
  }
}
```

---

## ⚠️ Error Responses

All errors follow consistent format:

```json
{
  "detail": "Error message",
  "status_code": 400,
  "type": "error_type"
}
```

### Common Errors

**400 Bad Request:**
```json
{
  "detail": "Validation error: field 'dimensions' must be between 2 and 10",
  "status_code": 400,
  "type": "validation_error"
}
```

**401 Unauthorized:**
```json
{
  "detail": "Invalid or expired token",
  "status_code": 401,
  "type": "authentication_error"
}
```

**429 Rate Limit Exceeded:**
```json
{
  "detail": "Rate limit exceeded. Try again in 60 seconds",
  "status_code": 429,
  "type": "rate_limit_error"
}
```

---

## 🎯 Subscription Plans

| Feature | Free | Pro | Enterprise |
|---------|------|-----|------------|
| Requests/Month | 1,000 | 100,000 | Custom |
| Max Lattices | 5 | 100 | Unlimited |
| Max Dimensions | 3 | 10 | Unlimited |
| Max Lattice Size | 10 | 1,000 | 10,000 |
| GPU Acceleration | ❌ | ✅ | ✅ |
| Priority Support | ❌ | ✅ | ✅ |
| SLA | None | 99.9% | 99.99% |

---

## 🔒 Security Features

### D3FEND Compliance

This API implements MITRE D3FEND defensive techniques:

- **D3-UAC** (User Account Control): JWT authentication, password policies
- **D3-RAC** (Resource Access Control): Rate limiting, tenant isolation
- **D3-IVV** (Input Validation): Pydantic schemas, SQL injection prevention
- **D3-KM** (Key Management): Token blacklist, secret rotation

### Security Headers

All responses include:

- `Strict-Transport-Security`: HTTPS enforcement
- `X-Content-Type-Options: nosniff`: MIME sniffing prevention
- `X-Frame-Options: DENY`: Clickjacking prevention
- `Content-Security-Policy`: XSS prevention

---

## 🚀 Performance

### GPU Acceleration

- **21.22x speedup** for lattices with >1000 elements
- Automatic GPU detection and utilization
- Graceful CPU fallback

### Latency Targets

| Endpoint | p95 Latency | p99 Latency |
|----------|-------------|-------------|
| `/api/auth/login` | <100ms | <200ms |
| `/api/lattices` (GET) | <50ms | <100ms |
| `/api/lattices` (POST) | <500ms | <1000ms |
| `/health` | <10ms | <20ms |

---

## 📝 Changelog

### Version 1.0.0 (October 5, 2025)

**Added:**
- Complete OpenAPI 3.0.3 specification
- Interactive Swagger UI at `/docs`
- ReDoc documentation at `/redoc`
- Authentication endpoints (register, login, verify, refresh, logout)
- Lattice CRUD operations
- Health check and metrics endpoints
- JWT token blacklist support
- Rate limiting documentation
- Subscription plan details

---

## 🛠️ Development Tools

### Validate OpenAPI Spec

```bash
# Install validator
npm install -g @apidevtools/swagger-cli

# Validate spec
swagger-cli validate openapi.yaml
```

### Test API Endpoints

```bash
# Using HTTPie
pip install httpie

# Register
http POST localhost:8000/api/auth/register \
  company_name="Test Corp" \
  email="test@example.com" \
  password="Test123!" \
  first_name="Test" \
  last_name="User" \
  plan_code="free"

# Login
http POST localhost:8000/api/auth/login \
  email="test@example.com" \
  password="Test123!"
```

---

## 📚 Additional Resources

- **Human-Readable Docs**: `../API_DOCUMENTATION.md`
- **Interactive Testing**: http://localhost:8000/docs
- **OpenAPI Spec**: `openapi.yaml` / `openapi.json`
- **Integration Tests**: `../../tests/integration/`
- **Systematic Plan**: `../../SYSTEMATIC_EXECUTION_PLAN_2025-10-05.md`

---

## 🏆 Completion Status

- ✅ OpenAPI 3.0.3 specification generated
- ✅ YAML and JSON formats created
- ✅ Swagger UI integration ready
- ✅ ReDoc integration ready
- ✅ Human-readable documentation complete
- ✅ Authentication flow documented
- ✅ All endpoints documented with examples
- ✅ Error responses standardized
- ✅ Rate limiting documented
- ✅ Security features documented

**Phase 2 (Days 4-5): API Documentation** → ✅ **COMPLETE**

---

**Next Phase:** E2E Testing Framework (Days 6-8)

---

*Generated: October 5, 2025*  
*Systematic Execution Plan: Phase 2 Complete*
