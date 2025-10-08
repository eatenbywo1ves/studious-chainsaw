# Catalytic Computing SaaS API - Complete Documentation

**Version:** 1.0.0  
**Base URL:** `http://localhost:8000` (Development) | `https://api.catalyticcomputing.example.com` (Production)  
**Authentication:** JWT Bearer Token

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Authentication](#authentication)
3. [API Endpoints](#api-endpoints)
4. [Error Handling](#error-handling)
5. [Rate Limiting](#rate-limiting)
6. [Examples](#examples)

---

## Quick Start

### 1. Register a New Tenant

```bash
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "company_name": "Acme Corporation",
    "email": "admin@acme.com",
    "password": "SecurePassword123!",
    "first_name": "John",
    "last_name": "Doe",
    "plan_code": "free"
  }'
```

**Response (201 Created):**
```json
{
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

### 2. Login (Get JWT Tokens)

```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@acme.com",
    "password": "SecurePassword123!"
  }'
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

### 3. Create a Lattice

```bash
curl -X POST http://localhost:8000/api/lattices \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My First Lattice",
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
  "name": "My First Lattice",
  "dimensions": 3,
  "size": 1000,
  "field_type": "complex",
  "geometry": "euclidean",
  "owner_id": "123e4567-e89b-12d3-a456-426614174000",
  "created_at": "2025-10-05T20:00:00Z",
  "updated_at": "2025-10-05T20:00:00Z",
  "processing_info": {
    "gpu_used": true,
    "processing_time_ms": 45.2
  }
}
```

---

## Authentication

### JWT Token-Based Authentication

All protected endpoints require a JWT access token in the `Authorization` header:

```
Authorization: Bearer <access_token>
```

### Token Lifecycle

| Token Type | Lifetime | Purpose | Storage |
|------------|----------|---------|---------|
| Access Token | 30 minutes | API requests | Memory (not localStorage) |
| Refresh Token | 7 days | Get new access tokens | HttpOnly cookie |

### Token Refresh

When access token expires, use refresh token to get a new one:

```bash
curl -X POST http://localhost:8000/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "<refresh_token>"}'
```

### Logout (Token Blacklist)

```bash
curl -X POST http://localhost:8000/api/auth/logout \
  -H "Authorization: Bearer <access_token>"
```

This adds the token to Redis blacklist for immediate invalidation.

---

## API Endpoints

### Authentication Endpoints

#### POST `/api/auth/register`

Register a new tenant and create admin user.

**Request Body:**
```json
{
  "company_name": "string (2-255 chars)",
  "email": "string (valid email)",
  "password": "string (min 8 chars, uppercase + lowercase + digit)",
  "first_name": "string (1-100 chars)",
  "last_name": "string (1-100 chars)",
  "domain": "string (optional)",
  "plan_code": "free|pro|enterprise (default: free)"
}
```

**Responses:**
- `201 Created`: Registration successful
- `400 Bad Request`: Invalid input data
- `409 Conflict`: Email already registered

---

#### POST `/api/auth/login`

Authenticate user and receive JWT tokens.

**Request Body:**
```json
{
  "email": "string",
  "password": "string"
}
```

**Responses:**
- `200 OK`: Login successful
- `401 Unauthorized`: Invalid credentials

---

#### POST `/api/auth/verify`

Verify a JWT token and get decoded payload.

**Request Body:**
```json
{
  "token": "string",
  "token_type": "access|refresh (default: access)"
}
```

**Response (200 OK):**
```json
{
  "sub": "user_id",
  "tenant_id": "tenant_id",
  "email": "user@example.com",
  "role": "admin|user",
  "type": "access|refresh",
  "jti": "token_id",
  "iat": 1696531200,
  "exp": 1696532000
}
```

---

#### POST `/api/auth/refresh`

Get new access token using refresh token.

**Request Body:**
```json
{
  "refresh_token": "string"
}
```

**Response (200 OK):**
```json
{
  "access_token": "string",
  "token_type": "bearer"
}
```

---

#### POST `/api/auth/logout`

🔒 **Requires Authentication**

Logout user and blacklist current token.

**Response (200 OK):**
```json
{
  "message": "Logged out successfully"
}
```

---

### Lattice Endpoints

#### POST `/api/lattices`

🔒 **Requires Authentication**

Create a new Knowledge Algebra lattice.

**Request Body:**
```json
{
  "name": "string (1-255 chars)",
  "dimensions": "integer (2-10)",
  "size": "integer (1-10000)",
  "field_type": "real|complex (default: complex)",
  "geometry": "euclidean|hyperbolic|spherical (default: euclidean)",
  "enable_gpu": "boolean (default: false)"
}
```

**GPU Acceleration:**
- Lattices with `size > 1000` automatically trigger GPU if available
- GPU provides **21.22x speedup** for large operations
- Graceful CPU fallback if GPU unavailable

**Responses:**
- `201 Created`: Lattice created successfully
- `400 Bad Request`: Invalid input
- `401 Unauthorized`: Missing/invalid token
- `429 Too Many Requests`: Rate limit exceeded

---

#### GET `/api/lattices`

🔒 **Requires Authentication**

List all lattices for current tenant.

**Query Parameters:**
- `skip` (integer, default: 0): Pagination offset
- `limit` (integer, default: 100, max: 1000): Results per page

**Response (200 OK):**
```json
[
  {
    "id": "uuid",
    "name": "string",
    "dimensions": 3,
    "size": 1000,
    "created_at": "2025-10-05T20:00:00Z"
  }
]
```

---

#### GET `/api/lattices/{lattice_id}`

🔒 **Requires Authentication**

Get detailed information about a specific lattice.

**Path Parameters:**
- `lattice_id` (UUID): Lattice identifier

**Responses:**
- `200 OK`: Lattice details
- `404 Not Found`: Lattice not found or access denied

---

#### DELETE `/api/lattices/{lattice_id}`

🔒 **Requires Authentication**

Delete a lattice and free resources.

**Path Parameters:**
- `lattice_id` (UUID): Lattice identifier

**Responses:**
- `204 No Content`: Lattice deleted
- `404 Not Found`: Lattice not found

---

### Monitoring Endpoints

#### GET `/health`

Health check endpoint for monitoring.

**Response (200 OK):**
```json
{
  "status": "healthy|degraded|unhealthy",
  "timestamp": "2025-10-05T20:00:00Z",
  "components": {
    "database": {
      "status": "healthy",
      "latency_ms": 5.2
    },
    "redis": {
      "status": "healthy",
      "latency_ms": 1.8
    }
  }
}
```

---

#### GET `/metrics`

Prometheus-compatible metrics endpoint.

**Response (200 OK):**
```
# HELP http_requests_total Total HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="GET",endpoint="/api/lattices",status="200"} 1523

# HELP http_request_duration_seconds HTTP request latency
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{le="0.1"} 1234
http_request_duration_seconds_bucket{le="0.5"} 1456
http_request_duration_seconds_sum 567.8
http_request_duration_seconds_count 1500
```

---

## Error Handling

All errors follow a consistent JSON format:

```json
{
  "detail": "Human-readable error message",
  "status_code": 400,
  "type": "error_type"
}
```

### HTTP Status Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 200 | OK | Request successful |
| 201 | Created | Resource created |
| 204 | No Content | Successful deletion |
| 400 | Bad Request | Invalid input data |
| 401 | Unauthorized | Missing/invalid authentication |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Resource already exists |
| 422 | Unprocessable Entity | Validation failed |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error |

### Example Error Responses

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

## Rate Limiting

Rate limits are enforced based on subscription plan:

| Plan | Requests/Month | Lattices | Max Dimensions | Max Size |
|------|----------------|----------|----------------|----------|
| **Free** | 1,000 | 5 | 3 | 10 |
| **Pro** | 100,000 | 100 | 10 | 1,000 |
| **Enterprise** | Custom | Unlimited | Unlimited | 10,000 |

### Rate Limit Headers

All responses include rate limit information:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 847
X-RateLimit-Reset: 1696531200
```

### Exceeding Rate Limits

When rate limit is exceeded, the API returns `429 Too Many Requests`:

```json
{
  "detail": "Rate limit exceeded. Try again in 60 seconds",
  "status_code": 429,
  "type": "rate_limit_error"
}
```

---

## Examples

### Complete Workflow: Register → Create Lattice → Query

```bash
#!/bin/bash

# 1. Register tenant
REGISTER_RESPONSE=$(curl -s -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "company_name": "Example Corp",
    "email": "admin@example.com",
    "password": "SecurePass123!",
    "first_name": "Jane",
    "last_name": "Smith",
    "plan_code": "pro"
  }')

ACCESS_TOKEN=$(echo $REGISTER_RESPONSE | jq -r '.access_token')

# 2. Create lattice
LATTICE_RESPONSE=$(curl -s -X POST http://localhost:8000/api/lattices \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Analysis Lattice",
    "dimensions": 4,
    "size": 2000,
    "field_type": "complex",
    "geometry": "euclidean",
    "enable_gpu": true
  }')

LATTICE_ID=$(echo $LATTICE_RESPONSE | jq -r '.id')

# 3. Get lattice details
curl -X GET "http://localhost:8000/api/lattices/$LATTICE_ID" \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# 4. List all lattices
curl -X GET "http://localhost:8000/api/lattices" \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# 5. Logout
curl -X POST http://localhost:8000/api/auth/logout \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

---

## Interactive Documentation

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

---

## Support

- **Documentation**: https://docs.catalyticcomputing.example.com
- **API Status**: https://status.catalyticcomputing.example.com
- **Email**: support@catalyticcomputing.example.com

---

**Generated:** October 5, 2025  
**API Version:** 1.0.0  
**OpenAPI Spec:** `docs/api/openapi.yaml`
