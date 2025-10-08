"""
FastAPI Swagger UI Integration
Configures interactive API documentation with OpenAPI/Swagger
"""

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from typing import Dict, Any


def configure_openapi_docs(app: FastAPI) -> None:
    """
    Configure enhanced OpenAPI documentation for FastAPI application

    This function customizes the OpenAPI schema with additional metadata,
    examples, and descriptions for better developer experience.
    """

    def custom_openapi() -> Dict[str, Any]:
        if app.openapi_schema:
            return app.openapi_schema

        openapi_schema = get_openapi(
            title="Catalytic Computing SaaS API",
            version="1.0.0",
            description="""
# Catalytic Computing SaaS Platform API

A multi-tenant SaaS platform for advanced computational lattice operations with GPU acceleration.

## Features

- **Multi-tenant Architecture**: Complete tenant isolation with Row-Level Security (RLS)
- **JWT Authentication**: Secure token-based authentication with refresh tokens
- **Rate Limiting**: Configurable rate limits per tenant and plan
- **GPU Acceleration**: Automatic GPU utilization for large lattice operations (21.22x speedup)
- **Real-time Monitoring**: Prometheus metrics and health checks
- **Subscription Management**: Flexible subscription plans with usage tracking

## Quick Start

### 1. Register a Tenant

```bash
curl -X POST http://localhost:8000/api/auth/register \\
  -H "Content-Type: application/json" \\
  -d '{
    "company_name": "Acme Corp",
    "email": "admin@acme.com",
    "password": "SecurePass123!",
    "first_name": "John",
    "last_name": "Doe",
    "plan_code": "free"
  }'
```

### 2. Login and Get JWT Token

```bash
curl -X POST http://localhost:8000/api/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{
    "email": "admin@acme.com",
    "password": "SecurePass123!"
  }'
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

### 3. Create a Lattice

```bash
curl -X POST http://localhost:8000/api/lattices \\
  -H "Authorization: Bearer <access_token>" \\
  -H "Content-Type: application/json" \\
  -d '{
    "name": "My First Lattice",
    "dimensions": 3,
    "size": 1000,
    "field_type": "complex",
    "geometry": "euclidean",
    "enable_gpu": true
  }'
```

## Authentication

All API endpoints (except `/auth/register` and `/auth/login`) require a valid JWT access token.

Include the token in the `Authorization` header:

```
Authorization: Bearer <access_token>
```

### Token Lifecycle

1. **Access Token**: Valid for 30 minutes, used for API requests
2. **Refresh Token**: Valid for 7 days, used to get new access tokens
3. **Token Blacklist**: Logout adds token to Redis blacklist (immediate invalidation)

## Rate Limiting

Rate limits are enforced based on your subscription plan:

| Plan | Requests/Month | Lattices | Max Dimensions | Max Size |
|------|----------------|----------|----------------|----------|
| Free | 1,000 | 5 | 3 | 10 |
| Pro | 100,000 | 100 | 10 | 1,000 |
| Enterprise | Custom | Unlimited | Unlimited | 10,000 |

Rate limit headers are included in all responses:

- `X-RateLimit-Limit`: Total requests allowed
- `X-RateLimit-Remaining`: Requests remaining
- `X-RateLimit-Reset`: Unix timestamp when limit resets

## Error Handling

All errors follow a consistent format:

```json
{
  "detail": "Error message describing what went wrong",
  "status_code": 400,
  "type": "validation_error"
}
```

### Common HTTP Status Codes

- `200 OK`: Request successful
- `201 Created`: Resource created successfully
- `400 Bad Request`: Invalid request data
- `401 Unauthorized`: Missing or invalid authentication
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error

## Security

### D3FEND Compliance

This API implements MITRE D3FEND defensive techniques:

- **D3-UAC** (User Account Control): JWT authentication, password policies
- **D3-RAC** (Resource Access Control): Rate limiting, tenant isolation
- **D3-IVV** (Input Validation): Pydantic validation, SQL injection prevention
- **D3-KM** (Key Management): Token blacklist, secret rotation

### Security Headers

All responses include security headers:

- `Strict-Transport-Security`: HTTPS enforcement
- `X-Content-Type-Options: nosniff`: MIME type sniffing prevention
- `X-Frame-Options: DENY`: Clickjacking prevention
- `Content-Security-Policy`: XSS prevention

## GPU Acceleration

Large lattices (>1000 elements) automatically use GPU acceleration when available:

- **21.22x speedup** for operations on 10,000 element lattices
- **Automatic fallback** to CPU if GPU unavailable
- **Memory management** with automatic cleanup

## Monitoring

### Health Check

```bash
curl http://localhost:8000/health
```

### Prometheus Metrics

```bash
curl http://localhost:8000/metrics
```

Available metrics:
- `http_requests_total`: Total HTTP requests
- `http_request_duration_seconds`: Request latency histogram
- `lattice_creations_total`: Total lattices created
- `gpu_utilization_percent`: GPU utilization percentage
- `active_users`: Currently active users

## Support

- **Documentation**: https://docs.catalyticcomputing.example.com
- **API Status**: https://status.catalyticcomputing.example.com
- **Support Email**: support@catalyticcomputing.example.com
            """,
            routes=app.routes,
            servers=[
                {
                    "url": "http://localhost:8000",
                    "description": "Development server"
                },
                {
                    "url": "https://api.catalyticcomputing.example.com",
                    "description": "Production server"
                }
            ],
            contact={
                "name": "Catalytic Computing Support",
                "email": "support@catalyticcomputing.example.com"
            },
            license_info={
                "name": "Proprietary",
                "url": "https://catalyticcomputing.example.com/license"
            }
        )

        # Customize schema with security schemes
        openapi_schema["components"]["securitySchemes"] = {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": "JWT access token from /api/auth/login endpoint"
            }
        }

        # Add tags with descriptions
        openapi_schema["tags"] = [
            {
                "name": "authentication",
                "description": "Authentication and authorization operations",
                "externalDocs": {
                    "description": "Authentication guide",
                    "url": "https://docs.catalyticcomputing.example.com/auth"
                }
            },
            {
                "name": "tenants",
                "description": "Tenant management and registration",
                "externalDocs": {
                    "description": "Multi-tenancy guide",
                    "url": "https://docs.catalyticcomputing.example.com/tenants"
                }
            },
            {
                "name": "lattices",
                "description": "Knowledge Algebra lattice operations",
                "externalDocs": {
                    "description": "Lattice operations guide",
                    "url": "https://docs.catalyticcomputing.example.com/lattices"
                }
            },
            {
                "name": "subscriptions",
                "description": "Subscription and billing management",
                "externalDocs": {
                    "description": "Billing guide",
                    "url": "https://docs.catalyticcomputing.example.com/billing"
                }
            },
            {
                "name": "monitoring",
                "description": "Health checks, metrics, and monitoring",
                "externalDocs": {
                    "description": "Monitoring guide",
                    "url": "https://docs.catalyticcomputing.example.com/monitoring"
                }
            }
        ]

        app.openapi_schema = openapi_schema
        return app.openapi_schema

    app.openapi = custom_openapi


def setup_swagger_ui(app: FastAPI) -> None:
    """
    Configure Swagger UI and ReDoc with custom settings

    This enables interactive API documentation at:
    - /docs (Swagger UI)
    - /redoc (ReDoc)
    """

    # Swagger UI is automatically enabled by FastAPI
    # Configure with custom settings via app initialization:
    # app = FastAPI(
    #     docs_url="/docs",
    #     redoc_url="/redoc",
    #     openapi_url="/openapi.json",
    #     swagger_ui_parameters={
    #         "defaultModelsExpandDepth": -1,
    #         "deepLinking": True,
    #         "displayRequestDuration": True,
    #         "filter": True,
    #         "syntaxHighlight.theme": "monokai"
    #     }
    # )

    pass


def get_openapi_metadata() -> Dict[str, Any]:
    """Get OpenAPI metadata for external documentation tools"""

    return {
        "title": "Catalytic Computing SaaS API",
        "version": "1.0.0",
        "description": "Multi-tenant SaaS platform for computational lattice operations",
        "termsOfService": "https://catalyticcomputing.example.com/terms",
        "contact": {
            "name": "Catalytic Computing Support",
            "email": "support@catalyticcomputing.example.com",
            "url": "https://catalyticcomputing.example.com/support"
        },
        "license": {
            "name": "Proprietary",
            "url": "https://catalyticcomputing.example.com/license"
        }
    }
