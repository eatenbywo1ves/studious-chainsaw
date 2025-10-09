#!/usr/bin/env python3
"""
OpenAPI Specification Generator for Catalytic Computing SaaS API
Generates comprehensive OpenAPI 3.0 specification with all endpoints documented
"""

import json
import yaml
from typing import Dict, Any


def generate_openapi_spec() -> Dict[str, Any]:
    """Generate complete OpenAPI 3.0 specification"""

    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": "Catalytic Computing SaaS API",
            "description": """
# Catalytic Computing SaaS Platform API

A multi-tenant SaaS platform for advanced computational lattice operations with GPU acceleration.

## Features

- **Multi-tenant Architecture**: Complete tenant isolation with Row-Level Security (RLS)
- **JWT Authentication**: Secure token-based authentication with refresh tokens
- **Rate Limiting**: Configurable rate limits per tenant and plan
- **GPU Acceleration**: Automatic GPU utilization for large lattice operations
- **Real-time Monitoring**: Prometheus metrics and health checks
- **Subscription Management**: Flexible subscription plans with usage tracking

## Authentication

All API endpoints (except `/auth/register` and `/auth/login`) require a valid JWT access token.

Include the token in the `Authorization` header:

```
Authorization: Bearer <access_token>
```

## Rate Limiting

Rate limits are enforced based on your subscription plan:

- **Free Tier**: 1,000 requests/month
- **Pro Tier**: 100,000 requests/month
- **Enterprise**: Custom limits

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

Common HTTP status codes:

- `200 OK`: Request successful
- `201 Created`: Resource created successfully
- `400 Bad Request`: Invalid request data
- `401 Unauthorized`: Missing or invalid authentication
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error
            """,
            "version": "1.0.0",
            "contact": {
                "name": "Catalytic Computing Support",
                "email": "support@catalyticcomputing.example.com",
            },
            "license": {
                "name": "Proprietary",
                "url": "https://catalyticcomputing.example.com/license",
            },
        },
        "servers": [
            {"url": "http://localhost:8000", "description": "Development server"},
            {
                "url": "https://api.catalyticcomputing.example.com",
                "description": "Production server",
            },
        ],
        "tags": [
            {
                "name": "authentication",
                "description": "Authentication and authorization operations",
            },
            {"name": "tenants", "description": "Tenant management and registration"},
            {"name": "users", "description": "User management within tenants"},
            {"name": "lattices", "description": "KA Lattice creation and operations"},
            {"name": "subscriptions", "description": "Subscription and billing management"},
            {"name": "monitoring", "description": "Health checks and metrics"},
        ],
        "paths": generate_paths(),
        "components": generate_components(),
    }

    return spec


def generate_paths() -> Dict[str, Any]:
    """Generate all API endpoint definitions"""

    return {
        # ====================================================================
        # AUTHENTICATION ENDPOINTS
        # ====================================================================
        "/api/auth/register": {
            "post": {
                "tags": ["authentication"],
                "summary": "Register new tenant",
                "description": "Register a new tenant account with admin user",
                "operationId": "registerTenant",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/TenantRegistration"},
                            "example": {
                                "company_name": "Acme Corporation",
                                "email": "admin@acme.com",
                                "password": "SecurePassword123!",
                                "first_name": "John",
                                "last_name": "Doe",
                                "domain": "acme.com",
                                "plan_code": "free",
                            },
                        }
                    },
                },
                "responses": {
                    "201": {
                        "description": "Tenant registered successfully",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/RegistrationResponse"}
                            }
                        },
                    },
                    "400": {"$ref": "#/components/responses/BadRequest"},
                    "409": {"description": "Tenant already exists"},
                },
            }
        },
        "/api/auth/login": {
            "post": {
                "tags": ["authentication"],
                "summary": "Login and get JWT tokens",
                "description": "Authenticate user and receive access + refresh tokens",
                "operationId": "login",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/LoginRequest"},
                            "example": {
                                "email": "admin@acme.com",
                                "password": "SecurePassword123!",
                            },
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Login successful",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/LoginResponse"}
                            }
                        },
                    },
                    "401": {"description": "Invalid credentials"},
                },
            }
        },
        "/api/auth/verify": {
            "post": {
                "tags": ["authentication"],
                "summary": "Verify JWT token",
                "description": "Verify a JWT token and return decoded payload",
                "operationId": "verifyToken",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/TokenVerifyRequest"}
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Token is valid",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/TokenVerifyResponse"}
                            }
                        },
                    },
                    "401": {"description": "Token is invalid or expired"},
                },
            }
        },
        "/api/auth/refresh": {
            "post": {
                "tags": ["authentication"],
                "summary": "Refresh access token",
                "description": "Get new access token using refresh token",
                "operationId": "refreshToken",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {"refresh_token": {"type": "string"}},
                                "required": ["refresh_token"],
                            }
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Token refreshed",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "access_token": {"type": "string"},
                                        "token_type": {"type": "string", "example": "bearer"},
                                    },
                                }
                            }
                        },
                    },
                    "401": {"description": "Invalid refresh token"},
                },
            }
        },
        "/api/auth/logout": {
            "post": {
                "tags": ["authentication"],
                "summary": "Logout and blacklist token",
                "description": "Logout user and add token to blacklist",
                "operationId": "logout",
                "security": [{"bearerAuth": []}],
                "responses": {
                    "200": {"description": "Logged out successfully"},
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                },
            }
        },
        # ====================================================================
        # LATTICE ENDPOINTS
        # ====================================================================
        "/api/lattices": {
            "post": {
                "tags": ["lattices"],
                "summary": "Create new KA lattice",
                "description": "Create a new Knowledge Algebra lattice with specified dimensions",
                "operationId": "createLattice",
                "security": [{"bearerAuth": []}],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/LatticeCreate"},
                            "example": {
                                "name": "My Lattice",
                                "dimensions": 3,
                                "size": 1000,
                                "field_type": "complex",
                                "geometry": "euclidean",
                                "enable_gpu": True,
                            },
                        }
                    },
                },
                "responses": {
                    "201": {
                        "description": "Lattice created",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/LatticeResponse"}
                            }
                        },
                    },
                    "400": {"$ref": "#/components/responses/BadRequest"},
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "429": {"$ref": "#/components/responses/RateLimitExceeded"},
                },
            },
            "get": {
                "tags": ["lattices"],
                "summary": "List tenant lattices",
                "description": "Get all lattices for current tenant",
                "operationId": "listLattices",
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {"name": "skip", "in": "query", "schema": {"type": "integer", "default": 0}},
                    {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 100}},
                ],
                "responses": {
                    "200": {
                        "description": "List of lattices",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/LatticeResponse"},
                                }
                            }
                        },
                    },
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                },
            },
        },
        "/api/lattices/{lattice_id}": {
            "get": {
                "tags": ["lattices"],
                "summary": "Get lattice details",
                "description": "Get detailed information about a specific lattice",
                "operationId": "getLattice",
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {
                        "name": "lattice_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string", "format": "uuid"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Lattice details",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/LatticeResponse"}
                            }
                        },
                    },
                    "404": {"$ref": "#/components/responses/NotFound"},
                },
            },
            "delete": {
                "tags": ["lattices"],
                "summary": "Delete lattice",
                "description": "Delete a lattice and free resources",
                "operationId": "deleteLattice",
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {
                        "name": "lattice_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string", "format": "uuid"},
                    }
                ],
                "responses": {
                    "204": {"description": "Lattice deleted"},
                    "404": {"$ref": "#/components/responses/NotFound"},
                },
            },
        },
        # ====================================================================
        # MONITORING ENDPOINTS
        # ====================================================================
        "/health": {
            "get": {
                "tags": ["monitoring"],
                "summary": "Health check",
                "description": "Check API health and component status",
                "operationId": "healthCheck",
                "responses": {
                    "200": {
                        "description": "Service is healthy",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/HealthResponse"}
                            }
                        },
                    }
                },
            }
        },
        "/metrics": {
            "get": {
                "tags": ["monitoring"],
                "summary": "Prometheus metrics",
                "description": "Get Prometheus-compatible metrics",
                "operationId": "getMetrics",
                "responses": {
                    "200": {
                        "description": "Metrics in Prometheus format",
                        "content": {"text/plain": {"schema": {"type": "string"}}},
                    }
                },
            }
        },
    }


def generate_components() -> Dict[str, Any]:
    """Generate reusable component schemas"""

    return {
        "securitySchemes": {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": "JWT access token from /api/auth/login",
            }
        },
        "schemas": {
            # Authentication schemas
            "TenantRegistration": {
                "type": "object",
                "required": ["company_name", "email", "password", "first_name", "last_name"],
                "properties": {
                    "company_name": {"type": "string", "minLength": 2, "maxLength": 255},
                    "email": {"type": "string", "format": "email"},
                    "password": {
                        "type": "string",
                        "minLength": 8,
                        "description": "Must contain uppercase, lowercase, and digit",
                    },
                    "first_name": {"type": "string", "minLength": 1, "maxLength": 100},
                    "last_name": {"type": "string", "minLength": 1, "maxLength": 100},
                    "domain": {"type": "string", "nullable": True},
                    "plan_code": {
                        "type": "string",
                        "default": "free",
                        "enum": ["free", "pro", "enterprise"],
                    },
                },
            },
            "RegistrationResponse": {
                "type": "object",
                "properties": {
                    "tenant_id": {"type": "string", "format": "uuid"},
                    "user_id": {"type": "string", "format": "uuid"},
                    "access_token": {"type": "string"},
                    "refresh_token": {"type": "string"},
                    "token_type": {"type": "string", "example": "bearer"},
                },
            },
            "LoginRequest": {
                "type": "object",
                "required": ["email", "password"],
                "properties": {
                    "email": {"type": "string", "format": "email"},
                    "password": {"type": "string"},
                },
            },
            "LoginResponse": {
                "type": "object",
                "properties": {
                    "access_token": {"type": "string"},
                    "refresh_token": {"type": "string"},
                    "token_type": {"type": "string", "example": "bearer"},
                    "expires_in": {"type": "integer", "description": "Seconds until expiration"},
                },
            },
            "TokenVerifyRequest": {
                "type": "object",
                "required": ["token"],
                "properties": {
                    "token": {"type": "string"},
                    "token_type": {"type": "string", "default": "access"},
                },
            },
            "TokenVerifyResponse": {
                "type": "object",
                "properties": {
                    "sub": {"type": "string"},
                    "tenant_id": {"type": "string"},
                    "email": {"type": "string"},
                    "role": {"type": "string"},
                    "type": {"type": "string"},
                    "jti": {"type": "string", "nullable": True},
                    "iat": {"type": "integer", "nullable": True},
                    "exp": {"type": "integer", "nullable": True},
                },
            },
            # Lattice schemas
            "LatticeCreate": {
                "type": "object",
                "required": ["name", "dimensions", "size"],
                "properties": {
                    "name": {"type": "string", "minLength": 1, "maxLength": 255},
                    "dimensions": {"type": "integer", "minimum": 2, "maximum": 10},
                    "size": {"type": "integer", "minimum": 1, "maximum": 10000},
                    "field_type": {
                        "type": "string",
                        "enum": ["real", "complex"],
                        "default": "complex",
                    },
                    "geometry": {
                        "type": "string",
                        "enum": ["euclidean", "hyperbolic", "spherical"],
                        "default": "euclidean",
                    },
                    "enable_gpu": {"type": "boolean", "default": False},
                },
            },
            "LatticeResponse": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "format": "uuid"},
                    "name": {"type": "string"},
                    "dimensions": {"type": "integer"},
                    "size": {"type": "integer"},
                    "field_type": {"type": "string"},
                    "geometry": {"type": "string"},
                    "owner_id": {"type": "string", "format": "uuid"},
                    "created_at": {"type": "string", "format": "date-time"},
                    "updated_at": {"type": "string", "format": "date-time"},
                    "processing_info": {
                        "type": "object",
                        "nullable": True,
                        "properties": {
                            "gpu_used": {"type": "boolean"},
                            "processing_time_ms": {"type": "number"},
                        },
                    },
                },
            },
            # Monitoring schemas
            "HealthResponse": {
                "type": "object",
                "properties": {
                    "status": {"type": "string", "enum": ["healthy", "degraded", "unhealthy"]},
                    "timestamp": {"type": "string", "format": "date-time"},
                    "components": {
                        "type": "object",
                        "properties": {
                            "database": {
                                "type": "object",
                                "properties": {
                                    "status": {"type": "string"},
                                    "latency_ms": {"type": "number"},
                                },
                            },
                            "redis": {
                                "type": "object",
                                "properties": {
                                    "status": {"type": "string"},
                                    "latency_ms": {"type": "number"},
                                },
                            },
                        },
                    },
                },
            },
            # Error schemas
            "Error": {
                "type": "object",
                "properties": {
                    "detail": {"type": "string"},
                    "status_code": {"type": "integer"},
                    "type": {"type": "string"},
                },
            },
        },
        "responses": {
            "BadRequest": {
                "description": "Bad request - invalid input",
                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
            },
            "Unauthorized": {
                "description": "Unauthorized - missing or invalid authentication",
                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
            },
            "NotFound": {
                "description": "Resource not found",
                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
            },
            "RateLimitExceeded": {
                "description": "Rate limit exceeded",
                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
            },
        },
    }


def main():
    """Generate and save OpenAPI specification"""
    spec = generate_openapi_spec()

    # Save as YAML
    with open("openapi.yaml", "w") as f:
        yaml.dump(spec, f, default_flow_style=False, sort_keys=False)
    print("✓ Generated openapi.yaml")

    # Save as JSON
    with open("openapi.json", "w") as f:
        json.dump(spec, f, indent=2)
    print("✓ Generated openapi.json")

    print("\nOpenAPI specification generated successfully!")
    print("View with Swagger UI: https://editor.swagger.io/")


if __name__ == "__main__":
    main()
