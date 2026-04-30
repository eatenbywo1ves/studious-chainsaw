# Cross-Cutting Concerns: Error Handling

## Overview
Consistent error handling across all services ensures predictable client behavior and effective debugging.

## Error Response Format

### Standard Error Response
```json
{
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "The requested resource was not found",
    "details": {
      "resource_type": "job",
      "resource_id": "job_abc123"
    }
  },
  "request_id": "req_xyz789",
  "timestamp": "2024-10-15T10:30:00Z",
  "documentation_url": "https://docs.catalytic.dev/errors#RESOURCE_NOT_FOUND"
}
```

### Error Codes

#### Authentication Errors (AUTH_*)
| Code | HTTP Status | Description |
|------|-------------|-------------|
| AUTH_001 | 401 | Invalid credentials |
| AUTH_002 | 401 | Token expired |
| AUTH_003 | 401 | Token invalid |
| AUTH_004 | 401 | Token revoked |
| AUTH_005 | 403 | Insufficient permissions |
| AUTH_006 | 429 | Account locked |

#### Resource Errors (RES_*)
| Code | HTTP Status | Description |
|------|-------------|-------------|
| RES_001 | 404 | Resource not found |
| RES_002 | 409 | Resource already exists |
| RES_003 | 410 | Resource deleted |
| RES_004 | 423 | Resource locked |

#### Validation Errors (VAL_*)
| Code | HTTP Status | Description |
|------|-------------|-------------|
| VAL_001 | 400 | Invalid request format |
| VAL_002 | 400 | Missing required field |
| VAL_003 | 400 | Field value out of range |
| VAL_004 | 400 | Invalid field format |
| VAL_005 | 422 | Business rule violation |

#### Rate Limiting Errors (RATE_*)
| Code | HTTP Status | Description |
|------|-------------|-------------|
| RATE_001 | 429 | Too many requests |
| RATE_002 | 429 | Quota exceeded |

#### Server Errors (SRV_*)
| Code | HTTP Status | Description |
|------|-------------|-------------|
| SRV_001 | 500 | Internal server error |
| SRV_002 | 503 | Service unavailable |
| SRV_003 | 504 | Upstream timeout |

## Exception Hierarchy

```python
class CatalyticException(Exception):
    """Base exception for all platform errors."""
    def __init__(self, code: str, message: str, details: dict = None):
        self.code = code
        self.message = message
        self.details = details or {}
        super().__init__(message)

class AuthenticationError(CatalyticException):
    """Authentication-related errors."""
    pass

class AuthorizationError(CatalyticException):
    """Authorization-related errors."""
    pass

class ResourceNotFoundError(CatalyticException):
    """Resource not found errors."""
    pass

class ValidationError(CatalyticException):
    """Input validation errors."""
    pass

class RateLimitError(CatalyticException):
    """Rate limiting errors."""
    pass

class ServiceError(CatalyticException):
    """Internal service errors."""
    pass
```

## Error Handling Middleware

```python
from fastapi import Request
from fastapi.responses import JSONResponse
import structlog

logger = structlog.get_logger()

async def error_handler(request: Request, call_next):
    try:
        return await call_next(request)
    except CatalyticException as e:
        logger.warning(
            "handled_error",
            error_code=e.code,
            error_message=e.message,
            request_id=request.state.request_id
        )
        return JSONResponse(
            status_code=get_status_code(e.code),
            content={
                "error": {
                    "code": e.code,
                    "message": e.message,
                    "details": e.details
                },
                "request_id": request.state.request_id,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
    except Exception as e:
        logger.exception(
            "unhandled_error",
            error=str(e),
            request_id=request.state.request_id
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "SRV_001",
                    "message": "An internal error occurred"
                },
                "request_id": request.state.request_id,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
```

## Circuit Breaker Pattern

```python
from tenacity import retry, stop_after_attempt, wait_exponential
import pybreaker

# Circuit breaker for external services
external_breaker = pybreaker.CircuitBreaker(
    fail_max=5,
    reset_timeout=60
)

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10)
)
@external_breaker
async def call_external_service(data):
    """Call external service with retry and circuit breaker."""
    try:
        return await client.post("/api", json=data)
    except HTTPError as e:
        if e.response.status_code >= 500:
            raise  # Trigger retry
        raise ExternalServiceError(str(e))
```

### Circuit Breaker States
```
┌─────────────────────────────────────────────────────────────────┐
│                    Circuit Breaker States                        │
│                                                                  │
│  ┌──────────┐     failures >= 5     ┌──────────┐               │
│  │  CLOSED  │──────────────────────►│   OPEN   │               │
│  │ (normal) │                       │ (failing)│               │
│  └────┬─────┘                       └────┬─────┘               │
│       │                                  │                      │
│       │                            timeout (60s)                │
│       │                                  │                      │
│       │     success                      ▼                      │
│       │◄────────────────────────┌────────────────┐             │
│       │                         │   HALF-OPEN    │             │
│       │                         │  (testing)     │             │
│       │                         └────────┬───────┘             │
│       │                                  │                      │
│       │                             failure                     │
│       │                                  │                      │
│       │                                  ▼                      │
│       │                           Back to OPEN                  │
└───────┴─────────────────────────────────────────────────────────┘
```

## Validation Error Details

```python
from pydantic import ValidationError

def format_validation_errors(exc: ValidationError) -> dict:
    """Format Pydantic validation errors for API response."""
    errors = []
    for error in exc.errors():
        errors.append({
            "field": ".".join(str(loc) for loc in error["loc"]),
            "message": error["msg"],
            "type": error["type"]
        })

    return {
        "error": {
            "code": "VAL_001",
            "message": "Validation failed",
            "details": {
                "errors": errors
            }
        }
    }
```

### Validation Error Response Example
```json
{
  "error": {
    "code": "VAL_001",
    "message": "Validation failed",
    "details": {
      "errors": [
        {
          "field": "email",
          "message": "value is not a valid email address",
          "type": "value_error.email"
        },
        {
          "field": "password",
          "message": "ensure this value has at least 12 characters",
          "type": "value_error.any_str.min_length"
        }
      ]
    }
  },
  "request_id": "req_abc123",
  "timestamp": "2024-10-15T10:30:00Z"
}
```

## Error Logging Strategy

| Error Type | Log Level | Include Stack | Alert |
|------------|-----------|---------------|-------|
| Validation | WARN | No | No |
| Auth failure | WARN | No | Threshold |
| Not found | INFO | No | No |
| Rate limit | WARN | No | Threshold |
| Service error | ERROR | Yes | Yes |
| Unhandled | ERROR | Yes | Yes |

---
**Last Updated**: 2024-10-15
