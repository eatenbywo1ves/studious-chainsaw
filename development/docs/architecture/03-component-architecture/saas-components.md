# SaaS Platform - Component Architecture

## Overview
The SaaS Platform API is structured using a layered architecture with clear separation between controllers, services, and repositories.

## Component Layers

### 1. Controller Layer (API Endpoints)

#### Auth Controller
**Path**: `/api/v1/auth`
```
POST /login          - User authentication
POST /register       - New user registration
POST /refresh        - Token refresh
POST /logout         - Token invalidation
POST /forgot         - Password reset request
POST /reset          - Password reset execution
```

#### User Controller
**Path**: `/api/v1/users`
```
GET  /me             - Current user profile
PUT  /me             - Update profile
GET  /me/usage       - Usage statistics
GET  /me/api-keys    - List API keys
POST /me/api-keys    - Create API key
```

#### Subscription Controller
**Path**: `/api/v1/subscriptions`
```
GET  /               - Current subscription
POST /checkout       - Create checkout session
POST /portal         - Customer portal link
GET  /invoices       - Invoice history
```

#### Analysis Controller
**Path**: `/api/v1/analysis`
```
POST /submit         - Submit binary for analysis
GET  /{job_id}       - Job status
GET  /{job_id}/result - Analysis results
DELETE /{job_id}     - Cancel job
```

### 2. Service Layer (Business Logic)

#### Auth Service
**Responsibilities**:
- JWT token generation (RS256)
- Password hashing (bcrypt, cost=12)
- Token blacklist management
- Session tracking

**Key Methods**:
```python
class AuthService:
    def authenticate(email: str, password: str) -> TokenPair
    def refresh_token(refresh_token: str) -> TokenPair
    def invalidate_token(token: str) -> None
    def verify_password(plain: str, hashed: str) -> bool
```

#### User Service
**Responsibilities**:
- User CRUD operations
- Profile validation
- Usage quota enforcement
- RLS context management

**Key Methods**:
```python
class UserService:
    def get_current_user(token: str) -> User
    def update_profile(user_id: UUID, data: UserUpdate) -> User
    def check_quota(user_id: UUID, resource: str) -> bool
    def set_tenant_context(tenant_id: UUID) -> None
```

#### Billing Service
**Responsibilities**:
- Stripe API integration
- Subscription lifecycle
- Invoice management
- Usage-based billing

**Key Methods**:
```python
class BillingService:
    def create_checkout_session(user_id: UUID, price_id: str) -> str
    def handle_webhook(payload: bytes, signature: str) -> None
    def get_subscription(user_id: UUID) -> Subscription
    def record_usage(user_id: UUID, quantity: int) -> None
```

#### Cache Service
**Responsibilities**:
- Redis connection management
- Cache key generation
- TTL management
- Cache invalidation

**Key Methods**:
```python
class CacheService:
    def get(key: str) -> Optional[bytes]
    def set(key: str, value: bytes, ttl: int) -> None
    def delete(key: str) -> None
    def rate_limit_check(key: str, limit: int, window: int) -> bool
```

### 3. Repository Layer (Data Access)

#### User Repository
```python
class UserRepository:
    def find_by_email(email: str) -> Optional[User]
    def find_by_id(user_id: UUID) -> Optional[User]
    def create(data: UserCreate) -> User
    def update(user_id: UUID, data: UserUpdate) -> User
    def delete(user_id: UUID) -> None
```

#### Subscription Repository
```python
class SubscriptionRepository:
    def find_by_user(user_id: UUID) -> Optional[Subscription]
    def find_by_stripe_id(stripe_id: str) -> Optional[Subscription]
    def create(data: SubscriptionCreate) -> Subscription
    def update_status(sub_id: UUID, status: str) -> Subscription
```

### 4. Middleware Layer

#### JWT Middleware
- Extracts Bearer token from Authorization header
- Validates token signature (RS256)
- Checks token blacklist
- Populates request state with user context

#### RLS Middleware
- Extracts tenant_id from authenticated user
- Sets PostgreSQL session variable: `SET app.tenant_id = ?`
- Ensures all queries are tenant-scoped

#### Rate Limiter
- Sliding window algorithm (Redis ZSET)
- Per-endpoint configuration
- Returns 429 with Retry-After header

## Component Dependencies

```
┌─────────────────────────────────────────────────────────┐
│                    Controller Layer                      │
│  ┌─────────┐ ┌──────────┐ ┌──────────────┐ ┌─────────┐ │
│  │  Auth   │ │   User   │ │ Subscription │ │Analysis │ │
│  └────┬────┘ └────┬─────┘ └──────┬───────┘ └────┬────┘ │
└───────┼───────────┼──────────────┼──────────────┼──────┘
        │           │              │              │
┌───────▼───────────▼──────────────▼──────────────▼──────┐
│                     Service Layer                       │
│  ┌─────────┐ ┌──────────┐ ┌─────────┐ ┌─────────────┐  │
│  │  Auth   │ │   User   │ │ Billing │ │   Analysis  │  │
│  │ Service │ │ Service  │ │ Service │ │   Service   │  │
│  └────┬────┘ └────┬─────┘ └────┬────┘ └──────┬──────┘  │
│       │           │            │             │          │
│       └─────┬─────┴────────────┴─────────────┘          │
│             │                                           │
│       ┌─────▼─────┐                                     │
│       │   Cache   │                                     │
│       │  Service  │                                     │
│       └───────────┘                                     │
└─────────────────────────────────────────────────────────┘
        │           │              │
┌───────▼───────────▼──────────────▼─────────────────────┐
│                   Repository Layer                      │
│  ┌──────────────┐ ┌────────────────────┐ ┌──────────┐  │
│  │     User     │ │    Subscription    │ │   Job    │  │
│  │  Repository  │ │    Repository      │ │Repository│  │
│  └──────────────┘ └────────────────────┘ └──────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Security Boundaries

| Layer | Security Measure |
|-------|------------------|
| Controller | Input validation, request sanitization |
| Middleware | Authentication, authorization, rate limiting |
| Service | Business rule enforcement, quota checks |
| Repository | RLS enforcement, parameterized queries |

## Error Handling

All components follow a consistent error pattern:
```python
class ServiceException(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        self.code = code
        self.message = message
        self.status = status

# Usage
raise ServiceException("AUTH_001", "Invalid credentials", 401)
```

---
**Last Updated**: 2024-10-15
