# Authentication Module - Code Architecture

## Overview
The authentication module implements JWT RS256-based authentication with comprehensive security features including password policies, token blacklisting, and rate limiting.

## Class Responsibilities

### AuthController
**Location**: `api/controllers/auth_controller.py`

Handles HTTP request/response for authentication endpoints.

```python
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr

router = APIRouter(prefix="/auth", tags=["Authentication"])

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int

@router.post("/login", response_model=TokenResponse)
async def login(
    credentials: LoginRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    try:
        tokens = await auth_service.authenticate(
            credentials.email,
            credentials.password
        )
        return TokenResponse(**tokens.dict())
    except InvalidCredentialsError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
```

### AuthService
**Location**: `services/auth_service.py`

Core authentication business logic.

```python
from passlib.context import CryptContext
from datetime import datetime, timedelta

class AuthService:
    def __init__(
        self,
        user_repo: UserRepository,
        jwt_manager: JWTManager,
        cache: CacheService,
        password_policy: PasswordPolicy
    ):
        self._user_repo = user_repo
        self._jwt = jwt_manager
        self._cache = cache
        self._policy = password_policy
        self._pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    async def authenticate(self, email: str, password: str) -> TokenPair:
        # Rate limiting check
        if await self._is_rate_limited(email):
            raise RateLimitExceededError()

        user = await self._user_repo.find_by_email(email)
        if not user or not self._verify_password(password, user.password_hash):
            await self._record_failed_attempt(email)
            raise InvalidCredentialsError()

        await self._clear_failed_attempts(email)
        return self._jwt.create_token_pair(user.id, {"tenant_id": str(user.tenant_id)})

    def _verify_password(self, plain: str, hashed: str) -> bool:
        return self._pwd_context.verify(plain, hashed)

    def hash_password(self, password: str) -> str:
        self._policy.validate(password)  # Raises if invalid
        return self._pwd_context.hash(password)
```

### JWTManager
**Location**: `services/jwt_manager.py`

Handles JWT token creation and validation using RS256.

```python
import jwt
from cryptography.hazmat.primitives import serialization
from uuid import UUID
from datetime import datetime, timedelta
from typing import Optional

class JWTManager:
    def __init__(self, private_key_path: str, public_key_path: str):
        with open(private_key_path, "rb") as f:
            self._private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(public_key_path, "rb") as f:
            self._public_key = serialization.load_pem_public_key(f.read())

        self._access_ttl = 1800      # 30 minutes
        self._refresh_ttl = 604800   # 7 days
        self._algorithm = "RS256"
        self._issuer = "catalytic-platform"

    def create_access_token(self, user_id: UUID, claims: dict) -> str:
        now = datetime.utcnow()
        payload = {
            "sub": str(user_id),
            "iat": now,
            "exp": now + timedelta(seconds=self._access_ttl),
            "iss": self._issuer,
            "type": "access",
            **claims
        }
        return jwt.encode(payload, self._private_key, algorithm=self._algorithm)

    def create_refresh_token(self, user_id: UUID) -> str:
        now = datetime.utcnow()
        payload = {
            "sub": str(user_id),
            "iat": now,
            "exp": now + timedelta(seconds=self._refresh_ttl),
            "iss": self._issuer,
            "type": "refresh"
        }
        return jwt.encode(payload, self._private_key, algorithm=self._algorithm)

    def verify_token(self, token: str) -> TokenPayload:
        try:
            payload = jwt.decode(
                token,
                self._public_key,
                algorithms=[self._algorithm],
                issuer=self._issuer
            )
            return TokenPayload(**payload)
        except jwt.ExpiredSignatureError:
            raise TokenExpiredError()
        except jwt.InvalidTokenError as e:
            raise InvalidTokenError(str(e))
```

### PasswordPolicy
**Location**: `services/password_policy.py`

Enforces strong password requirements (D3FEND D3-SPP).

```python
import re
from dataclasses import dataclass
from typing import List

@dataclass
class ValidationResult:
    is_valid: bool
    errors: List[str]

class PasswordPolicy:
    MIN_LENGTH = 12
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_DIGIT = True
    REQUIRE_SPECIAL = True
    SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    # Common passwords list (loaded from file)
    _common_passwords: set = None

    def validate(self, password: str) -> ValidationResult:
        errors = []

        if len(password) < self.MIN_LENGTH:
            errors.append(f"Password must be at least {self.MIN_LENGTH} characters")

        if self.REQUIRE_UPPERCASE and not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter")

        if self.REQUIRE_LOWERCASE and not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter")

        if self.REQUIRE_DIGIT and not re.search(r"\d", password):
            errors.append("Password must contain at least one digit")

        if self.REQUIRE_SPECIAL and not any(c in self.SPECIAL_CHARS for c in password):
            errors.append("Password must contain at least one special character")

        if self._is_common_password(password):
            errors.append("Password is too common")

        if errors:
            raise PasswordPolicyViolation(errors)

        return ValidationResult(is_valid=True, errors=[])

    def _is_common_password(self, password: str) -> bool:
        if self._common_passwords is None:
            self._load_common_passwords()
        return password.lower() in self._common_passwords
```

### TokenBlacklist
**Location**: `services/token_blacklist.py`

Manages invalidated tokens in Redis (D3FEND D3-SE).

```python
from redis import Redis
from datetime import datetime
import hashlib

class TokenBlacklist:
    PREFIX = "blacklist:"

    def __init__(self, redis: Redis):
        self._redis = redis

    def add(self, token: str, expiry: datetime) -> None:
        """Add token to blacklist with TTL matching token expiry."""
        token_hash = self._hash_token(token)
        ttl = int((expiry - datetime.utcnow()).total_seconds())
        if ttl > 0:
            self._redis.setex(f"{self.PREFIX}{token_hash}", ttl, "1")

    def is_blacklisted(self, token: str) -> bool:
        """Check if token has been invalidated."""
        token_hash = self._hash_token(token)
        return self._redis.exists(f"{self.PREFIX}{token_hash}") > 0

    def _hash_token(self, token: str) -> str:
        """Hash token for storage (don't store raw tokens)."""
        return hashlib.sha256(token.encode()).hexdigest()[:32]
```

### JWTMiddleware
**Location**: `middleware/jwt_middleware.py`

FastAPI middleware for authentication.

```python
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from typing import Optional

class JWTMiddleware(BaseHTTPMiddleware):
    EXEMPT_PATHS = {"/auth/login", "/auth/register", "/health", "/docs", "/openapi.json"}

    def __init__(self, app, auth_service: AuthService, blacklist: TokenBlacklist):
        super().__init__(app)
        self._auth = auth_service
        self._blacklist = blacklist

    async def dispatch(self, request: Request, call_next):
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        token = self._extract_token(request)
        if not token:
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing authentication token"}
            )

        if self._blacklist.is_blacklisted(token):
            return JSONResponse(
                status_code=401,
                content={"detail": "Token has been revoked"}
            )

        try:
            payload = self._auth._jwt.verify_token(token)
            request.state.user_id = payload.sub
            request.state.tenant_id = payload.tenant_id
        except (TokenExpiredError, InvalidTokenError) as e:
            return JSONResponse(
                status_code=401,
                content={"detail": str(e)}
            )

        return await call_next(request)

    def _extract_token(self, request: Request) -> Optional[str]:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:]
        return None
```

## Security Measures

| Measure | Implementation | D3FEND |
|---------|---------------|--------|
| Strong passwords | 12+ chars, complexity | D3-SPP |
| Account lockout | 5 failures → 15min | D3-AL |
| Session expiration | JWT 30min TTL | D3-SE |
| Token blacklist | Redis with TTL | D3-SE |
| Asymmetric signing | RS256 (2048-bit) | D3-CA |
| Rate limiting | Sliding window | D3-NTA |

## Dependencies

```
┌──────────────┐
│AuthController│
└──────┬───────┘
       │
       ▼
┌──────────────┐    ┌────────────────┐
│ AuthService  │───►│ PasswordPolicy │
└──────┬───────┘    └────────────────┘
       │
       ├───────────────┐
       ▼               ▼
┌──────────────┐ ┌────────────────┐
│  JWTManager  │ │ TokenBlacklist │
└──────────────┘ └────────────────┘
       │               │
       └───────┬───────┘
               ▼
        ┌──────────────┐
        │ CacheService │
        │   (Redis)    │
        └──────────────┘
```

---
**Last Updated**: 2024-10-15
