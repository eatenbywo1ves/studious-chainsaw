"""
Authentication and Authorization System
Provides JWT tokens, API keys, role-based access control, and session management
"""

import jwt
import secrets
import logging
from typing import Dict, List, Optional, Any, Set, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
import bcrypt
from abc import ABC, abstractmethod


class AuthMethod(Enum):
    """Authentication methods"""

    API_KEY = "api_key"
    JWT_TOKEN = "jwt_token"
    BASIC_AUTH = "basic_auth"
    OAUTH2 = "oauth2"


class UserRole(Enum):
    """User roles for RBAC"""

    GUEST = "guest"
    USER = "user"
    ADMIN = "admin"
    SERVICE = "service"
    SYSTEM = "system"


class Permission(Enum):
    """Permissions for fine-grained access control"""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    ADMIN = "admin"

    # Service-specific permissions
    MCP_ACCESS = "mcp_access"
    AGENT_ACCESS = "agent_access"
    GATEWAY_ADMIN = "gateway_admin"
    METRICS_READ = "metrics_read"
    LOGS_READ = "logs_read"


@dataclass
class User:
    """User entity"""

    id: str
    username: str
    email: str
    password_hash: Optional[str] = None
    roles: Set[UserRole] = field(default_factory=set)
    permissions: Set[Permission] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    last_login: Optional[datetime] = None
    is_active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data["roles"] = [role.value for role in self.roles]
        data["permissions"] = [perm.value for perm in self.permissions]
        data["created_at"] = self.created_at.isoformat()
        if self.last_login:
            data["last_login"] = self.last_login.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "User":
        """Create from dictionary"""
        data = data.copy()
        data["roles"] = {UserRole(role) for role in data.get("roles", [])}
        data["permissions"] = {Permission(perm) for perm in data.get("permissions", [])}
        if data.get("created_at"):
            data["created_at"] = datetime.fromisoformat(data["created_at"])
        if data.get("last_login"):
            data["last_login"] = datetime.fromisoformat(data["last_login"])
        return cls(**data)


@dataclass
class APIKey:
    """API Key entity"""

    key: str
    name: str
    user_id: str
    permissions: Set[Permission] = field(default_factory=set)
    expires_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.now)
    last_used: Optional[datetime] = None
    is_active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if API key is expired"""
        if self.expires_at:
            return datetime.now() > self.expires_at
        return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data["permissions"] = [perm.value for perm in self.permissions]
        data["created_at"] = self.created_at.isoformat()
        if self.expires_at:
            data["expires_at"] = self.expires_at.isoformat()
        if self.last_used:
            data["last_used"] = self.last_used.isoformat()
        return data


@dataclass
class JWTToken:
    """JWT Token payload"""

    user_id: str
    username: str
    roles: List[str]
    permissions: List[str]
    issued_at: datetime
    expires_at: datetime
    token_id: str = field(default_factory=lambda: secrets.token_hex(16))

    def to_payload(self) -> Dict[str, Any]:
        """Convert to JWT payload"""
        return {
            "user_id": self.user_id,
            "username": self.username,
            "roles": self.roles,
            "permissions": self.permissions,
            "iat": int(self.issued_at.timestamp()),
            "exp": int(self.expires_at.timestamp()),
            "jti": self.token_id,
        }


@dataclass
class AuthConfig:
    """Authentication configuration"""

    jwt_secret: str = field(default_factory=lambda: secrets.token_hex(32))
    jwt_algorithm: str = "HS256"
    jwt_expiry_hours: int = 24
    api_key_expiry_days: int = 365
    password_min_length: int = 8
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 15
    session_timeout_hours: int = 8
    require_email_verification: bool = False


class AuthenticationProvider(ABC):
    """Abstract authentication provider"""

    @abstractmethod
    async def authenticate(self, credentials: Dict[str, Any]) -> Optional[User]:
        """Authenticate user with credentials"""

    @abstractmethod
    async def validate_token(self, token: str) -> Optional[User]:
        """Validate authentication token"""


class DatabaseAuthProvider(AuthenticationProvider):
    """Database-backed authentication provider"""

    def __init__(self, user_store: Dict[str, User]):
        self.user_store = user_store

    async def authenticate(self, credentials: Dict[str, Any]) -> Optional[User]:
        """Authenticate with username/password"""
        username = credentials.get("username")
        password = credentials.get("password")

        if not username or not password:
            return None

        # Find user
        user = None
        for u in self.user_store.values():
            if u.username == username and u.is_active:
                user = u
                break

        if not user or not user.password_hash:
            return None

        # Verify password
        if bcrypt.checkpw(password.encode("utf-8"), user.password_hash.encode("utf-8")):
            user.last_login = datetime.now()
            return user

        return None

    async def validate_token(self, token: str) -> Optional[User]:
        """Validate JWT token"""
        # This would be implemented by the JWT manager
        return None


class AuthenticationManager:
    """Central authentication manager"""

    def __init__(self, config: Optional[AuthConfig] = None):
        self.config = config or AuthConfig()
        self.logger = self._setup_logging()

        # Storage
        self.users: Dict[str, User] = {}
        self.api_keys: Dict[str, APIKey] = {}
        self.revoked_tokens: Set[str] = set()

        # Authentication providers
        self.providers: Dict[AuthMethod, AuthenticationProvider] = {}
        self.providers[AuthMethod.BASIC_AUTH] = DatabaseAuthProvider(self.users)

        # Rate limiting for failed attempts
        self.failed_attempts: Dict[str, List[datetime]] = {}

        # Role-based permissions
        self._setup_default_roles()

    def _setup_logging(self) -> logging.Logger:
        """Setup structured logging"""
        logger = logging.getLogger("AuthenticationManager")
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '{"timestamp": "%(asctime)s", "component": "AuthenticationManager", '
                '"level": "%(levelname)s", "message": "%(message)s"}'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def _setup_default_roles(self):
        """Setup default role permissions"""
        self.role_permissions = {
            UserRole.GUEST: {Permission.READ},
            UserRole.USER: {Permission.READ, Permission.WRITE, Permission.MCP_ACCESS},
            UserRole.ADMIN: {
                Permission.READ,
                Permission.WRITE,
                Permission.DELETE,
                Permission.EXECUTE,
                Permission.MCP_ACCESS,
                Permission.AGENT_ACCESS,
                Permission.METRICS_READ,
                Permission.LOGS_READ,
            },
            UserRole.SERVICE: {
                Permission.READ,
                Permission.WRITE,
                Permission.MCP_ACCESS,
                Permission.AGENT_ACCESS,
                Permission.EXECUTE,
            },
            UserRole.SYSTEM: {perm for perm in Permission},  # All permissions
        }

    async def create_user(
        self,
        username: str,
        email: str,
        password: str,
        roles: Optional[Set[UserRole]] = None,
    ) -> User:
        """Create a new user"""
        # Validate password
        if len(password) < self.config.password_min_length:
            raise ValueError(
                f"Password must be at least {self.config.password_min_length} characters"
            )

        # Check if user exists
        if any(u.username == username for u in self.users.values()):
            raise ValueError("Username already exists")

        if any(u.email == email for u in self.users.values()):
            raise ValueError("Email already exists")

        # Hash password
        password_hash = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

        # Create user
        user = User(
            id=secrets.token_hex(16),
            username=username,
            email=email,
            password_hash=password_hash,
            roles=roles or {UserRole.USER},
        )

        # Set permissions based on roles
        user.permissions = set()
        for role in user.roles:
            user.permissions.update(self.role_permissions.get(role, set()))

        self.users[user.id] = user
        self.logger.info(f"Created user: {username}")

        return user

    async def authenticate(
        self, method: AuthMethod, credentials: Dict[str, Any]
    ) -> Optional[User]:
        """Authenticate user"""
        # Check rate limiting
        identifier = credentials.get("username", credentials.get("api_key", "unknown"))
        if await self._is_rate_limited(identifier):
            self.logger.warning(f"Rate limited authentication attempt for {identifier}")
            return None

        provider = self.providers.get(method)
        if not provider:
            self.logger.error(f"No provider for auth method: {method}")
            return None

        user = await provider.authenticate(credentials)

        if user:
            self.logger.info(f"Successful authentication: {user.username}")
            # Clear failed attempts on success
            if identifier in self.failed_attempts:
                del self.failed_attempts[identifier]
        else:
            # Record failed attempt
            await self._record_failed_attempt(identifier)
            self.logger.warning(f"Failed authentication attempt for {identifier}")

        return user

    async def _is_rate_limited(self, identifier: str) -> bool:
        """Check if identifier is rate limited"""
        if identifier not in self.failed_attempts:
            return False

        cutoff_time = datetime.now() - timedelta(
            minutes=self.config.lockout_duration_minutes
        )
        recent_attempts = [
            attempt
            for attempt in self.failed_attempts[identifier]
            if attempt > cutoff_time
        ]

        self.failed_attempts[identifier] = recent_attempts
        return len(recent_attempts) >= self.config.max_login_attempts

    async def _record_failed_attempt(self, identifier: str):
        """Record failed authentication attempt"""
        if identifier not in self.failed_attempts:
            self.failed_attempts[identifier] = []
        self.failed_attempts[identifier].append(datetime.now())

    async def generate_jwt(self, user: User) -> str:
        """Generate JWT token for user"""
        issued_at = datetime.now()
        expires_at = issued_at + timedelta(hours=self.config.jwt_expiry_hours)

        token_data = JWTToken(
            user_id=user.id,
            username=user.username,
            roles=[role.value for role in user.roles],
            permissions=[perm.value for perm in user.permissions],
            issued_at=issued_at,
            expires_at=expires_at,
        )

        payload = token_data.to_payload()
        token = jwt.encode(
            payload, self.config.jwt_secret, algorithm=self.config.jwt_algorithm
        )

        self.logger.info(f"Generated JWT for user: {user.username}")
        return token

    async def validate_jwt(self, token: str) -> Optional[User]:
        """Validate JWT token"""
        try:
            payload = jwt.decode(
                token, self.config.jwt_secret, algorithms=[self.config.jwt_algorithm]
            )

            # Check if token is revoked
            token_id = payload.get("jti")
            if token_id in self.revoked_tokens:
                return None

            # Get user
            user_id = payload.get("user_id")
            user = self.users.get(user_id)

            if not user or not user.is_active:
                return None

            return user

        except jwt.ExpiredSignatureError:
            self.logger.warning("JWT token expired")
            return None
        except jwt.InvalidTokenError as e:
            self.logger.warning(f"Invalid JWT token: {e}")
            return None

    async def revoke_jwt(self, token: str) -> bool:
        """Revoke JWT token"""
        try:
            payload = jwt.decode(
                token,
                self.config.jwt_secret,
                algorithms=[self.config.jwt_algorithm],
                options={"verify_exp": False},  # Allow expired tokens to be revoked
            )
            token_id = payload.get("jti")
            if token_id:
                self.revoked_tokens.add(token_id)
                self.logger.info(f"Revoked JWT token: {token_id}")
                return True
        except jwt.InvalidTokenError:
            pass
        return False

    async def create_api_key(
        self,
        user_id: str,
        name: str,
        permissions: Optional[Set[Permission]] = None,
        expires_days: Optional[int] = None,
    ) -> APIKey:
        """Create API key for user"""
        user = self.users.get(user_id)
        if not user:
            raise ValueError("User not found")

        # Generate secure key
        key = f"ak_{secrets.token_hex(32)}"

        # Set expiration
        expires_at = None
        if expires_days is not None:
            expires_at = datetime.now() + timedelta(days=expires_days)
        elif self.config.api_key_expiry_days > 0:
            expires_at = datetime.now() + timedelta(
                days=self.config.api_key_expiry_days
            )

        # Limit permissions to user's permissions
        if permissions:
            permissions = permissions.intersection(user.permissions)
        else:
            permissions = user.permissions.copy()

        api_key = APIKey(
            key=key,
            name=name,
            user_id=user_id,
            permissions=permissions,
            expires_at=expires_at,
        )

        self.api_keys[key] = api_key
        self.logger.info(f"Created API key '{name}' for user: {user.username}")

        return api_key

    async def validate_api_key(self, key: str) -> Optional[User]:
        """Validate API key"""
        api_key = self.api_keys.get(key)

        if not api_key or not api_key.is_active or api_key.is_expired():
            return None

        # Update last used
        api_key.last_used = datetime.now()

        # Get user
        user = self.users.get(api_key.user_id)
        if not user or not user.is_active:
            return None

        # Create temporary user with API key permissions
        temp_user = User(
            id=user.id,
            username=user.username,
            email=user.email,
            roles=user.roles,
            permissions=api_key.permissions,
            metadata={**user.metadata, "api_key_name": api_key.name},
        )

        return temp_user

    async def revoke_api_key(self, key: str) -> bool:
        """Revoke API key"""
        if key in self.api_keys:
            self.api_keys[key].is_active = False
            self.logger.info(f"Revoked API key: {key[:10]}...")
            return True
        return False

    def has_permission(self, user: User, permission: Permission) -> bool:
        """Check if user has permission"""
        return permission in user.permissions

    def has_any_permission(self, user: User, permissions: Set[Permission]) -> bool:
        """Check if user has any of the specified permissions"""
        return bool(user.permissions.intersection(permissions))

    def has_all_permissions(self, user: User, permissions: Set[Permission]) -> bool:
        """Check if user has all specified permissions"""
        return permissions.issubset(user.permissions)

    def has_role(self, user: User, role: UserRole) -> bool:
        """Check if user has role"""
        return role in user.roles

    async def change_password(
        self, user_id: str, old_password: str, new_password: str
    ) -> bool:
        """Change user password"""
        user = self.users.get(user_id)
        if not user or not user.password_hash:
            return False

        # Verify old password
        if not bcrypt.checkpw(
            old_password.encode("utf-8"), user.password_hash.encode("utf-8")
        ):
            return False

        # Validate new password
        if len(new_password) < self.config.password_min_length:
            raise ValueError(
                f"Password must be at least {self.config.password_min_length} characters"
            )

        # Hash new password
        user.password_hash = bcrypt.hashpw(
            new_password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

        self.logger.info(f"Password changed for user: {user.username}")
        return True

    def get_statistics(self) -> Dict[str, Any]:
        """Get authentication statistics"""
        now = datetime.now()
        active_users = sum(1 for user in self.users.values() if user.is_active)
        recent_logins = sum(
            1
            for user in self.users.values()
            if user.last_login and (now - user.last_login).days <= 7
        )

        active_api_keys = sum(
            1
            for key in self.api_keys.values()
            if key.is_active and not key.is_expired()
        )

        return {
            "total_users": len(self.users),
            "active_users": active_users,
            "recent_logins_7d": recent_logins,
            "total_api_keys": len(self.api_keys),
            "active_api_keys": active_api_keys,
            "revoked_tokens": len(self.revoked_tokens),
            "failed_attempts_blocked": len(self.failed_attempts),
        }


# Singleton instance
_auth_manager_instance: Optional[AuthenticationManager] = None


def get_auth_manager() -> AuthenticationManager:
    """Get singleton authentication manager"""
    global _auth_manager_instance
    if _auth_manager_instance is None:
        _auth_manager_instance = AuthenticationManager()
    return _auth_manager_instance


# Convenience decorators
def require_auth(permissions: Optional[Set[Permission]] = None):
    """Decorator to require authentication and permissions"""

    def decorator(func: Callable) -> Callable:
        async def wrapper(*args, **kwargs):
            # This would be implemented by the web framework integration
            # For now, it's a placeholder for the pattern
            return await func(*args, **kwargs)

        return wrapper

    return decorator


def require_role(roles: Set[UserRole]):
    """Decorator to require specific roles"""

    def decorator(func: Callable) -> Callable:
        async def wrapper(*args, **kwargs):
            # This would be implemented by the web framework integration
            return await func(*args, **kwargs)

        return wrapper

    return decorator
