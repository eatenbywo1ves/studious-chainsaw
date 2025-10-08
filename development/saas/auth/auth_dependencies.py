"""
Authentication Dependencies
Provides reusable dependency injection components for FastAPI
"""

from typing import Optional, List
from fastapi import Request, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
import logging

from .jwt_auth import verify_token, verify_api_key, TokenData

logger = logging.getLogger(__name__)

# Security schemes
bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
tenant_header = APIKeyHeader(name="X-Tenant-ID", auto_error=False)


# ============================================================================
# AUTHENTICATION EXTRACTORS
# ============================================================================


class AuthenticationExtractor:
    """
    Extracts and validates authentication credentials.

    Supports:
    - JWT Bearer tokens
    - API keys
    - Custom authentication schemes
    """

    @staticmethod
    async def extract_jwt_token(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    ) -> Optional[TokenData]:
        """Extract and validate JWT token from Authorization header"""
        if not credentials:
            return None

        token_data = verify_token(credentials.credentials)
        if not token_data:
            logger.warning("Invalid or expired JWT token")
            return None

        logger.debug(f"JWT token validated for user: {token_data.sub}")
        return token_data

    @staticmethod
    async def extract_api_key(
        api_key: Optional[str] = Depends(api_key_header),
    ) -> Optional[dict]:
        """Extract and validate API key from header"""
        if not api_key:
            return None

        # Note: verify_api_key needs refactoring to not require db_session inline
        # For now, we'll validate basic format
        key_data = verify_api_key(api_key)
        if not key_data:
            logger.warning("Invalid API key")
            return None

        logger.debug(f"API key validated: {key_data.get('name')}")
        return key_data

    @staticmethod
    async def extract_any_auth(
        jwt_token: Optional[TokenData] = Depends(extract_jwt_token),
        api_key_data: Optional[dict] = Depends(extract_api_key),
    ) -> Optional[dict]:
        """
        Extract authentication from any available source.

        Priority: JWT > API Key

        Returns:
            Dict with auth info or None if no valid auth
        """
        if jwt_token:
            return {
                "type": "jwt",
                "user_id": jwt_token.sub,
                "tenant_id": jwt_token.tenant_id,
                "email": jwt_token.email,
                "role": jwt_token.role,
                "token_data": jwt_token,
            }

        if api_key_data:
            return {
                "type": "api_key",
                "tenant_id": api_key_data.get("tenant_id"),
                "name": api_key_data.get("name"),
                "permissions": api_key_data.get("permissions", []),
                "key_data": api_key_data,
            }

        return None


# Convenience extractors
extract_jwt_token = AuthenticationExtractor.extract_jwt_token
extract_api_key = AuthenticationExtractor.extract_api_key
extract_any_auth = AuthenticationExtractor.extract_any_auth


# ============================================================================
# AUTHENTICATION REQUIREMENTS
# ============================================================================


async def require_authentication(auth_data: Optional[dict] = Depends(extract_any_auth)) -> dict:
    """
    Dependency that requires valid authentication.

    Raises:
        HTTPException: If no valid authentication found
    """
    if not auth_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return auth_data


async def require_jwt_authentication(
    token_data: Optional[TokenData] = Depends(extract_jwt_token),
) -> TokenData:
    """
    Dependency that specifically requires JWT authentication.

    Raises:
        HTTPException: If no valid JWT found
    """
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="JWT authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return token_data


async def get_current_user(
    token_data: TokenData = Depends(require_jwt_authentication),
) -> TokenData:
    """Get current authenticated user (backward compatible)"""
    return token_data


async def get_current_active_user(current_user: TokenData = Depends(get_current_user)) -> TokenData:
    """Ensure user is active (can add database checks here)"""
    # TODO: Add database check for user status
    return current_user


# ============================================================================
# ROLE-BASED ACCESS CONTROL
# ============================================================================


class RoleChecker:
    """
    Dependency class for checking user roles.

    Usage:
    ```python
    @app.get("/admin")
    async def admin_endpoint(user = Depends(RoleChecker(["admin", "owner"]))):
        ...
    ```
    """

    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles

    async def __call__(
        self, current_user: TokenData = Depends(get_current_active_user)
    ) -> TokenData:
        """Check if user has required role"""
        if current_user.role not in self.allowed_roles:
            logger.warning(
                f"Access denied: User {current_user.sub} has role "
                f"{current_user.role}, requires one of {self.allowed_roles}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {', '.join(self.allowed_roles)}",
            )

        return current_user


# Convenience role checkers
require_admin = RoleChecker(["owner", "admin"])
require_owner = RoleChecker(["owner"])
require_member = RoleChecker(["owner", "admin", "member"])


# ============================================================================
# PERMISSION-BASED ACCESS CONTROL
# ============================================================================


class PermissionChecker:
    """
    Dependency class for checking specific permissions.

    Usage:
    ```python
    @app.post("/data")
    async def create_data(user = Depends(PermissionChecker(["write", "create"]))):
        ...
    ```
    """

    def __init__(self, required_permissions: List[str]):
        self.required_permissions = required_permissions

    async def __call__(
        self, request: Request, auth_data: dict = Depends(require_authentication)
    ) -> dict:
        """Check if user/key has required permissions"""

        # JWT users: Check based on role
        if auth_data["type"] == "jwt":
            role = auth_data.get("role")

            # Owners and admins have all permissions
            if role in ["owner", "admin"]:
                return auth_data

            # Check role-based permissions
            role_permissions = {
                "member": ["read", "write", "create", "update"],
                "viewer": ["read"],
            }

            user_permissions = role_permissions.get(role, [])
            has_permission = all(p in user_permissions for p in self.required_permissions)

            if not has_permission:
                logger.warning(
                    f"Permission denied: User needs {self.required_permissions}, "
                    f"has {user_permissions}"
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Requires permissions: {', '.join(self.required_permissions)}",
                )

        # API keys: Check explicit permissions
        elif auth_data["type"] == "api_key":
            api_permissions = auth_data.get("permissions", [])
            has_permission = all(p in api_permissions for p in self.required_permissions)

            if not has_permission:
                logger.warning(
                    f"Permission denied: API key needs {self.required_permissions}, "
                    f"has {api_permissions}"
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"API key lacks permissions: {', '.join(self.required_permissions)}",
                )

        return auth_data


# Convenience permission checkers
require_read = PermissionChecker(["read"])
require_write = PermissionChecker(["write"])
require_delete = PermissionChecker(["delete"])


# ============================================================================
# TENANT ISOLATION
# ============================================================================


async def get_tenant_id(
    auth_data: dict = Depends(require_authentication),
    tenant_id_header: Optional[str] = Depends(tenant_header),
) -> str:
    """
    Extract tenant ID with validation.

    Priority: Auth data > Tenant header

    Raises:
        HTTPException: If tenant ID cannot be determined
    """
    # Get from auth data
    tenant_id = auth_data.get("tenant_id")

    if tenant_id:
        return tenant_id

    # Fallback to header (if explicitly provided and matches auth)
    if tenant_id_header:
        # In production, validate tenant_id_header matches user's allowed tenants
        logger.warning("Using tenant ID from header - validate in production")
        return tenant_id_header

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST, detail="Tenant identification required"
    )


class TenantAccessChecker:
    """
    Check if user has access to specific tenant.

    Usage:
    ```python
    @app.get("/tenant/{tenant_id}/data")
    async def get_tenant_data(
        tenant_id: str,
        user = Depends(TenantAccessChecker())
    ):
        ...
    ```
    """

    async def __call__(
        self,
        request: Request,
        current_tenant: str = Depends(get_tenant_id),
        auth_data: dict = Depends(require_authentication),
    ) -> dict:
        """Verify user has access to tenant"""

        # Extract tenant from path or query
        path_tenant = request.path_params.get("tenant_id")

        if path_tenant and path_tenant != current_tenant:
            logger.warning(
                f"Tenant access denied: User from tenant {current_tenant} "
                f"attempted access to tenant {path_tenant}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Access to this tenant is not allowed"
            )

        return auth_data
