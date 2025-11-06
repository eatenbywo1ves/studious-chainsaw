"""
CSRF Protection Middleware
Protects against Cross-Site Request Forgery attacks

SECURITY (SEC-010 Fix): CSRF protection for state-changing operations
"""

import os
import hmac
import hashlib
import secrets
from typing import Optional, List
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from starlette.datastructures import Headers
import logging

logger = logging.getLogger(__name__)

# Phase 6B: Import Vault client for secrets management
try:
    from auth.vault_client import get_csrf_secret
    VAULT_AVAILABLE = True
except ImportError:
    logger.warning("vault_client not available for CSRF - falling back to environment variables")
    VAULT_AVAILABLE = False


class CSRFProtectionMiddleware(BaseHTTPMiddleware):
    """
    Middleware that provides CSRF protection for state-changing operations

    Protects against:
    - Cross-Site Request Forgery (CSRF) attacks
    - Session riding attacks
    - Malicious form submissions from third-party sites

    How it works:
    1. Generates CSRF token on first request
    2. Validates CSRF token on state-changing requests (POST, PUT, PATCH, DELETE)
    3. Exempts safe methods (GET, HEAD, OPTIONS) and configurable paths
    """

    def __init__(
        self,
        app,
        secret_key: Optional[str] = None,
        exempt_paths: Optional[List[str]] = None,
        header_name: str = "X-CSRF-Token",
        cookie_name: str = "csrf_token",
        cookie_secure: bool = True,
        cookie_samesite: str = "lax",
    ):
        """
        Initialize CSRF protection middleware

        Args:
            app: ASGI application
            secret_key: Secret key for HMAC signing (from environment)
            exempt_paths: List of paths to exempt from CSRF protection
            header_name: Header name for CSRF token
            cookie_name: Cookie name for CSRF token
            cookie_secure: Use secure cookie (HTTPS only)
            cookie_samesite: SameSite cookie attribute (strict, lax, none)
        """
        super().__init__(app)

        # Phase 6B: Get secret key from Vault if available, fallback to environment
        if secret_key:
            self.secret_key = secret_key.encode()
        elif VAULT_AVAILABLE:
            try:
                csrf_secret = get_csrf_secret()
                self.secret_key = (csrf_secret or "").encode()
                if self.secret_key:
                    logger.info("✓ CSRF secret loaded from Vault")
                else:
                    raise ValueError("Empty CSRF secret from Vault")
            except Exception as e:
                logger.warning(f"Failed to load CSRF secret from Vault: {e}, using environment variable")
                self.secret_key = (os.getenv("CSRF_SECRET_KEY") or "").encode()
        else:
            self.secret_key = (os.getenv("CSRF_SECRET_KEY") or "").encode()

        if not self.secret_key:
            raise RuntimeError(
                "\n"
                "=" * 80 + "\n"
                "CRITICAL SECURITY ERROR: CSRF_SECRET_KEY not configured!\n"
                "=" * 80 + "\n"
                "CSRF protection requires a secret key for token generation.\n"
                "\n"
                "To fix this:\n"
                "1. Set CSRF_SECRET_KEY in your environment or .env.production.local\n"
                "2. Generate a secure secret:\n"
                "   python -c 'import secrets; print(secrets.token_hex(32))'\n"
                "\n"
                "For production: Use environment variables or key management service\n"
                "=" * 80
            )

        # Default exempt paths
        default_exempt = [
            "/",
            "/health",
            "/docs",
            "/openapi.json",
            "/redoc",
            "/api/auth/verify",  # Token verification (read-only)
        ]
        self.exempt_paths = set(exempt_paths or []) | set(default_exempt)

        self.header_name = header_name
        self.cookie_name = cookie_name
        self.cookie_secure = cookie_secure
        self.cookie_samesite = cookie_samesite

        # Safe HTTP methods (don't require CSRF protection)
        self.safe_methods = {"GET", "HEAD", "OPTIONS", "TRACE"}

    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Process request and enforce CSRF protection

        Args:
            request: Incoming request
            call_next: Next middleware/endpoint

        Returns:
            Response with CSRF token cookie
        """
        # Skip CSRF check for exempt paths
        if request.url.path in self.exempt_paths:
            response = await call_next(request)
            return response

        # Skip CSRF check for safe HTTP methods
        if request.method in self.safe_methods:
            response = await call_next(request)
            # Add CSRF token cookie for future requests
            self._set_csrf_cookie(response, request)
            return response

        # ============================================================================
        # SECURITY (SEC-010): Validate CSRF token for state-changing operations
        # ============================================================================
        # POST, PUT, PATCH, DELETE requests must include valid CSRF token

        # Get CSRF token from request (header or form data)
        token_from_header = request.headers.get(self.header_name)
        token_from_form = None

        # Try to get token from form data (for HTML forms)
        if request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
            try:
                form_data = await request.form()
                token_from_form = form_data.get("csrf_token")
            except Exception:
                pass  # Not a form request

        token = token_from_header or token_from_form

        # Get expected token from cookie
        expected_token = request.cookies.get(self.cookie_name)

        # Validate token
        if not token or not expected_token:
            logger.warning(
                "CSRF token missing",
                extra={
                    "path": request.url.path,
                    "method": request.method,
                    "has_header_token": bool(token_from_header),
                    "has_form_token": bool(token_from_form),
                    "has_cookie_token": bool(expected_token),
                }
            )
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "CSRF token missing. Include X-CSRF-Token header or csrf_token form field."
                }
            )

        if not self._validate_token(token, expected_token):
            logger.warning(
                "CSRF token invalid",
                extra={
                    "path": request.url.path,
                    "method": request.method,
                    "client_ip": request.client.host if request.client else "unknown",
                }
            )
            return JSONResponse(
                status_code=403,
                content={"detail": "CSRF token invalid. Please refresh the page and try again."}
            )

        # Token valid - proceed with request
        logger.debug(
            "CSRF token validated",
            extra={
                "path": request.url.path,
                "method": request.method,
            }
        )

        response = await call_next(request)

        # Refresh CSRF token in response (token rotation)
        self._set_csrf_cookie(response, request)

        return response

    def _generate_token(self) -> str:
        """
        Generate a new CSRF token

        Returns:
            CSRF token string
        """
        # Generate random token
        random_bytes = secrets.token_bytes(32)

        # Sign with HMAC for integrity
        signature = hmac.new(
            self.secret_key,
            random_bytes,
            hashlib.sha256
        ).hexdigest()

        # Combine token and signature
        token = f"{random_bytes.hex()}:{signature}"

        return token

    def _validate_token(self, token: str, expected_token: str) -> bool:
        """
        Validate CSRF token

        Args:
            token: Token from request
            expected_token: Expected token from cookie

        Returns:
            True if token is valid, False otherwise
        """
        try:
            # Tokens must match exactly (constant-time comparison)
            if not hmac.compare_digest(token, expected_token):
                return False

            # Verify token structure
            if ":" not in token:
                return False

            token_bytes_hex, signature = token.split(":", 1)
            token_bytes = bytes.fromhex(token_bytes_hex)

            # Verify HMAC signature
            expected_signature = hmac.new(
                self.secret_key,
                token_bytes,
                hashlib.sha256
            ).hexdigest()

            return hmac.compare_digest(signature, expected_signature)

        except Exception as e:
            logger.error(f"CSRF token validation error: {e}", exc_info=True)
            return False

    def _set_csrf_cookie(self, response: Response, request: Request) -> None:
        """
        Set CSRF token cookie in response

        Args:
            response: Response to modify
            request: Current request
        """
        # Check if cookie already exists
        existing_token = request.cookies.get(self.cookie_name)

        # Generate new token if not exists
        if not existing_token:
            token = self._generate_token()

            # Set cookie
            response.set_cookie(
                key=self.cookie_name,
                value=token,
                max_age=3600 * 24,  # 24 hours
                secure=self.cookie_secure,
                httponly=True,  # Prevent JavaScript access
                samesite=self.cookie_samesite,
                path="/",
            )

            logger.debug(
                "CSRF token cookie set",
                extra={
                    "path": request.url.path,
                    "secure": self.cookie_secure,
                    "samesite": self.cookie_samesite,
                }
            )


# Convenience functions

def create_csrf_middleware(
    environment: str = "production",
    secret_key: Optional[str] = None,
    exempt_paths: Optional[List[str]] = None,
) -> CSRFProtectionMiddleware:
    """
    Create CSRF protection middleware with environment-specific settings

    Args:
        environment: "production", "staging", or "development"
        secret_key: CSRF secret key (defaults to CSRF_SECRET_KEY env var)
        exempt_paths: Additional paths to exempt from CSRF protection

    Returns:
        Configured CSRFProtectionMiddleware instance
    """
    # Production uses strict settings
    if environment == "production":
        return CSRFProtectionMiddleware(
            app=None,
            secret_key=secret_key,
            exempt_paths=exempt_paths,
            cookie_secure=True,  # HTTPS only
            cookie_samesite="strict",  # Strict SameSite policy
        )

    # Development uses relaxed settings
    return CSRFProtectionMiddleware(
        app=None,
        secret_key=secret_key,
        exempt_paths=exempt_paths,
        cookie_secure=False,  # Allow HTTP for local development
        cookie_samesite="lax",  # Lax SameSite policy
    )
