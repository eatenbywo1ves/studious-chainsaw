"""
Security Headers Middleware
Adds security headers to all HTTP responses to protect against common attacks
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from typing import Callable, Optional
import logging

logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware that adds security headers to all responses

    Protects against:
    - Clickjacking (X-Frame-Options, CSP frame-ancestors)
    - XSS (Content-Security-Policy, X-XSS-Protection)
    - MIME sniffing (X-Content-Type-Options)
    - Man-in-the-middle (Strict-Transport-Security)
    - Information leakage (X-Powered-By removal, Server hiding)
    """

    def __init__(
        self,
        app,
        hsts_max_age: int = 31536000,  # 1 year in seconds
        csp_directives: Optional[dict] = None,
        frame_options: str = "DENY",
        enable_permissions_policy: bool = True,
        enable_referrer_policy: bool = True
    ):
        """
        Initialize security headers middleware

        Args:
            app: ASGI application
            hsts_max_age: HSTS max-age in seconds (default: 1 year)
            csp_directives: Custom CSP directives (default: strict policy)
            frame_options: X-Frame-Options value (DENY, SAMEORIGIN, or ALLOW-FROM uri)
            enable_permissions_policy: Enable Permissions-Policy header
            enable_referrer_policy: Enable Referrer-Policy header
        """
        super().__init__(app)
        self.hsts_max_age = hsts_max_age
        self.frame_options = frame_options
        self.enable_permissions_policy = enable_permissions_policy
        self.enable_referrer_policy = enable_referrer_policy

        # Default CSP directives (strict)
        default_csp = {
            "default-src": "'self'",
            "script-src": "'self' 'unsafe-inline' 'unsafe-eval'",  # Relaxed for modern frameworks
            "style-src": "'self' 'unsafe-inline'",  # For inline styles
            "img-src": "'self' data: https:",
            "font-src": "'self' data:",
            "connect-src": "'self'",
            "frame-ancestors": "'none'",
            "base-uri": "'self'",
            "form-action": "'self'",
            "upgrade-insecure-requests": ""
        }

        # Merge custom CSP with defaults
        self.csp_directives = {**default_csp, **(csp_directives or {})}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request and add security headers to response

        Args:
            request: Incoming request
            call_next: Next middleware/endpoint

        Returns:
            Response with security headers added
        """
        # Get response from next middleware/endpoint
        response = await call_next(request)

        # Add security headers
        self._add_security_headers(response)

        return response

    def _add_security_headers(self, response: Response) -> None:
        """
        Add all security headers to response

        Args:
            response: Response object to modify
        """
        # Strict-Transport-Security (HSTS)
        # Forces HTTPS connections
        if self.hsts_max_age > 0:
            response.headers["Strict-Transport-Security"] = (
                f"max-age={self.hsts_max_age}; includeSubDomains; preload"
            )

        # X-Content-Type-Options
        # Prevents MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # X-Frame-Options
        # Prevents clickjacking
        response.headers["X-Frame-Options"] = self.frame_options

        # Content-Security-Policy
        # Mitigates XSS, clickjacking, and other injection attacks
        csp_header = self._build_csp_header()
        if csp_header:
            response.headers["Content-Security-Policy"] = csp_header

        # X-XSS-Protection
        # Legacy XSS filter (still useful for older browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Referrer-Policy
        # Controls referrer information sent with requests
        if self.enable_referrer_policy:
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions-Policy (formerly Feature-Policy)
        # Controls browser features and APIs
        if self.enable_permissions_policy:
            permissions_policy = (
                "geolocation=(), "
                "microphone=(), "
                "camera=(), "
                "payment=(), "
                "usb=(), "
                "magnetometer=(), "
                "gyroscope=(), "
                "accelerometer=()"
            )
            response.headers["Permissions-Policy"] = permissions_policy

        # Remove information disclosure headers
        response.headers.pop("Server", None)  # Hide server version
        response.headers.pop("X-Powered-By", None)  # Hide framework version

        # Cross-Origin headers (CORS-related security)
        # These prevent cross-origin attacks while allowing legitimate CORS
        if "Access-Control-Allow-Origin" not in response.headers:
            response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
            response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
            response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

    def _build_csp_header(self) -> str:
        """
        Build Content-Security-Policy header from directives

        Returns:
            CSP header string
        """
        csp_parts = []
        for directive, value in self.csp_directives.items():
            if value:  # Only add if value is not empty
                csp_parts.append(f"{directive} {value}")
            else:
                csp_parts.append(directive)  # Directive with no value (like upgrade-insecure-requests)

        return "; ".join(csp_parts)


# Pre-configured middleware instances for common use cases

def create_strict_security_headers() -> SecurityHeadersMiddleware:
    """
    Create middleware with strict security headers
    Recommended for production applications
    """
    return SecurityHeadersMiddleware(
        app=None,  # App will be set by FastAPI
        hsts_max_age=31536000,  # 1 year
        frame_options="DENY",
        csp_directives={
            "default-src": "'self'",
            "script-src": "'self'",
            "style-src": "'self'",
            "img-src": "'self' data: https:",
            "font-src": "'self'",
            "connect-src": "'self'",
            "frame-ancestors": "'none'",
            "base-uri": "'self'",
            "form-action": "'self'",
            "upgrade-insecure-requests": ""
        },
        enable_permissions_policy=True,
        enable_referrer_policy=True
    )


def create_relaxed_security_headers() -> SecurityHeadersMiddleware:
    """
    Create middleware with relaxed security headers
    Suitable for development or applications with inline scripts/styles
    """
    return SecurityHeadersMiddleware(
        app=None,
        hsts_max_age=0,  # Disabled for development
        frame_options="SAMEORIGIN",
        csp_directives={
            "default-src": "'self'",
            "script-src": "'self' 'unsafe-inline' 'unsafe-eval'",
            "style-src": "'self' 'unsafe-inline'",
            "img-src": "'self' data: https: blob:",
            "font-src": "'self' data: https:",
            "connect-src": "'self' ws: wss:",  # Allow WebSocket
            "frame-ancestors": "'self'",
            "base-uri": "'self'",
            "form-action": "'self'"
        },
        enable_permissions_policy=False,
        enable_referrer_policy=True
    )


def create_api_security_headers() -> SecurityHeadersMiddleware:
    """
    Create middleware optimized for API endpoints
    No CSP restrictions on scripts/styles, focused on transport security
    """
    return SecurityHeadersMiddleware(
        app=None,
        hsts_max_age=31536000,
        frame_options="DENY",
        csp_directives={
            "default-src": "'none'",  # APIs shouldn't load resources
            "frame-ancestors": "'none'",
            "base-uri": "'none'"
        },
        enable_permissions_policy=True,
        enable_referrer_policy=True
    )


# Helper function for custom configuration
def create_custom_security_headers(
    environment: str = "production",
    allow_inline_scripts: bool = False,
    allow_websockets: bool = False,
    allowed_origins: list = None
) -> SecurityHeadersMiddleware:
    """
    Create middleware with custom security headers based on requirements

    Args:
        environment: "production", "staging", or "development"
        allow_inline_scripts: Allow inline scripts and eval (reduces security)
        allow_websockets: Allow WebSocket connections
        allowed_origins: List of allowed origins for CORS-safe operations

    Returns:
        Configured SecurityHeadersMiddleware instance
    """
    # Base configuration
    config = {
        "hsts_max_age": 31536000 if environment == "production" else 0,
        "frame_options": "DENY" if environment == "production" else "SAMEORIGIN",
        "enable_permissions_policy": environment == "production",
        "enable_referrer_policy": True,
        "csp_directives": {
            "default-src": "'self'",
            "img-src": "'self' data: https:",
            "font-src": "'self' data:",
            "frame-ancestors": "'none'",
            "base-uri": "'self'",
            "form-action": "'self'"
        }
    }

    # Script source configuration
    if allow_inline_scripts:
        config["csp_directives"]["script-src"] = "'self' 'unsafe-inline' 'unsafe-eval'"
        config["csp_directives"]["style-src"] = "'self' 'unsafe-inline'"
    else:
        config["csp_directives"]["script-src"] = "'self'"
        config["csp_directives"]["style-src"] = "'self'"

    # WebSocket configuration
    if allow_websockets:
        config["csp_directives"]["connect-src"] = "'self' ws: wss:"
    else:
        config["csp_directives"]["connect-src"] = "'self'"

    # HTTPS upgrade in production
    if environment == "production":
        config["csp_directives"]["upgrade-insecure-requests"] = ""

    return SecurityHeadersMiddleware(app=None, **config)
