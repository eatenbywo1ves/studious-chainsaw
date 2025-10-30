"""
Request Size Limit Middleware
Prevents DOS attacks via large request payloads

SECURITY (SEC-011 Fix): Request size limits
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from starlette.types import ASGIApp
import logging

logger = logging.getLogger(__name__)


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware that enforces request body size limits

    Protects against:
    - DOS attacks via large payloads
    - Memory exhaustion
    - Bandwidth exhaustion
    """

    def __init__(
        self,
        app: ASGIApp,
        max_request_size: int = 10 * 1024 * 1024,  # 10MB default
        max_upload_size: int = 100 * 1024 * 1024,  # 100MB for file uploads
    ):
        """
        Initialize request size limit middleware

        Args:
            app: ASGI application
            max_request_size: Maximum request body size in bytes (default: 10MB)
            max_upload_size: Maximum upload size in bytes (default: 100MB)
        """
        super().__init__(app)
        self.max_request_size = max_request_size
        self.max_upload_size = max_upload_size

    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Process request and enforce size limits

        Args:
            request: Incoming request
            call_next: Next middleware/endpoint

        Returns:
            Response or error if size limit exceeded
        """
        # Get Content-Length header
        content_length = request.headers.get("content-length")

        if content_length:
            content_length = int(content_length)

            # Check if this is a file upload endpoint
            is_upload = (
                "/upload" in request.url.path or
                "/file" in request.url.path or
                request.headers.get("content-type", "").startswith("multipart/form-data")
            )

            # Select appropriate limit
            max_size = self.max_upload_size if is_upload else self.max_request_size

            # Check size limit
            if content_length > max_size:
                size_mb = content_length / (1024 * 1024)
                limit_mb = max_size / (1024 * 1024)

                logger.warning(
                    f"Request size limit exceeded: {size_mb:.2f}MB > {limit_mb:.2f}MB",
                    extra={
                        "path": request.url.path,
                        "method": request.method,
                        "content_length": content_length,
                        "max_size": max_size,
                        "is_upload": is_upload,
                        "client_ip": request.client.host if request.client else "unknown",
                    }
                )

                return JSONResponse(
                    status_code=413,  # Payload Too Large
                    content={
                        "detail": f"Request too large. Maximum size: {limit_mb:.0f}MB, "
                                  f"received: {size_mb:.2f}MB"
                    }
                )

        # Size OK - proceed with request
        response = await call_next(request)
        return response
