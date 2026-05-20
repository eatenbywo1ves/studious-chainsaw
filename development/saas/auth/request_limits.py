"""
Request Size Limit Middleware
Prevents DOS attacks via large request payloads

SECURITY (SEC-011 Fix): Request size limits with streaming validation
Version: 2.1 (100% complete - includes streaming validation + Prometheus metrics)
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from starlette.types import ASGIApp
from starlette.exceptions import HTTPException
import logging

# Prometheus metrics for monitoring
try:
    from prometheus_client import Counter, Histogram

    # Request size rejections counter
    request_size_exceeded = Counter(
        'request_size_limit_exceeded_total',
        'Total number of requests rejected due to size limits',
        ['method', 'path', 'limit_type', 'rejection_type']
    )

    # Request body size distribution histogram
    request_body_bytes = Histogram(
        'request_body_bytes',
        'Distribution of request body sizes in bytes',
        ['method', 'limit_type'],
        buckets=[
            1024,           # 1KB
            10*1024,        # 10KB
            100*1024,       # 100KB
            1*1024*1024,    # 1MB
            10*1024*1024,   # 10MB
            100*1024*1024,  # 100MB
            1000*1024*1024  # 1GB
        ]
    )

    METRICS_ENABLED = True
except ImportError:
    # Prometheus client not installed - metrics disabled
    METRICS_ENABLED = False

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

    async def _create_validated_stream(self, request: Request, max_size: int, is_upload: bool):
        """
        Create a stream that validates body size as it's read

        Args:
            request: Original request
            max_size: Maximum allowed size in bytes
            is_upload: Whether this is an upload request

        Yields:
            Chunks of the request body

        Raises:
            HTTPException: If body exceeds max_size during streaming
        """
        bytes_read = 0
        content_length_header = request.headers.get("content-length", "not provided")

        try:
            async for chunk in request.stream():
                bytes_read += len(chunk)

                if bytes_read > max_size:
                    size_mb = bytes_read / (1024 * 1024)
                    limit_mb = max_size / (1024 * 1024)

                    logger.error(
                        f"Streaming body exceeded limit: {size_mb:.2f}MB > {limit_mb:.2f}MB",
                        extra={
                            "path": str(request.url.path),
                            "method": request.method,
                            "bytes_read": bytes_read,
                            "max_size": max_size,
                            "is_upload": is_upload,
                            "content_length_header": content_length_header,
                            "client_ip": request.client.host if request.client else "unknown",
                        }
                    )

                    # Increment metrics for streaming rejection
                    if METRICS_ENABLED:
                        limit_type = "upload" if is_upload else "regular"
                        request_size_exceeded.labels(
                            method=request.method,
                            path=str(request.url.path),
                            limit_type=limit_type,
                            rejection_type="streaming"
                        ).inc()

                    raise HTTPException(
                        status_code=413,
                        detail=f"Request body too large. Maximum: {limit_mb:.0f}MB, "
                               f"received: {size_mb:.2f}MB"
                    )

                yield chunk

        finally:
            # Log final size for monitoring (only if not exceeded)
            if bytes_read <= max_size:
                logger.debug(
                    f"Request body validated: {bytes_read} bytes",
                    extra={
                        "path": str(request.url.path),
                        "bytes_read": bytes_read,
                        "max_size": max_size
                    }
                )

                # Record successful request body size in histogram
                if METRICS_ENABLED:
                    limit_type = "upload" if is_upload else "regular"
                    request_body_bytes.labels(
                        method=request.method,
                        limit_type=limit_type
                    ).observe(bytes_read)

    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Process request and enforce size limits

        Args:
            request: Incoming request
            call_next: Next middleware/endpoint

        Returns:
            Response or error if size limit exceeded
        """
        # Determine if this is an upload endpoint
        is_upload = (
            "/upload" in request.url.path or
            "/file" in request.url.path or
            request.headers.get("content-type", "").startswith("multipart/form-data")
        )

        # Select appropriate limit
        max_size = self.max_upload_size if is_upload else self.max_request_size

        # Get Content-Length header for fast-path validation
        content_length = request.headers.get("content-length")

        if content_length:
            content_length_int = int(content_length)

            # Fast path: reject immediately if Content-Length exceeds limit
            if content_length_int > max_size:
                size_mb = content_length_int / (1024 * 1024)
                limit_mb = max_size / (1024 * 1024)

                logger.warning(
                    f"Request size limit exceeded (Content-Length): {size_mb:.2f}MB > {limit_mb:.2f}MB",
                    extra={
                        "path": str(request.url.path),
                        "method": request.method,
                        "content_length": content_length_int,
                        "max_size": max_size,
                        "is_upload": is_upload,
                        "client_ip": request.client.host if request.client else "unknown",
                    }
                )

                # Increment metrics for Content-Length rejection (fast path)
                if METRICS_ENABLED:
                    limit_type = "upload" if is_upload else "regular"
                    request_size_exceeded.labels(
                        method=request.method,
                        path=str(request.url.path),
                        limit_type=limit_type,
                        rejection_type="content_length"
                    ).inc()

                return JSONResponse(
                    status_code=413,  # Payload Too Large
                    content={
                        "detail": f"Request too large. Maximum size: {limit_mb:.0f}MB, "
                                  f"received: {size_mb:.2f}MB"
                    }
                )

        # Streaming validation: wrap body stream for POST/PUT/PATCH requests
        # This protects against:
        # 1. Missing Content-Length headers
        # 2. Incorrect Content-Length headers (attacker lying about size)
        # 3. Chunked transfer encoding without Content-Length
        if request.method in ["POST", "PUT", "PATCH"]:
            # Replace request stream with validated stream
            request._stream = self._create_validated_stream(request, max_size, is_upload)

        # Proceed with request (streaming validation happens during body read)
        try:
            response = await call_next(request)
            return response
        except HTTPException as e:
            # Convert HTTPException to JSONResponse
            return JSONResponse(
                status_code=e.status_code,
                content={"detail": e.detail}
            )
