"""
Prometheus Metrics Instrumentation for SaaS API
Add this to saas_server.py to enable metrics collection
"""

from fastapi import FastAPI, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
import time
from typing import Callable

# Import Prometheus metrics
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from security.application.prometheus_metrics import (
    get_metrics,
    track_login_attempt,
    track_validation_failure,
    http_requests_total,
    http_request_duration_seconds,
    lattice_operations_total,
    active_lattices,
    database_queries_total,
    rate_limit_hits_total,
)


# ============================================================================
# METRICS ENDPOINT
# ============================================================================


def add_metrics_endpoint(app: FastAPI):
    """Add /metrics endpoint to FastAPI app"""

    @app.get("/metrics")
    async def metrics():
        """Prometheus metrics endpoint"""
        content, content_type = get_metrics()
        return Response(content=content, media_type=content_type)


# ============================================================================
# METRICS MIDDLEWARE
# ============================================================================


class MetricsMiddleware(BaseHTTPMiddleware):
    """Middleware to track HTTP request metrics"""

    async def dispatch(self, request: Request, call_next: Callable):
        # Start timer
        start_time = time.time()

        # Get request details
        method = request.method
        path = request.url.path

        # Normalize path (remove IDs)
        endpoint = self._normalize_path(path)

        try:
            # Process request
            response = await call_next(request)
            status_code = response.status_code

            # Track metrics
            http_requests_total.labels(
                method=method, endpoint=endpoint, status=str(status_code)
            ).inc()

            duration = time.time() - start_time
            http_request_duration_seconds.labels(method=method, endpoint=endpoint).observe(duration)

            return response

        except Exception as e:
            # Track error
            http_requests_total.labels(method=method, endpoint=endpoint, status="500").inc()

            duration = time.time() - start_time
            http_request_duration_seconds.labels(method=method, endpoint=endpoint).observe(duration)

            raise e

    def _normalize_path(self, path: str) -> str:
        """Normalize URL path by replacing IDs with placeholders"""
        import re

        # Replace UUIDs
        path = re.sub(
            r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "/{id}",
            path,
            flags=re.IGNORECASE,
        )

        # Replace numeric IDs
        path = re.sub(r"/\d+", "/{id}", path)

        return path


# ============================================================================
# INSTRUMENTATION HELPERS
# ============================================================================


def track_authentication(tenant_slug: str, success: bool):
    """Track authentication attempt"""
    track_login_attempt(tenant_slug or "default", success)


def track_input_validation_error(validator_name: str, error_type: str):
    """Track input validation failure"""
    track_validation_failure(validator_name, error_type)


def track_lattice_operation(operation: str, dimensions: int):
    """Track lattice operation"""
    lattice_operations_total.labels(operation=operation, dimensions=str(dimensions)).inc()


def update_active_lattice_count(count: int):
    """Update active lattices gauge"""
    active_lattices.set(count)


def track_database_operation(operation: str, table: str, success: bool):
    """Track database query"""
    status = "success" if success else "failure"
    database_queries_total.labels(operation=operation, table=table, status=status).inc()


def track_rate_limit(endpoint: str, limit_type: str = "api"):
    """Track rate limit hit"""
    rate_limit_hits_total.labels(endpoint=endpoint, limit_type=limit_type).inc()


# ============================================================================
# INTEGRATION EXAMPLE
# ============================================================================

"""
To integrate with saas_server.py:

1. Add metrics endpoint:

   from api.metrics_instrumentation import add_metrics_endpoint
   add_metrics_endpoint(app)

2. Add metrics middleware:

   from api.metrics_instrumentation import MetricsMiddleware
   app.add_middleware(MetricsMiddleware)

3. Track authentication:

   from api.metrics_instrumentation import track_authentication

   @app.post("/auth/login")
   async def login(request: LoginRequest, db: Session = Depends(get_db)):
       try:
           user = authenticate(request.email, request.password)
           track_authentication(request.tenant_slug, success=True)
           return {"token": create_token(user)}
       except AuthenticationError:
           track_authentication(request.tenant_slug, success=False)
           raise HTTPException(status_code=401)

4. Track lattice operations:

   from api.metrics_instrumentation import track_lattice_operation, update_active_lattice_count

   @app.post("/lattices")
   async def create_lattice(request: LatticeCreateRequest):
       lattice = lattice_manager.create_lattice(...)
       track_lattice_operation('create', request.dimensions)
       update_active_lattice_count(len(lattice_manager._lattices))
       return lattice

5. Track validation errors:

   from api.metrics_instrumentation import track_input_validation_error
   from pydantic import ValidationError

   try:
       LoginRequest(**request_data)
   except ValidationError as e:
       track_input_validation_error('LoginRequest', 'invalid_email')
       raise
"""
