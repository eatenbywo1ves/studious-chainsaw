"""
Prometheus Metrics Instrumentation for Catalytic Computing SaaS
Phase 2 Security Deployment - Monitoring & Alerting

Implements:
- PCI DSS Requirement 10 - Logging and monitoring
- SOC 2 CC7.2 - System monitoring
- ISO 27001 A.12.4 - Logging and monitoring
"""

from prometheus_client import (
    Counter,
    Histogram,
    Gauge,
    Summary,
    generate_latest,
    CONTENT_TYPE_LATEST
)
from functools import wraps
import time
from typing import Callable
import logging

logger = logging.getLogger(__name__)

# ============================================================================
# PROMETHEUS REGISTRY
# ============================================================================

# Use default registry for simplicity (can be customized per environment)
# registry = CollectorRegistry()  # Custom registry if needed


# ============================================================================
# HTTP METRICS
# ============================================================================

http_requests_total = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

http_request_duration_seconds = Histogram(
    'http_request_duration_seconds',
    'HTTP request latency in seconds',
    ['method', 'endpoint'],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0]
)

http_request_size_bytes = Summary(
    'http_request_size_bytes',
    'HTTP request size in bytes',
    ['method', 'endpoint']
)

http_response_size_bytes = Summary(
    'http_response_size_bytes',
    'HTTP response size in bytes',
    ['method', 'endpoint', 'status']
)


# ============================================================================
# AUTHENTICATION METRICS
# ============================================================================

jwt_token_operations_total = Counter(
    'jwt_token_operations_total',
    'JWT token operations',
    ['operation', 'status']
)

jwt_token_blacklist_size = Gauge(
    'jwt_token_blacklist_size',
    'Number of blacklisted JWT tokens'
)

login_attempts_total = Counter(
    'login_attempts_total',
    'Login attempts',
    ['tenant', 'status']
)

password_reset_requests_total = Counter(
    'password_reset_requests_total',
    'Password reset requests',
    ['status']
)


# ============================================================================
# SECURITY METRICS
# ============================================================================

rate_limit_hits_total = Counter(
    'rate_limit_hits_total',
    'Rate limit hits',
    ['endpoint', 'limit_type']
)

input_validation_failures_total = Counter(
    'input_validation_failures_total',
    'Input validation failures',
    ['validator', 'type']
)

encryption_operations_total = Counter(
    'encryption_operations_total',
    'Encryption operations',
    ['operation', 'status']
)

encryption_errors_total = Counter(
    'encryption_errors_total',
    'Encryption operation errors',
    ['operation', 'error_type']
)

decryption_errors_total = Counter(
    'decryption_errors_total',
    'Decryption operation errors',
    ['error_type']
)

encryption_duration_seconds = Histogram(
    'encryption_duration_seconds',
    'Encryption operation duration',
    ['operation'],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
)


# ============================================================================
# DATABASE METRICS
# ============================================================================

database_queries_total = Counter(
    'database_queries_total',
    'Database queries executed',
    ['operation', 'table', 'status']
)

database_query_duration_seconds = Histogram(
    'database_query_duration_seconds',
    'Database query duration',
    ['operation', 'table'],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
)

database_connections_active = Gauge(
    'database_connections_active',
    'Active database connections'
)

database_connections_max = Gauge(
    'database_connections_max',
    'Maximum database connections'
)


# ============================================================================
# CACHE METRICS (REDIS)
# ============================================================================

cache_requests_total = Counter(
    'cache_requests_total',
    'Cache requests',
    ['operation', 'status']
)

cache_hits_total = Counter(
    'cache_hits_total',
    'Cache hits'
)

cache_misses_total = Counter(
    'cache_misses_total',
    'Cache misses'
)

redis_connections_active = Gauge(
    'redis_connections_active',
    'Active Redis connections'
)


# ============================================================================
# APPLICATION METRICS
# ============================================================================

lattice_operations_total = Counter(
    'lattice_operations_total',
    'Lattice operations',
    ['operation', 'dimensions']
)

lattice_creation_seconds = Histogram(
    'lattice_creation_seconds',
    'Lattice creation duration',
    ['dimensions'],
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0]
)

path_finding_seconds = Histogram(
    'path_finding_seconds',
    'Path finding duration',
    ['dimensions', 'algorithm'],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
)

active_lattices = Gauge(
    'active_lattices',
    'Number of active lattices'
)

memory_usage_bytes = Gauge(
    'memory_usage_bytes',
    'Memory usage by component',
    ['component']
)


# ============================================================================
# DECORATOR FUNCTIONS
# ============================================================================

def track_request_metrics(endpoint: str):
    """
    Decorator to track HTTP request metrics

    Usage:
        @track_request_metrics('/api/lattices')
        async def create_lattice(request):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get request object (adjust based on framework)
            request = args[0] if args else kwargs.get('request')
            method = getattr(request, 'method', 'UNKNOWN')

            # Start timer
            start_time = time.time()

            try:
                # Execute request
                response = await func(*args, **kwargs)

                # Track success metrics
                status = getattr(response, 'status_code', 200)
                http_requests_total.labels(method=method, endpoint=endpoint, status=status).inc()

                duration = time.time() - start_time
                http_request_duration_seconds.labels(method=method, endpoint=endpoint).observe(duration)

                return response

            except Exception as e:
                # Track error metrics
                http_requests_total.labels(method=method, endpoint=endpoint, status='500').inc()

                duration = time.time() - start_time
                http_request_duration_seconds.labels(method=method, endpoint=endpoint).observe(duration)

                raise e

        return wrapper
    return decorator


def track_authentication(operation: str):
    """
    Decorator to track authentication operations

    Usage:
        @track_authentication('login')
        async def login(credentials):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                result = await func(*args, **kwargs)
                jwt_token_operations_total.labels(operation=operation, status='success').inc()
                return result
            except Exception as e:
                jwt_token_operations_total.labels(operation=operation, status='failure').inc()
                raise e
        return wrapper
    return decorator


def track_encryption(operation: str):
    """
    Decorator to track encryption operations

    Usage:
        @track_encryption('encrypt_field')
        def encrypt_data(data):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()

            try:
                result = func(*args, **kwargs)

                # Track success
                encryption_operations_total.labels(operation=operation, status='success').inc()

                duration = time.time() - start_time
                encryption_duration_seconds.labels(operation=operation).observe(duration)

                return result

            except Exception as e:
                # Track failure
                encryption_operations_total.labels(operation=operation, status='failure').inc()
                encryption_errors_total.labels(operation=operation, error_type=type(e).__name__).inc()
                raise e

        return wrapper
    return decorator


def track_database_query(operation: str, table: str):
    """
    Decorator to track database queries

    Usage:
        @track_database_query('select', 'users')
        async def get_user(user_id):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()

            try:
                result = await func(*args, **kwargs)

                # Track success
                database_queries_total.labels(operation=operation, table=table, status='success').inc()

                duration = time.time() - start_time
                database_query_duration_seconds.labels(operation=operation, table=table).observe(duration)

                return result

            except Exception as e:
                # Track failure
                database_queries_total.labels(operation=operation, table=table, status='failure').inc()
                raise e

        return wrapper
    return decorator


# ============================================================================
# MANUAL TRACKING FUNCTIONS
# ============================================================================

def track_login_attempt(tenant: str, success: bool):
    """Track login attempt"""
    status = 'success' if success else 'failure'
    login_attempts_total.labels(tenant=tenant, status=status).inc()


def track_rate_limit_hit(endpoint: str, limit_type: str):
    """Track rate limit hit"""
    rate_limit_hits_total.labels(endpoint=endpoint, limit_type=limit_type).inc()


def track_validation_failure(validator: str, failure_type: str):
    """Track input validation failure"""
    input_validation_failures_total.labels(validator=validator, type=failure_type).inc()


def track_cache_operation(operation: str, hit: bool):
    """Track cache operation"""
    status = 'hit' if hit else 'miss'
    cache_requests_total.labels(operation=operation, status=status).inc()

    if hit:
        cache_hits_total.inc()
    else:
        cache_misses_total.inc()


def update_blacklist_size(size: int):
    """Update JWT blacklist size gauge"""
    jwt_token_blacklist_size.set(size)


def update_active_connections(db_active: int, db_max: int, redis_active: int):
    """Update connection pool metrics"""
    database_connections_active.set(db_active)
    database_connections_max.set(db_max)
    redis_connections_active.set(redis_active)


def update_memory_usage(component: str, bytes_used: int):
    """Update memory usage metric"""
    memory_usage_bytes.labels(component=component).set(bytes_used)


# ============================================================================
# METRICS ENDPOINT
# ============================================================================

def get_metrics() -> tuple:
    """
    Generate Prometheus metrics output

    Returns:
        (content, content_type) tuple for HTTP response
    """
    try:
        metrics_output = generate_latest()
        return metrics_output, CONTENT_TYPE_LATEST
    except Exception as e:
        logger.error(f"Error generating metrics: {e}")
        return b"# Error generating metrics\n", CONTENT_TYPE_LATEST


# ============================================================================
# EXAMPLE INTEGRATION
# ============================================================================

"""
Example integration with FastAPI:

from fastapi import FastAPI, Response
from security.application.prometheus_metrics import (
    get_metrics,
    track_request_metrics,
    track_login_attempt
)

app = FastAPI()

# Metrics endpoint
@app.get('/metrics')
async def metrics():
    content, content_type = get_metrics()
    return Response(content=content, media_type=content_type)

# Instrumented endpoint
@app.post('/auth/login')
@track_request_metrics('/auth/login')
async def login(request: LoginRequest):
    try:
        # Login logic
        user = authenticate(request.email, request.password)
        track_login_attempt(request.tenant_slug or 'default', success=True)
        return {"token": generate_token(user)}
    except AuthenticationError:
        track_login_attempt(request.tenant_slug or 'default', success=False)
        raise HTTPException(status_code=401)
"""
