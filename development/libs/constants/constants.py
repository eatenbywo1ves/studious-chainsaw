"""
Constants for Catalytic Computing System
Centralizes all magic numbers and configuration constants
"""

from enum import Enum, IntEnum
from typing import Final

# === Lattice Computing Constants ===

# Dimension constraints
MIN_DIMENSIONS: Final[int] = 1
MAX_DIMENSIONS: Final[int] = 10
DEFAULT_DIMENSIONS: Final[int] = 4

# Size constraints
MIN_LATTICE_SIZE: Final[int] = 2
MAX_LATTICE_SIZE: Final[int] = 100
DEFAULT_LATTICE_SIZE: Final[int] = 10

# Memory constraints
MIN_AUX_MEMORY_MB: Final[float] = 0.1
MAX_AUX_MEMORY_MB: Final[float] = 1024.0
DEFAULT_AUX_MEMORY_MB: Final[float] = 10.0

# Performance thresholds
MAX_PATH_FINDING_TIMEOUT_SEC: Final[float] = 60.0
DEFAULT_COMPUTATION_TIMEOUT_SEC: Final[float] = 30.0
CACHE_LINE_SIZE_BYTES: Final[int] = 64

# === GPU Constants ===

# CUDA configuration
CUDA_CORES_PER_SM: Final[int] = 32  # For most NVIDIA GPUs
MAX_THREADS_PER_BLOCK: Final[int] = 1024
DEFAULT_BLOCK_SIZE: Final[int] = 256
WARP_SIZE: Final[int] = 32

# Memory limits
MIN_GPU_MEMORY_MB: Final[int] = 512
DEFAULT_GPU_MEMORY_LIMIT_MB: Final[int] = 8192
GPU_MEMORY_SAFETY_MARGIN: Final[float] = 0.9  # Use only 90% of available memory

# === API Server Constants ===

# Port ranges
MIN_PORT: Final[int] = 1
MAX_PORT: Final[int] = 65535
DEFAULT_API_PORT: Final[int] = 8080
DEFAULT_WEBHOOK_PORT: Final[int] = 8085
DEFAULT_METRICS_PORT: Final[int] = 9090

# Rate limiting
DEFAULT_RATE_LIMIT_PER_MINUTE: Final[int] = 60
MAX_RATE_LIMIT_PER_MINUTE: Final[int] = 1000
RATE_LIMIT_WINDOW_SECONDS: Final[int] = 60

# Request/Response limits
MAX_REQUEST_SIZE_MB: Final[int] = 10
MAX_RESPONSE_SIZE_MB: Final[int] = 100
DEFAULT_REQUEST_TIMEOUT_SEC: Final[int] = 30
MAX_REQUEST_TIMEOUT_SEC: Final[int] = 300

# Pagination
DEFAULT_PAGE_SIZE: Final[int] = 100
MAX_PAGE_SIZE: Final[int] = 1000
MIN_PAGE_SIZE: Final[int] = 1

# === Webhook Constants ===

# Retry configuration
MIN_WEBHOOK_RETRIES: Final[int] = 0
MAX_WEBHOOK_RETRIES: Final[int] = 10
DEFAULT_WEBHOOK_RETRIES: Final[int] = 3

MIN_RETRY_DELAY_SEC: Final[int] = 1
MAX_RETRY_DELAY_SEC: Final[int] = 60
DEFAULT_RETRY_DELAY_SEC: Final[int] = 5
EXPONENTIAL_BACKOFF_FACTOR: Final[float] = 2.0

# Webhook limits
MAX_WEBHOOKS_PER_EVENT: Final[int] = 100
MAX_WEBHOOK_PAYLOAD_SIZE_KB: Final[int] = 512
WEBHOOK_SIGNATURE_ALGORITHM: Final[str] = "sha256"

# Delivery status check
WEBHOOK_DELIVERY_SUCCESS_CODES: Final[tuple] = (200, 201, 202, 204)
WEBHOOK_DELIVERY_RETRY_CODES: Final[tuple] = (429, 500, 502, 503, 504)

# === Database Constants ===

# Connection pool
MIN_DB_CONNECTIONS: Final[int] = 1
MAX_DB_CONNECTIONS: Final[int] = 100
DEFAULT_DB_POOL_SIZE: Final[int] = 10

# Timeouts
DEFAULT_DB_TIMEOUT_SEC: Final[int] = 30
MAX_DB_TIMEOUT_SEC: Final[int] = 300
DB_LOCK_TIMEOUT_SEC: Final[int] = 10

# Query limits
MAX_QUERY_RESULTS: Final[int] = 10000
DEFAULT_BATCH_SIZE: Final[int] = 1000

# === Memory Optimization Constants ===

# Memory pool configuration
DEFAULT_MEMORY_POOL_SIZE: Final[int] = 10
MAX_MEMORY_POOL_SIZE: Final[int] = 100
MEMORY_ALIGNMENT_BYTES: Final[int] = 64

# Memory thresholds
MEMORY_WARNING_THRESHOLD_PERCENT: Final[float] = 80.0
MEMORY_CRITICAL_THRESHOLD_PERCENT: Final[float] = 95.0
MEMORY_CLEANUP_THRESHOLD_MB: Final[float] = 100.0

# Cache configuration
DEFAULT_CACHE_SIZE_MB: Final[int] = 1024
MAX_CACHE_SIZE_MB: Final[int] = 10240
CACHE_EVICTION_PERCENT: Final[float] = 0.2  # Evict 20% when full
CACHE_TTL_SECONDS: Final[int] = 3600  # 1 hour

# === File System Constants ===

# File size limits
MAX_UPLOAD_SIZE_MB: Final[int] = 100
MAX_LOG_FILE_SIZE_MB: Final[int] = 10
LOG_FILE_BACKUP_COUNT: Final[int] = 5

# Path limits
MAX_PATH_LENGTH: Final[int] = 260  # Windows limit
MAX_FILENAME_LENGTH: Final[int] = 255

# === Performance Benchmarking ===

# Benchmark iterations
MIN_BENCHMARK_ITERATIONS: Final[int] = 10
DEFAULT_BENCHMARK_ITERATIONS: Final[int] = 100
MAX_BENCHMARK_ITERATIONS: Final[int] = 10000

# Performance thresholds
TARGET_MEMORY_REDUCTION_FACTOR: Final[float] = 200.0  # 200x reduction target
TARGET_SPEEDUP_FACTOR: Final[float] = 10.0  # 10x speedup target
ACCEPTABLE_PERFORMANCE_DEGRADATION: Final[float] = 0.1  # 10% degradation acceptable

# === Docker/Kubernetes Constants ===

# Resource limits
DEFAULT_CONTAINER_MEMORY_MB: Final[int] = 512
MAX_CONTAINER_MEMORY_MB: Final[int] = 8192
DEFAULT_CONTAINER_CPU_CORES: Final[float] = 1.0
MAX_CONTAINER_CPU_CORES: Final[float] = 8.0

# Health check configuration
HEALTH_CHECK_INTERVAL_SEC: Final[int] = 30
HEALTH_CHECK_TIMEOUT_SEC: Final[int] = 10
HEALTH_CHECK_RETRIES: Final[int] = 3
STARTUP_PERIOD_SEC: Final[int] = 10

# === Monitoring Constants ===

# Metrics collection
METRICS_COLLECTION_INTERVAL_SEC: Final[int] = 15
METRICS_RETENTION_DAYS: Final[int] = 30
MAX_METRIC_LABELS: Final[int] = 10

# Alert thresholds
CPU_ALERT_THRESHOLD_PERCENT: Final[float] = 80.0
MEMORY_ALERT_THRESHOLD_PERCENT: Final[float] = 85.0
DISK_ALERT_THRESHOLD_PERCENT: Final[float] = 90.0
ERROR_RATE_ALERT_THRESHOLD_PERCENT: Final[float] = 1.0

# === Enums for Type Safety ===

class LogLevel(str, Enum):
    """Logging levels"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class Environment(str, Enum):
    """Application environments"""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TESTING = "testing"


class LatticeAlgorithm(str, Enum):
    """Available lattice algorithms"""
    DIJKSTRA = "dijkstra"
    CATALYTIC = "catalytic"
    BREADTH_FIRST = "bfs"
    DEPTH_FIRST = "dfs"
    A_STAR = "astar"


class WebhookEvent(str, Enum):
    """Webhook event types"""
    LATTICE_CREATED = "lattice.created"
    LATTICE_DELETED = "lattice.deleted"
    COMPUTATION_STARTED = "computation.started"
    COMPUTATION_COMPLETED = "computation.completed"
    COMPUTATION_FAILED = "computation.failed"
    ERROR_OCCURRED = "error.occurred"
    SYSTEM_STARTUP = "system.startup"
    SYSTEM_SHUTDOWN = "system.shutdown"


class HttpMethod(str, Enum):
    """HTTP methods"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class ContentType(str, Enum):
    """Content types"""
    JSON = "application/json"
    TEXT = "text/plain"
    HTML = "text/html"
    XML = "application/xml"
    FORM = "application/x-www-form-urlencoded"
    MULTIPART = "multipart/form-data"
    OCTET_STREAM = "application/octet-stream"


class StatusCode(IntEnum):
    """HTTP status codes"""
    # Success
    OK = 200
    CREATED = 201
    ACCEPTED = 202
    NO_CONTENT = 204

    # Redirection
    MOVED_PERMANENTLY = 301
    FOUND = 302
    NOT_MODIFIED = 304

    # Client errors
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    CONFLICT = 409
    UNPROCESSABLE_ENTITY = 422
    TOO_MANY_REQUESTS = 429

    # Server errors
    INTERNAL_SERVER_ERROR = 500
    NOT_IMPLEMENTED = 501
    BAD_GATEWAY = 502
    SERVICE_UNAVAILABLE = 503
    GATEWAY_TIMEOUT = 504


# === Validation Ranges ===

class ValidationRange:
    """Validation ranges for input parameters"""

    DIMENSIONS = range(MIN_DIMENSIONS, MAX_DIMENSIONS + 1)
    LATTICE_SIZE = range(MIN_LATTICE_SIZE, MAX_LATTICE_SIZE + 1)
    PORT = range(MIN_PORT, MAX_PORT + 1)
    RETRY_COUNT = range(MIN_WEBHOOK_RETRIES, MAX_WEBHOOK_RETRIES + 1)
    PAGE_SIZE = range(MIN_PAGE_SIZE, MAX_PAGE_SIZE + 1)


# === Time Constants ===

SECONDS_PER_MINUTE: Final[int] = 60
SECONDS_PER_HOUR: Final[int] = 3600
SECONDS_PER_DAY: Final[int] = 86400
MILLISECONDS_PER_SECOND: Final[int] = 1000
MICROSECONDS_PER_SECOND: Final[int] = 1_000_000
NANOSECONDS_PER_SECOND: Final[int] = 1_000_000_000

# === Export all constants ===

__all__ = [
    # Lattice constants
    'MIN_DIMENSIONS', 'MAX_DIMENSIONS', 'DEFAULT_DIMENSIONS',
    'MIN_LATTICE_SIZE', 'MAX_LATTICE_SIZE', 'DEFAULT_LATTICE_SIZE',
    'MIN_AUX_MEMORY_MB', 'MAX_AUX_MEMORY_MB', 'DEFAULT_AUX_MEMORY_MB',

    # GPU constants
    'CUDA_CORES_PER_SM', 'MAX_THREADS_PER_BLOCK', 'DEFAULT_BLOCK_SIZE',
    'MIN_GPU_MEMORY_MB', 'DEFAULT_GPU_MEMORY_LIMIT_MB',

    # API constants
    'DEFAULT_API_PORT', 'DEFAULT_WEBHOOK_PORT', 'DEFAULT_METRICS_PORT',
    'DEFAULT_RATE_LIMIT_PER_MINUTE', 'MAX_REQUEST_SIZE_MB',

    # Webhook constants
    'DEFAULT_WEBHOOK_RETRIES', 'DEFAULT_RETRY_DELAY_SEC',
    'WEBHOOK_DELIVERY_SUCCESS_CODES', 'WEBHOOK_DELIVERY_RETRY_CODES',

    # Database constants
    'DEFAULT_DB_POOL_SIZE', 'DEFAULT_DB_TIMEOUT_SEC',

    # Memory constants
    'DEFAULT_MEMORY_POOL_SIZE', 'MEMORY_ALIGNMENT_BYTES',
    'DEFAULT_CACHE_SIZE_MB', 'TARGET_MEMORY_REDUCTION_FACTOR',

    # Enums
    'LogLevel', 'Environment', 'LatticeAlgorithm', 'WebhookEvent',
    'HttpMethod', 'ContentType', 'StatusCode',

    # Validation ranges
    'ValidationRange',
]
