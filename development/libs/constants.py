"""
Application-wide constants
Centralized location for magic numbers, timeouts, and configuration defaults
"""

from typing import Final

# ============================================================================
# SSH Monitoring Constants
# ============================================================================

# Connection timeouts
SSH_DEFAULT_CONNECTION_TIMEOUT_SECONDS: Final[int] = 10
SSH_DEFAULT_CHECK_INTERVAL_SECONDS: Final[int] = 30
SSH_RESTART_WAIT_SECONDS: Final[int] = 3
SSH_RESTART_TIMEOUT_SECONDS: Final[int] = 10

# Retry configuration
SSH_DEFAULT_MAX_RETRY_ATTEMPTS: Final[int] = 5
SSH_DEFAULT_BACKOFF_MULTIPLIER: Final[int] = 2
SSH_MAX_BACKOFF_SECONDS: Final[int] = 300

# Ports
SSH_DEFAULT_PORT: Final[int] = 22
SSH_TERMUX_DEFAULT_PORT: Final[int] = 8022


# ============================================================================
# GPU/CUDA Constants
# ============================================================================

# Memory thresholds (in MB)
GPU_MIN_MEMORY_MB: Final[int] = 512
GPU_MAX_MEMORY_MB: Final[int] = 8192
GPU_MEMORY_SAFETY_MARGIN: Final[float] = 0.9

# CUDA configuration
CUDA_DEFAULT_DEVICE_ID: Final[int] = 0
CUDA_MAX_THREADS_PER_BLOCK: Final[int] = 256
CUDA_DEFAULT_BLOCK_SIZE: Final[int] = 128

# Performance thresholds
GPU_THRESHOLD_ELEMENTS: Final[int] = 1000
GPU_OPTIMAL_THRESHOLD_ELEMENTS: Final[int] = 10000
GPU_ROUTING_OVERHEAD_TOLERANCE_MS: Final[float] = 10.0

# Timeouts
GPU_OPERATION_TIMEOUT_SECONDS: Final[float] = 30.0


# ============================================================================
# Lattice Constants
# ============================================================================

# Dimension constraints
LATTICE_MIN_DIMENSIONS: Final[int] = 1
LATTICE_MAX_DIMENSIONS: Final[int] = 20
LATTICE_DEFAULT_DIMENSIONS: Final[int] = 4

# Size constraints
LATTICE_MIN_SIZE: Final[int] = 2
LATTICE_MAX_SIZE: Final[int] = 1000
LATTICE_DEFAULT_SIZE: Final[int] = 10

# Memory configuration
LATTICE_MIN_AUX_MEMORY_MB: Final[float] = 0.1
LATTICE_MAX_AUX_MEMORY_MB: Final[float] = 10240.0
LATTICE_DEFAULT_AUX_MEMORY_MB: Final[float] = 10.0

# Timeouts
LATTICE_MAX_PATH_FINDING_TIMEOUT_SECONDS: Final[float] = 60.0
LATTICE_DEFAULT_COMPUTATION_TIMEOUT_SECONDS: Final[float] = 30.0

# Cache settings
LATTICE_DEFAULT_CACHE_TTL_SECONDS: Final[int] = 3600


# ============================================================================
# API Constants
# ============================================================================

# Server defaults
API_DEFAULT_HOST: Final[str] = "0.0.0.0"
API_DEFAULT_PORT: Final[int] = 8080
API_DEFAULT_WORKERS: Final[int] = 4

# Limits
API_MAX_CONCURRENT_LATTICES: Final[int] = 100
API_MAX_REQUEST_SIZE_MB: Final[int] = 10
API_REQUEST_TIMEOUT_SECONDS: Final[int] = 300

# Rate limiting
API_DEFAULT_RATE_LIMIT_PER_MINUTE: Final[int] = 60

# Metrics
API_METRICS_PORT: Final[int] = 9090
API_METRICS_EXPORT_INTERVAL_SECONDS: Final[int] = 60


# ============================================================================
# Webhook Constants
# ============================================================================

# Server configuration
WEBHOOK_DEFAULT_PORT: Final[int] = 8085

# Delivery settings
WEBHOOK_MAX_RETRIES: Final[int] = 3
WEBHOOK_RETRY_DELAY_SECONDS: Final[int] = 60
WEBHOOK_DELIVERY_TIMEOUT_SECONDS: Final[int] = 30

# Limits
WEBHOOK_MAX_PER_EVENT: Final[int] = 10
WEBHOOK_MAX_PAYLOAD_SIZE_KB: Final[int] = 100

# Signature algorithms
WEBHOOK_SIGNATURE_ALGORITHM: Final[str] = "hmac-sha256"


# ============================================================================
# Storage Constants
# ============================================================================

# Memory storage limits
STORAGE_MEMORY_MAX_ENTRIES: Final[int] = 1000

# Redis configuration
REDIS_DEFAULT_DB: Final[int] = 0
REDIS_DEFAULT_POOL_SIZE: Final[int] = 10

# PostgreSQL configuration
POSTGRES_DEFAULT_POOL_SIZE: Final[int] = 20


# ============================================================================
# Logging Constants
# ============================================================================

# Default log levels
LOG_LEVEL_DEBUG: Final[str] = "DEBUG"
LOG_LEVEL_INFO: Final[str] = "INFO"
LOG_LEVEL_WARNING: Final[str] = "WARNING"
LOG_LEVEL_ERROR: Final[str] = "ERROR"
LOG_LEVEL_CRITICAL: Final[str] = "CRITICAL"

# Log formats
LOG_FORMAT_JSON: Final[str] = "json"
LOG_FORMAT_TEXT: Final[str] = "text"

# Default log level
DEFAULT_LOG_LEVEL: Final[str] = LOG_LEVEL_INFO


# ============================================================================
# Validation Constants
# ============================================================================

# Numerical precision
FLOAT_COMPARISON_EPSILON: Final[float] = 1e-8
NUMERICAL_STABILITY_EPSILON: Final[float] = 1e-10

# String limits
MAX_NAME_LENGTH: Final[int] = 255
MAX_DESCRIPTION_LENGTH: Final[int] = 1000

# Array limits
MAX_ARRAY_SIZE: Final[int] = 1_000_000_000  # 1 billion elements


# ============================================================================
# Testing Constants
# ============================================================================

# Test timeouts
TEST_DEFAULT_TIMEOUT_SECONDS: Final[int] = 10
TEST_INTEGRATION_TIMEOUT_SECONDS: Final[int] = 60
TEST_PERFORMANCE_TIMEOUT_SECONDS: Final[int] = 300

# Test data sizes
TEST_SMALL_ARRAY_SIZE: Final[int] = 100
TEST_MEDIUM_ARRAY_SIZE: Final[int] = 1000
TEST_LARGE_ARRAY_SIZE: Final[int] = 10000

# Benchmarking
BENCHMARK_WARMUP_ITERATIONS: Final[int] = 3
BENCHMARK_MEASUREMENT_ITERATIONS: Final[int] = 10


# ============================================================================
# Performance Benchmarks (Measured on GTX 1080)
# ============================================================================

# GPU vs CPU speedup thresholds
EXPECTED_MATMUL_SPEEDUP: Final[float] = 20.0  # 21.22x measured
EXPECTED_GPU_TFLOPS: Final[float] = 7.0  # 7.24 TFLOPS measured

# Operation-specific thresholds
SMALL_OPERATION_THRESHOLD: Final[int] = 1000  # GPU overhead dominates
LARGE_OPERATION_THRESHOLD: Final[int] = 100000  # GPU excels


# ============================================================================
# File Paths (Relative to project root)
# ============================================================================

# Configuration paths
CONFIG_DIR: Final[str] = "config"
LOGS_DIR: Final[str] = "logs"
DATA_DIR: Final[str] = "data"
CACHE_DIR: Final[str] = "cache"

# Test paths
TEST_DIR: Final[str] = "tests"
TEST_FIXTURES_DIR: Final[str] = "tests/fixtures"
TEST_OUTPUT_DIR: Final[str] = "tests/output"


# ============================================================================
# Version Information
# ============================================================================

# Supported versions
MIN_PYTHON_VERSION: Final[tuple] = (3, 12)
MAX_PYTHON_VERSION: Final[tuple] = (3, 13)

# CUDA versions
REQUIRED_CUDA_VERSION: Final[str] = "12.1"
SUPPORTED_CUDA_VERSIONS: Final[list[str]] = ["12.1", "12.2", "12.3", "12.4"]

# Library versions
PYTORCH_MIN_VERSION: Final[str] = "2.5.0"
CUPY_MIN_VERSION: Final[str] = "13.0.0"
NUMPY_MIN_VERSION: Final[str] = "2.0.0"


# ============================================================================
# Environment Variables
# ============================================================================

# CUDA environment
ENV_CUDA_PATH: Final[str] = "CUDA_PATH"
ENV_CUDA_HOME: Final[str] = "CUDA_HOME"
ENV_CUDA_VISIBLE_DEVICES: Final[str] = "CUDA_VISIBLE_DEVICES"

# Application environment
ENV_APP_ENVIRONMENT: Final[str] = "APP_ENVIRONMENT"
ENV_DEBUG_MODE: Final[str] = "DEBUG_MODE"
ENV_AUTO_INIT_CUDA: Final[str] = "AUTO_INIT_CUDA"


# ============================================================================
# HTTP Status Codes (Commonly Used)
# ============================================================================

HTTP_OK: Final[int] = 200
HTTP_CREATED: Final[int] = 201
HTTP_ACCEPTED: Final[int] = 202
HTTP_NO_CONTENT: Final[int] = 204

HTTP_BAD_REQUEST: Final[int] = 400
HTTP_UNAUTHORIZED: Final[int] = 401
HTTP_FORBIDDEN: Final[int] = 403
HTTP_NOT_FOUND: Final[int] = 404
HTTP_TIMEOUT: Final[int] = 408
HTTP_CONFLICT: Final[int] = 409
HTTP_TOO_MANY_REQUESTS: Final[int] = 429

HTTP_INTERNAL_ERROR: Final[int] = 500
HTTP_SERVICE_UNAVAILABLE: Final[int] = 503
HTTP_GATEWAY_TIMEOUT: Final[int] = 504


# ============================================================================
# Character Encoding
# ============================================================================

DEFAULT_ENCODING: Final[str] = "utf-8"
FALLBACK_ENCODING: Final[str] = "latin-1"


# ============================================================================
# Export all constants
# ============================================================================

__all__ = [
    # SSH
    "SSH_DEFAULT_CONNECTION_TIMEOUT_SECONDS",
    "SSH_DEFAULT_CHECK_INTERVAL_SECONDS",
    "SSH_RESTART_WAIT_SECONDS",
    "SSH_RESTART_TIMEOUT_SECONDS",
    "SSH_DEFAULT_MAX_RETRY_ATTEMPTS",
    "SSH_DEFAULT_BACKOFF_MULTIPLIER",
    "SSH_MAX_BACKOFF_SECONDS",
    "SSH_DEFAULT_PORT",
    "SSH_TERMUX_DEFAULT_PORT",
    # GPU/CUDA
    "GPU_MIN_MEMORY_MB",
    "GPU_MAX_MEMORY_MB",
    "GPU_MEMORY_SAFETY_MARGIN",
    "CUDA_DEFAULT_DEVICE_ID",
    "CUDA_MAX_THREADS_PER_BLOCK",
    "CUDA_DEFAULT_BLOCK_SIZE",
    "GPU_THRESHOLD_ELEMENTS",
    "GPU_OPTIMAL_THRESHOLD_ELEMENTS",
    "GPU_ROUTING_OVERHEAD_TOLERANCE_MS",
    "GPU_OPERATION_TIMEOUT_SECONDS",
    # Lattice
    "LATTICE_MIN_DIMENSIONS",
    "LATTICE_MAX_DIMENSIONS",
    "LATTICE_DEFAULT_DIMENSIONS",
    "LATTICE_MIN_SIZE",
    "LATTICE_MAX_SIZE",
    "LATTICE_DEFAULT_SIZE",
    # Validation
    "FLOAT_COMPARISON_EPSILON",
    "NUMERICAL_STABILITY_EPSILON",
    # Testing
    "TEST_DEFAULT_TIMEOUT_SECONDS",
    "BENCHMARK_WARMUP_ITERATIONS",
    "BENCHMARK_MEASUREMENT_ITERATIONS",
]
