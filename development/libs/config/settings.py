"""
Centralized configuration management using Pydantic Settings
Provides type-safe configuration with validation and environment variable support
"""

import os
from typing import Optional, List, Dict, Any
from pathlib import Path
from functools import lru_cache
from enum import Enum

try:
    from pydantic_settings import BaseSettings
    from pydantic import Field, field_validator
except ImportError:
    # Fallback for Pydantic v1
    from pydantic import BaseSettings, Field, validator as field_validator


class Environment(str, Enum):
    """Application environment types"""
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"


class GPUBackend(str, Enum):
    """Available GPU backend implementations"""
    CUDA = "cuda"
    CUPY = "cupy"
    PYTORCH = "pytorch"
    NUMBA = "numba"
    CPU = "cpu"  # Fallback


class StorageBackend(str, Enum):
    """Available storage backends"""
    MEMORY = "memory"
    REDIS = "redis"
    POSTGRES = "postgres"
    FILESYSTEM = "filesystem"


class LatticeConfig(BaseSettings):
    """Lattice-specific configuration"""

    # Dimension constraints
    min_dimensions: int = Field(1, ge=1, description="Minimum lattice dimensions")
    max_dimensions: int = Field(10, le=20, description="Maximum lattice dimensions")
    default_dimensions: int = Field(4, ge=1, le=10, description="Default dimensions")

    # Size constraints
    min_lattice_size: int = Field(2, ge=1, description="Minimum lattice size per dimension")
    max_lattice_size: int = Field(100, le=1000, description="Maximum lattice size per dimension")
    default_lattice_size: int = Field(10, ge=2, le=100, description="Default lattice size")

    # Memory settings
    min_aux_memory_mb: float = Field(0.1, ge=0.01, description="Minimum auxiliary memory in MB")
    max_aux_memory_mb: float = Field(1024.0, le=10240.0, description="Maximum auxiliary memory in MB")
    default_aux_memory_mb: float = Field(10.0, ge=0.1, le=1024.0, description="Default auxiliary memory")

    # Performance settings
    max_path_finding_timeout: float = Field(60.0, ge=1.0, description="Maximum pathfinding timeout in seconds")
    default_computation_timeout: float = Field(30.0, ge=1.0, description="Default computation timeout")
    parallel_cores: int = Field(default_factory=lambda: os.cpu_count() or 4, description="Number of parallel cores")

    # Algorithm settings
    default_path_algorithm: str = Field("dijkstra", description="Default pathfinding algorithm")
    enable_caching: bool = Field(True, description="Enable result caching")
    cache_ttl_seconds: int = Field(3600, ge=0, description="Cache TTL in seconds")

    class Config:
        env_prefix = "LATTICE_"


class GPUConfig(BaseSettings):
    """GPU-specific configuration"""

    # Backend selection
    preferred_backend: GPUBackend = Field(GPUBackend.CUDA, description="Preferred GPU backend")
    fallback_backends: List[GPUBackend] = Field(
        [GPUBackend.CUPY, GPUBackend.PYTORCH, GPUBackend.NUMBA, GPUBackend.CPU],
        description="Fallback backends in priority order"
    )

    # CUDA settings
    cuda_device_id: int = Field(0, ge=0, description="CUDA device ID to use")
    max_threads_per_block: int = Field(256, ge=32, le=1024, description="Maximum threads per CUDA block")
    default_block_size: int = Field(128, ge=32, le=512, description="Default CUDA block size")

    # Memory settings
    min_gpu_memory_mb: int = Field(512, ge=256, description="Minimum required GPU memory")
    max_gpu_memory_mb: int = Field(8192, le=65536, description="Maximum GPU memory to use")
    memory_safety_margin: float = Field(0.9, ge=0.5, le=0.95, description="GPU memory safety margin")

    # Performance settings
    enable_gpu_profiling: bool = Field(False, description="Enable GPU performance profiling")
    gpu_timeout_seconds: float = Field(30.0, ge=1.0, description="GPU operation timeout")
    auto_select_device: bool = Field(True, description="Automatically select best GPU device")

    # Smart Routing Configuration
    enable_smart_routing: bool = Field(True, description="Enable smart GPU/CPU operation routing")
    gpu_threshold_elements: int = Field(1000, ge=10, description="Min elements for GPU consideration")
    gpu_optimal_threshold: int = Field(10000, ge=100, description="Elements for optimal GPU performance")
    routing_overhead_tolerance_ms: float = Field(10.0, ge=0.1, description="Max acceptable routing overhead")

    @field_validator('preferred_backend')
    @classmethod
    def validate_backend_availability(cls, v):
        """Validate that the preferred backend is available"""
        # This would check actual availability in production
        return v

    class Config:
        env_prefix = "GPU_"


class APIConfig(BaseSettings):
    """API server configuration"""

    # Server settings
    host: str = Field("0.0.0.0", description="API server host")
    port: int = Field(8080, ge=1, le=65535, description="API server port")
    workers: int = Field(4, ge=1, le=32, description="Number of API workers")
    reload: bool = Field(False, description="Enable auto-reload in development")

    # Limits
    max_lattices: int = Field(100, ge=1, le=10000, description="Maximum concurrent lattices")
    max_request_size_mb: int = Field(10, ge=1, le=100, description="Maximum request size in MB")
    request_timeout_seconds: int = Field(300, ge=10, description="Request timeout in seconds")

    # Caching
    cache_enabled: bool = Field(True, description="Enable API response caching")
    cache_size: int = Field(1024, ge=0, description="Maximum cache entries")
    cache_ttl_seconds: int = Field(3600, ge=0, description="Cache TTL in seconds")

    # Security
    enable_cors: bool = Field(True, description="Enable CORS")
    cors_origins: List[str] = Field(["*"], description="Allowed CORS origins")
    enable_rate_limiting: bool = Field(True, description="Enable rate limiting")
    rate_limit_per_minute: int = Field(60, ge=1, description="Requests per minute limit")

    # Monitoring
    enable_metrics: bool = Field(True, description="Enable Prometheus metrics")
    metrics_port: int = Field(9090, ge=1, le=65535, description="Metrics server port")
    enable_health_check: bool = Field(True, description="Enable health check endpoint")

    class Config:
        env_prefix = "API_"


class WebhookConfig(BaseSettings):
    """Webhook configuration"""

    # Server settings
    webhook_enabled: bool = Field(True, description="Enable webhook system")
    webhook_port: int = Field(8085, ge=1, le=65535, description="Webhook server port")

    # Delivery settings
    max_retries: int = Field(3, ge=0, le=10, description="Maximum delivery retries")
    retry_delay_seconds: int = Field(60, ge=1, description="Retry delay in seconds")
    delivery_timeout_seconds: int = Field(30, ge=1, description="Delivery timeout")

    # Security
    require_signature: bool = Field(True, description="Require webhook signatures")
    signature_algorithm: str = Field("hmac-sha256", description="Signature algorithm")

    # Limits
    max_webhooks_per_event: int = Field(10, ge=1, description="Max webhooks per event")
    max_payload_size_kb: int = Field(100, ge=1, le=1024, description="Max payload size in KB")

    class Config:
        env_prefix = "WEBHOOK_"


class StorageConfig(BaseSettings):
    """Storage backend configuration"""

    # Backend selection
    backend: StorageBackend = Field(StorageBackend.MEMORY, description="Storage backend type")

    # Memory storage
    memory_max_entries: int = Field(1000, ge=1, description="Max entries for memory storage")
    memory_eviction_policy: str = Field("lru", description="Eviction policy (lru, lfu, fifo)")

    # Redis settings
    redis_url: Optional[str] = Field(None, description="Redis connection URL")
    redis_password: Optional[str] = Field(None, description="Redis password")
    redis_db: int = Field(0, ge=0, description="Redis database number")
    redis_pool_size: int = Field(10, ge=1, description="Redis connection pool size")

    # PostgreSQL settings
    postgres_url: Optional[str] = Field(None, description="PostgreSQL connection URL")
    postgres_pool_size: int = Field(20, ge=1, description="PostgreSQL connection pool size")

    # Filesystem settings
    filesystem_base_path: Path = Field(
        default_factory=lambda: Path.home() / ".catalytic" / "storage",
        description="Base path for filesystem storage"
    )

    class Config:
        env_prefix = "STORAGE_"


class MonitoringConfig(BaseSettings):
    """Monitoring and observability configuration"""

    # Logging
    log_level: str = Field("INFO", description="Logging level")
    log_format: str = Field("json", description="Log format (json, text)")
    log_file_path: Optional[Path] = Field(None, description="Log file path")

    # Metrics
    enable_metrics: bool = Field(True, description="Enable metrics collection")
    metrics_export_interval: int = Field(60, ge=1, description="Metrics export interval in seconds")

    # Tracing
    enable_tracing: bool = Field(False, description="Enable distributed tracing")
    tracing_endpoint: Optional[str] = Field(None, description="Tracing collector endpoint")
    tracing_sample_rate: float = Field(0.1, ge=0.0, le=1.0, description="Tracing sample rate")

    class Config:
        env_prefix = "MONITORING_"


class CatalyticSettings(BaseSettings):
    """Main configuration class that combines all settings"""

    # Environment
    environment: Environment = Field(Environment.DEVELOPMENT, description="Application environment")
    debug: bool = Field(False, description="Enable debug mode")

    # Application info
    app_name: str = Field("Catalytic Computing System", description="Application name")
    app_version: str = Field("1.0.0", description="Application version")

    # Sub-configurations
    lattice: LatticeConfig = Field(default_factory=LatticeConfig)
    gpu: GPUConfig = Field(default_factory=GPUConfig)
    api: APIConfig = Field(default_factory=APIConfig)
    webhook: WebhookConfig = Field(default_factory=WebhookConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    monitoring: MonitoringConfig = Field(default_factory=MonitoringConfig)

    # Paths
    base_path: Path = Field(default_factory=Path.cwd, description="Base application path")
    data_path: Path = Field(
        default_factory=lambda: Path.home() / ".catalytic" / "data",
        description="Data storage path"
    )

    @field_validator('debug')
    @classmethod
    def set_debug_from_env(cls, v, info):
        """Set debug based on environment"""
        if info.data.get('environment') == Environment.DEVELOPMENT:
            return True
        return v

    @field_validator('data_path', 'base_path')
    @classmethod
    def ensure_paths_exist(cls, v):
        """Ensure required paths exist"""
        v.mkdir(parents=True, exist_ok=True)
        return v

    def get_effective_gpu_backend(self) -> GPUBackend:
        """Get the effective GPU backend to use based on availability"""
        # In production, this would check actual availability
        backends_to_try = [self.gpu.preferred_backend] + self.gpu.fallback_backends

        for backend in backends_to_try:
            if backend == GPUBackend.CUDA:
                try:
                    import torch
                    if torch.cuda.is_available():
                        return backend
                except ImportError:
                    pass
            elif backend == GPUBackend.CUPY:
                try:
                    import cupy
                    return backend
                except ImportError:
                    pass
            elif backend == GPUBackend.CPU:
                return backend  # CPU is always available

        return GPUBackend.CPU

    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary"""
        return self.dict(exclude_unset=True)

    class Config:
        env_prefix = "CATALYTIC_"
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

        # Allow extra fields for forward compatibility
        extra = "ignore"


@lru_cache()
def get_settings() -> CatalyticSettings:
    """
    Get cached settings instance (singleton pattern)

    Returns:
        CatalyticSettings: The settings instance
    """
    return CatalyticSettings()


def reload_settings() -> CatalyticSettings:
    """
    Force reload settings (clears cache)

    Returns:
        CatalyticSettings: Fresh settings instance
    """
    get_settings.cache_clear()
    return get_settings()


# Export convenience function
settings = get_settings
