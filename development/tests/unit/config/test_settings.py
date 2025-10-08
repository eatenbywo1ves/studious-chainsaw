"""
Unit tests for configuration management system
Tests Pydantic settings, validation, and environment variable loading
"""

import os
from unittest.mock import patch
from pathlib import Path

from libs.config.settings import (
    CatalyticSettings,
    LatticeConfig,
    GPUConfig,
    APIConfig,
    WebhookConfig,
    StorageConfig,
    MonitoringConfig,
    Environment,
    GPUBackend,
    StorageBackend,
    get_settings,
    reload_settings
)


class TestEnvironmentEnum:
    """Test Environment enumeration"""

    def test_environment_values(self):
        """Test environment enum values"""
        assert Environment.DEVELOPMENT == "development"
        assert Environment.TESTING == "testing"
        assert Environment.STAGING == "staging"
        assert Environment.PRODUCTION == "production"


class TestGPUBackendEnum:
    """Test GPU backend enumeration"""

    def test_gpu_backend_values(self):
        """Test GPU backend enum values"""
        assert GPUBackend.CUDA == "cuda"
        assert GPUBackend.CUPY == "cupy"
        assert GPUBackend.PYTORCH == "pytorch"
        assert GPUBackend.NUMBA == "numba"
        assert GPUBackend.CPU == "cpu"


class TestStorageBackendEnum:
    """Test storage backend enumeration"""

    def test_storage_backend_values(self):
        """Test storage backend enum values"""
        assert StorageBackend.MEMORY == "memory"
        assert StorageBackend.REDIS == "redis"
        assert StorageBackend.POSTGRES == "postgres"
        assert StorageBackend.FILESYSTEM == "filesystem"


class TestLatticeConfig:
    """Test lattice-specific configuration"""

    def test_default_values(self):
        """Test default lattice configuration values"""
        config = LatticeConfig()

        assert config.min_dimensions == 1
        assert config.max_dimensions == 10
        assert config.default_dimensions == 4
        assert config.min_lattice_size == 2
        assert config.max_lattice_size == 100
        assert config.default_lattice_size == 10
        assert config.min_aux_memory_mb == 0.1
        assert config.max_aux_memory_mb == 1024.0
        assert config.default_aux_memory_mb == 10.0
        assert config.max_path_finding_timeout == 60.0
        assert config.default_computation_timeout == 30.0
        assert config.default_path_algorithm == "dijkstra"
        assert config.enable_caching is True
        assert config.cache_ttl_seconds == 3600

    @patch.dict(os.environ, {
        'LATTICE_MIN_DIMENSIONS': '2',
        'LATTICE_MAX_DIMENSIONS': '20',
        'LATTICE_DEFAULT_DIMENSIONS': '5',
        'LATTICE_ENABLE_CACHING': 'false'
    })
    def test_env_var_override(self):
        """Test environment variable override"""
        config = LatticeConfig()

        assert config.min_dimensions == 2
        assert config.max_dimensions == 20
        assert config.default_dimensions == 5
        assert config.enable_caching is False

    def test_validation_constraints(self):
        """Test validation constraints"""
        # Valid config
        config = LatticeConfig(
            min_dimensions=1,
            max_dimensions=15,
            min_lattice_size=1
        )
        assert config.min_dimensions == 1

        # Test field validation would happen at instantiation
        # Pydantic v2 validates at assignment

    def test_parallel_cores_default(self):
        """Test parallel cores default to CPU count"""
        config = LatticeConfig()
        assert config.parallel_cores > 0
        assert config.parallel_cores == os.cpu_count()


class TestGPUConfig:
    """Test GPU-specific configuration"""

    def test_default_values(self):
        """Test default GPU configuration values"""
        config = GPUConfig()

        assert config.preferred_backend == GPUBackend.CUDA
        assert GPUBackend.CUPY in config.fallback_backends
        assert GPUBackend.CPU in config.fallback_backends
        assert config.cuda_device_id == 0
        assert config.max_threads_per_block == 256
        assert config.default_block_size == 128
        assert config.min_gpu_memory_mb == 512
        assert config.max_gpu_memory_mb == 8192
        assert config.memory_safety_margin == 0.9
        assert config.enable_gpu_profiling is False
        assert config.gpu_timeout_seconds == 30.0
        assert config.auto_select_device is True

    @patch.dict(os.environ, {
        'GPU_PREFERRED_BACKEND': 'pytorch',
        'GPU_CUDA_DEVICE_ID': '2',
        'GPU_ENABLE_GPU_PROFILING': 'true',
        'GPU_AUTO_SELECT_DEVICE': 'false'
    })
    def test_env_var_override(self):
        """Test GPU config environment variable override"""
        config = GPUConfig()

        assert config.preferred_backend == GPUBackend.PYTORCH
        assert config.cuda_device_id == 2
        assert config.enable_gpu_profiling is True
        assert config.auto_select_device is False

    def test_fallback_backends_order(self):
        """Test fallback backends priority order"""
        config = GPUConfig()
        fallbacks = config.fallback_backends

        # CPU should always be last fallback
        assert fallbacks[-1] == GPUBackend.CPU
        # Should have multiple fallbacks
        assert len(fallbacks) > 1


class TestAPIConfig:
    """Test API server configuration"""

    def test_default_values(self):
        """Test default API configuration values"""
        config = APIConfig()

        assert config.host == "0.0.0.0"
        assert config.port == 8080
        assert config.workers == 4
        assert config.reload is False
        assert config.max_lattices == 100
        assert config.max_request_size_mb == 10
        assert config.request_timeout_seconds == 300
        assert config.cache_enabled is True
        assert config.cache_size == 1024
        assert config.cache_ttl_seconds == 3600
        assert config.enable_cors is True
        assert config.cors_origins == ["*"]
        assert config.enable_rate_limiting is True
        assert config.rate_limit_per_minute == 60
        assert config.enable_metrics is True
        assert config.metrics_port == 9090
        assert config.enable_health_check is True

    @patch.dict(os.environ, {
        'API_HOST': 'localhost',
        'API_PORT': '8888',
        'API_WORKERS': '8',
        'API_RELOAD': 'true',
        'API_MAX_LATTICES': '200',
        'API_CACHE_ENABLED': 'false'
    })
    def test_env_var_override(self):
        """Test API config environment variable override"""
        config = APIConfig()

        assert config.host == "localhost"
        assert config.port == 8888
        assert config.workers == 8
        assert config.reload is True
        assert config.max_lattices == 200
        assert config.cache_enabled is False


class TestWebhookConfig:
    """Test webhook configuration"""

    def test_default_values(self):
        """Test default webhook configuration values"""
        config = WebhookConfig()

        assert config.webhook_enabled is True
        assert config.webhook_port == 8085
        assert config.max_retries == 3
        assert config.retry_delay_seconds == 60
        assert config.delivery_timeout_seconds == 30
        assert config.require_signature is True
        assert config.signature_algorithm == "hmac-sha256"
        assert config.max_webhooks_per_event == 10
        assert config.max_payload_size_kb == 100

    @patch.dict(os.environ, {
        'WEBHOOK_ENABLED': 'false',
        'WEBHOOK_PORT': '9000',
        'WEBHOOK_MAX_RETRIES': '5',
        'WEBHOOK_REQUIRE_SIGNATURE': 'false'
    })
    def test_env_var_override(self):
        """Test webhook config environment variable override"""
        config = WebhookConfig()

        assert config.webhook_enabled is False
        assert config.webhook_port == 9000
        assert config.max_retries == 5
        assert config.require_signature is False


class TestStorageConfig:
    """Test storage backend configuration"""

    def test_default_values(self):
        """Test default storage configuration values"""
        config = StorageConfig()

        assert config.backend == StorageBackend.MEMORY
        assert config.memory_max_entries == 1000
        assert config.memory_eviction_policy == "lru"
        assert config.redis_url is None
        assert config.redis_password is None
        assert config.redis_db == 0
        assert config.redis_pool_size == 10
        assert config.postgres_url is None
        assert config.postgres_pool_size == 20
        assert isinstance(config.filesystem_base_path, Path)

    @patch.dict(os.environ, {
        'STORAGE_BACKEND': 'redis',
        'STORAGE_REDIS_URL': 'redis://localhost:6379',
        'STORAGE_REDIS_PASSWORD': 'secret',
        'STORAGE_REDIS_DB': '1'
    })
    def test_redis_config(self):
        """Test Redis storage configuration"""
        config = StorageConfig()

        assert config.backend == StorageBackend.REDIS
        assert config.redis_url == "redis://localhost:6379"
        assert config.redis_password == "secret"
        assert config.redis_db == 1

    def test_filesystem_path_creation(self):
        """Test filesystem base path is valid"""
        config = StorageConfig()
        assert config.filesystem_base_path.is_absolute()
        assert ".catalytic" in str(config.filesystem_base_path)


class TestMonitoringConfig:
    """Test monitoring configuration"""

    def test_default_values(self):
        """Test default monitoring configuration values"""
        config = MonitoringConfig()

        assert config.log_level == "INFO"
        assert config.log_format == "json"
        assert config.log_file_path is None
        assert config.enable_metrics is True
        assert config.metrics_export_interval == 60
        assert config.enable_tracing is False
        assert config.tracing_endpoint is None
        assert config.tracing_sample_rate == 0.1

    @patch.dict(os.environ, {
        'MONITORING_LOG_LEVEL': 'DEBUG',
        'MONITORING_LOG_FORMAT': 'text',
        'MONITORING_ENABLE_TRACING': 'true',
        'MONITORING_TRACING_SAMPLE_RATE': '0.5'
    })
    def test_env_var_override(self):
        """Test monitoring config environment variable override"""
        config = MonitoringConfig()

        assert config.log_level == "DEBUG"
        assert config.log_format == "text"
        assert config.enable_tracing is True
        assert config.tracing_sample_rate == 0.5


class TestCatalyticSettings:
    """Test main settings class"""

    def test_default_values(self):
        """Test default main settings values"""
        settings = CatalyticSettings()

        assert settings.environment == Environment.DEVELOPMENT
        assert settings.debug is False
        assert settings.app_name == "Catalytic Computing System"
        assert settings.app_version == "1.0.0"
        assert isinstance(settings.lattice, LatticeConfig)
        assert isinstance(settings.gpu, GPUConfig)
        assert isinstance(settings.api, APIConfig)
        assert isinstance(settings.webhook, WebhookConfig)
        assert isinstance(settings.storage, StorageConfig)
        assert isinstance(settings.monitoring, MonitoringConfig)
        assert isinstance(settings.base_path, Path)
        assert isinstance(settings.data_path, Path)

    @patch.dict(os.environ, {
        'CATALYTIC_ENVIRONMENT': 'production',
        'CATALYTIC_DEBUG': 'true',
        'CATALYTIC_APP_NAME': 'Test App',
        'CATALYTIC_APP_VERSION': '2.0.0'
    })
    def test_env_var_override(self):
        """Test main settings environment variable override"""
        settings = CatalyticSettings()

        assert settings.environment == Environment.PRODUCTION
        assert settings.debug is True
        assert settings.app_name == "Test App"
        assert settings.app_version == "2.0.0"

    def test_debug_auto_set_in_development(self):
        """Test debug is auto-set in development environment"""
        settings = CatalyticSettings(environment=Environment.DEVELOPMENT)
        assert settings.debug is True

    @patch('apps.catalytic.gpu.base.torch')
    def test_get_effective_gpu_backend_cuda_available(self, mock_torch):
        """Test getting effective GPU backend when CUDA available"""
        mock_torch.cuda.is_available.return_value = True

        settings = CatalyticSettings()
        backend = settings.get_effective_gpu_backend()

        assert backend == GPUBackend.CUDA

    def test_get_effective_gpu_backend_cpu_fallback(self):
        """Test CPU fallback when no GPU available"""
        with patch('apps.catalytic.gpu.base.torch', None):
            with patch('apps.catalytic.gpu.base.cupy', None):
                settings = CatalyticSettings()
                backend = settings.get_effective_gpu_backend()

                assert backend == GPUBackend.CPU

    def test_to_dict(self):
        """Test converting settings to dictionary"""
        settings = CatalyticSettings()
        settings_dict = settings.to_dict()

        assert isinstance(settings_dict, dict)
        assert 'environment' in settings_dict
        assert 'lattice' in settings_dict
        assert 'gpu' in settings_dict

    @patch('pathlib.Path.mkdir')
    def test_path_creation(self, mock_mkdir):
        """Test that required paths are created"""
        CatalyticSettings()

        # Paths should be created during validation
        assert mock_mkdir.called


class TestSettingsFunctions:
    """Test settings utility functions"""

    def test_get_settings_returns_singleton(self):
        """Test get_settings returns cached instance"""
        settings1 = get_settings()
        settings2 = get_settings()

        assert settings1 is settings2

    def test_reload_settings_clears_cache(self):
        """Test reload_settings creates new instance"""
        settings1 = get_settings()
        settings2 = reload_settings()
        settings3 = get_settings()

        assert settings1 is not settings2
        assert settings2 is settings3

    @patch.dict(os.environ, {'CATALYTIC_APP_NAME': 'Initial'})
    def test_settings_reflect_env_changes_after_reload(self):
        """Test settings reflect environment changes after reload"""
        settings1 = reload_settings()
        assert settings1.app_name == "Initial"

        # Change environment
        os.environ['CATALYTIC_APP_NAME'] = 'Updated'

        settings2 = reload_settings()
        assert settings2.app_name == "Updated"
