"""
Configuration module for Director Agent
"""

import os
from typing import Dict, Any
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RedisConfig:
    host: str = "localhost"
    port: int = 6379
    db: int = 0
    password: str = None
    ssl: bool = False
    
    @property
    def url(self) -> str:
        protocol = "rediss" if self.ssl else "redis"
        auth = f":{self.password}@" if self.password else ""
        return f"{protocol}://{auth}{self.host}:{self.port}/{self.db}"


@dataclass
class AgentConfig:
    max_concurrent_tasks: int = 10
    health_check_interval: int = 30
    task_timeout: int = 300
    max_retries: int = 3
    heartbeat_interval: int = 60


@dataclass
class QualityConfig:
    min_visual_quality: float = 0.7
    min_audio_quality: float = 0.6
    min_consistency_score: float = 0.75
    min_overall_score: float = 0.7
    max_file_size_mb: int = 500
    
    # Supported formats
    video_formats: list = None
    audio_formats: list = None
    
    def __post_init__(self):
        if self.video_formats is None:
            self.video_formats = ['.mp4', '.avi', '.mov', '.mkv']
        if self.audio_formats is None:
            self.audio_formats = ['.wav', '.mp3', '.aac', '.flac']


@dataclass
class StorageConfig:
    base_path: str = "./projects"
    temp_path: str = "./temp"
    output_path: str = "./output"
    cache_path: str = "./cache"
    
    # Storage backends
    use_s3: bool = False
    s3_bucket: str = None
    s3_region: str = "us-east-1"
    
    # File cleanup
    cleanup_temp_files: bool = True
    cleanup_after_days: int = 7


@dataclass
class LoggingConfig:
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_path: str = "./logs/director_agent.log"
    max_file_size_mb: int = 100
    backup_count: int = 5
    
    # Structured logging
    use_json_format: bool = False
    
    # External logging services
    use_elasticsearch: bool = False
    elasticsearch_host: str = "localhost:9200"


@dataclass
class MonitoringConfig:
    enable_metrics: bool = True
    metrics_port: int = 8000
    health_check_port: int = 8001
    
    # Prometheus
    prometheus_enabled: bool = True
    prometheus_endpoint: str = "/metrics"
    
    # Custom metrics
    track_processing_time: bool = True
    track_queue_size: bool = True
    track_agent_health: bool = True


class DirectorConfig:
    """Main configuration class for Director Agent"""
    
    def __init__(self, config_file: str = None):
        self.redis = RedisConfig()
        self.agent = AgentConfig()
        self.quality = QualityConfig()
        self.storage = StorageConfig()
        self.logging = LoggingConfig()
        self.monitoring = MonitoringConfig()
        
        # Load from environment variables
        self._load_from_env()
        
        # Load from config file if provided
        if config_file:
            self._load_from_file(config_file)
        
        # Create necessary directories
        self._create_directories()
    
    def _load_from_env(self):
        """Load configuration from environment variables"""
        
        # Redis configuration
        self.redis.host = os.getenv("REDIS_HOST", self.redis.host)
        self.redis.port = int(os.getenv("REDIS_PORT", self.redis.port))
        self.redis.db = int(os.getenv("REDIS_DB", self.redis.db))
        self.redis.password = os.getenv("REDIS_PASSWORD", self.redis.password)
        self.redis.ssl = os.getenv("REDIS_SSL", "false").lower() == "true"
        
        # Agent configuration
        self.agent.max_concurrent_tasks = int(os.getenv("MAX_CONCURRENT_TASKS", self.agent.max_concurrent_tasks))
        self.agent.health_check_interval = int(os.getenv("HEALTH_CHECK_INTERVAL", self.agent.health_check_interval))
        self.agent.task_timeout = int(os.getenv("TASK_TIMEOUT", self.agent.task_timeout))
        self.agent.max_retries = int(os.getenv("MAX_RETRIES", self.agent.max_retries))
        
        # Quality configuration
        self.quality.min_visual_quality = float(os.getenv("MIN_VISUAL_QUALITY", self.quality.min_visual_quality))
        self.quality.min_audio_quality = float(os.getenv("MIN_AUDIO_QUALITY", self.quality.min_audio_quality))
        self.quality.min_consistency_score = float(os.getenv("MIN_CONSISTENCY_SCORE", self.quality.min_consistency_score))
        self.quality.min_overall_score = float(os.getenv("MIN_OVERALL_SCORE", self.quality.min_overall_score))
        
        # Storage configuration
        self.storage.base_path = os.getenv("STORAGE_BASE_PATH", self.storage.base_path)
        self.storage.use_s3 = os.getenv("USE_S3", "false").lower() == "true"
        self.storage.s3_bucket = os.getenv("S3_BUCKET", self.storage.s3_bucket)
        
        # Logging configuration
        self.logging.level = os.getenv("LOG_LEVEL", self.logging.level)
        self.logging.file_path = os.getenv("LOG_FILE_PATH", self.logging.file_path)
        
        # Monitoring configuration
        self.monitoring.enable_metrics = os.getenv("ENABLE_METRICS", "true").lower() == "true"
        self.monitoring.metrics_port = int(os.getenv("METRICS_PORT", self.monitoring.metrics_port))
    
    def _load_from_file(self, config_file: str):
        """Load configuration from JSON/YAML file"""
        import json
        
        try:
            config_path = Path(config_file)
            if config_path.exists():
                with open(config_path, 'r') as f:
                    if config_path.suffix.lower() == '.json':
                        config_data = json.load(f)
                    elif config_path.suffix.lower() in ['.yaml', '.yml']:
                        import yaml
                        config_data = yaml.safe_load(f)
                    else:
                        raise ValueError(f"Unsupported config file format: {config_path.suffix}")
                
                # Update configuration from file
                self._update_from_dict(config_data)
                
        except Exception as e:
            print(f"Warning: Could not load config file {config_file}: {e}")
    
    def _update_from_dict(self, config_data: Dict[str, Any]):
        """Update configuration from dictionary"""
        
        if "redis" in config_data:
            redis_config = config_data["redis"]
            self.redis.host = redis_config.get("host", self.redis.host)
            self.redis.port = redis_config.get("port", self.redis.port)
            self.redis.db = redis_config.get("db", self.redis.db)
            self.redis.password = redis_config.get("password", self.redis.password)
            self.redis.ssl = redis_config.get("ssl", self.redis.ssl)
        
        if "agent" in config_data:
            agent_config = config_data["agent"]
            self.agent.max_concurrent_tasks = agent_config.get("max_concurrent_tasks", self.agent.max_concurrent_tasks)
            self.agent.health_check_interval = agent_config.get("health_check_interval", self.agent.health_check_interval)
            self.agent.task_timeout = agent_config.get("task_timeout", self.agent.task_timeout)
            self.agent.max_retries = agent_config.get("max_retries", self.agent.max_retries)
        
        if "quality" in config_data:
            quality_config = config_data["quality"]
            self.quality.min_visual_quality = quality_config.get("min_visual_quality", self.quality.min_visual_quality)
            self.quality.min_audio_quality = quality_config.get("min_audio_quality", self.quality.min_audio_quality)
            self.quality.min_consistency_score = quality_config.get("min_consistency_score", self.quality.min_consistency_score)
            self.quality.min_overall_score = quality_config.get("min_overall_score", self.quality.min_overall_score)
        
        if "storage" in config_data:
            storage_config = config_data["storage"]
            self.storage.base_path = storage_config.get("base_path", self.storage.base_path)
            self.storage.use_s3 = storage_config.get("use_s3", self.storage.use_s3)
            self.storage.s3_bucket = storage_config.get("s3_bucket", self.storage.s3_bucket)
        
        if "logging" in config_data:
            logging_config = config_data["logging"]
            self.logging.level = logging_config.get("level", self.logging.level)
            self.logging.file_path = logging_config.get("file_path", self.logging.file_path)
        
        if "monitoring" in config_data:
            monitoring_config = config_data["monitoring"]
            self.monitoring.enable_metrics = monitoring_config.get("enable_metrics", self.monitoring.enable_metrics)
            self.monitoring.metrics_port = monitoring_config.get("metrics_port", self.monitoring.metrics_port)
    
    def _create_directories(self):
        """Create necessary directories"""
        directories = [
            self.storage.base_path,
            self.storage.temp_path,
            self.storage.output_path,
            self.storage.cache_path,
            os.path.dirname(self.logging.file_path) if self.logging.file_path else None
        ]
        
        for directory in directories:
            if directory:
                Path(directory).mkdir(parents=True, exist_ok=True)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            "redis": {
                "host": self.redis.host,
                "port": self.redis.port,
                "db": self.redis.db,
                "ssl": self.redis.ssl
            },
            "agent": {
                "max_concurrent_tasks": self.agent.max_concurrent_tasks,
                "health_check_interval": self.agent.health_check_interval,
                "task_timeout": self.agent.task_timeout,
                "max_retries": self.agent.max_retries
            },
            "quality": {
                "min_visual_quality": self.quality.min_visual_quality,
                "min_audio_quality": self.quality.min_audio_quality,
                "min_consistency_score": self.quality.min_consistency_score,
                "min_overall_score": self.quality.min_overall_score
            },
            "storage": {
                "base_path": self.storage.base_path,
                "temp_path": self.storage.temp_path,
                "output_path": self.storage.output_path,
                "use_s3": self.storage.use_s3,
                "s3_bucket": self.storage.s3_bucket
            },
            "logging": {
                "level": self.logging.level,
                "file_path": self.logging.file_path
            },
            "monitoring": {
                "enable_metrics": self.monitoring.enable_metrics,
                "metrics_port": self.monitoring.metrics_port
            }
        }
    
    def save_to_file(self, config_file: str):
        """Save current configuration to file"""
        import json
        
        config_path = Path(config_file)
        config_data = self.to_dict()
        
        with open(config_path, 'w') as f:
            if config_path.suffix.lower() == '.json':
                json.dump(config_data, f, indent=2)
            elif config_path.suffix.lower() in ['.yaml', '.yml']:
                import yaml
                yaml.dump(config_data, f, default_flow_style=False)
            else:
                raise ValueError(f"Unsupported config file format: {config_path.suffix}")


# Default configuration instance
default_config = DirectorConfig()


# Configuration validation
def validate_config(config: DirectorConfig) -> bool:
    """Validate configuration settings"""
    
    # Validate Redis configuration
    if not config.redis.host:
        print("Error: Redis host not specified")
        return False
    
    if config.redis.port < 1 or config.redis.port > 65535:
        print("Error: Invalid Redis port")
        return False
    
    # Validate agent configuration
    if config.agent.max_concurrent_tasks < 1:
        print("Error: max_concurrent_tasks must be at least 1")
        return False
    
    if config.agent.health_check_interval < 1:
        print("Error: health_check_interval must be at least 1 second")
        return False
    
    # Validate quality configuration
    if not (0.0 <= config.quality.min_visual_quality <= 1.0):
        print("Error: min_visual_quality must be between 0.0 and 1.0")
        return False
    
    if not (0.0 <= config.quality.min_audio_quality <= 1.0):
        print("Error: min_audio_quality must be between 0.0 and 1.0")
        return False
    
    # Validate storage configuration
    if not config.storage.base_path:
        print("Error: Storage base path not specified")
        return False
    
    # Validate S3 configuration if enabled
    if config.storage.use_s3 and not config.storage.s3_bucket:
        print("Error: S3 bucket not specified when S3 is enabled")
        return False
    
    return True


# Environment-specific configurations
def get_development_config() -> DirectorConfig:
    """Get development configuration"""
    config = DirectorConfig()
    config.logging.level = "DEBUG"
    config.monitoring.enable_metrics = True
    config.storage.cleanup_temp_files = False
    return config


def get_production_config() -> DirectorConfig:
    """Get production configuration"""
    config = DirectorConfig()
    config.logging.level = "INFO"
    config.monitoring.enable_metrics = True
    config.agent.max_concurrent_tasks = 20
    config.storage.cleanup_temp_files = True
    config.storage.use_s3 = True
    return config


def get_testing_config() -> DirectorConfig:
    """Get testing configuration"""
    config = DirectorConfig()
    config.logging.level = "WARNING"
    config.monitoring.enable_metrics = False
    config.storage.base_path = "./test_projects"
    config.storage.cleanup_temp_files = True
    config.redis.db = 1  # Use different Redis DB for testing
    return config