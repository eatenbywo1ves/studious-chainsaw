#!/usr/bin/env python3
"""
Simple Prometheus setup script for development
Alternative to Docker for quick testing
"""

from utilities.logging_utils import setup_service_logging, LogLevel
import asyncio
import sys
import subprocess
from pathlib import Path

# Add shared libraries to path
sys.path.append(str(Path(__file__).parent.parent / "shared"))


logger = setup_service_logging("monitoring-setup", LogLevel.INFO)


async def download_prometheus():
    """Download Prometheus binary for Windows"""
    try:
        import requests
        import zipfile

        prometheus_version = "2.45.0"
        prometheus_url = f"https://github.com/prometheus/prometheus/releases/download/v{prometheus_version}/prometheus-{prometheus_version}.windows-amd64.zip"

        logger.info(f"Downloading Prometheus {prometheus_version}...")

        # Create prometheus directory
        prom_dir = Path("prometheus-binary")
        prom_dir.mkdir(exist_ok=True)

        # Download if not exists
        zip_file = prom_dir / f"prometheus-{prometheus_version}.zip"
        if not zip_file.exists():
            response = requests.get(prometheus_url)
            response.raise_for_status()

            with open(zip_file, "wb") as f:
                f.write(response.content)

            # Extract
            with zipfile.ZipFile(zip_file, "r") as zip_ref:
                zip_ref.extractall(prom_dir)

            logger.info("Prometheus downloaded and extracted")
        else:
            logger.info("Prometheus already downloaded")

        # Find prometheus executable
        for item in prom_dir.rglob("prometheus.exe"):
            return item

        raise FileNotFoundError("Prometheus executable not found")

    except Exception as e:
        logger.error(f"Failed to download Prometheus: {e}")
        return None


async def start_prometheus():
    """Start Prometheus server"""
    try:
        prometheus_exe = await download_prometheus()
        if not prometheus_exe:
            logger.error("Cannot start Prometheus - executable not found")
            return None

        # Start Prometheus
        config_file = Path("prometheus/prometheus.yml")
        if not config_file.exists():
            logger.error(f"Prometheus config not found: {config_file}")
            return None

        cmd = [
            str(prometheus_exe),
            f"--config.file={config_file.absolute()}",
            "--storage.tsdb.path=./prometheus-data",
            "--web.console.libraries=./console_libraries",
            "--web.console.templates=./consoles",
            "--web.listen-address=:9090",
            "--web.enable-lifecycle",
        ]

        logger.info("Starting Prometheus server...")
        logger.info(f"Command: {' '.join(cmd)}")

        # Create data directory
        Path("prometheus-data").mkdir(exist_ok=True)

        # Start process in background
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=Path.cwd()
        )

        logger.info(f"Prometheus started with PID: {process.pid}")
        logger.info("Prometheus web interface: http://localhost:9090")

        return process

    except Exception as e:
        logger.error(f"Failed to start Prometheus: {e}")
        return None


def create_simple_config():
    """Create a simplified Prometheus config"""
    config = {
        "global": {"scrape_interval": "15s", "evaluation_interval": "15s"},
        "scrape_configs": [
            {
                "job_name": "api-gateway",
                "static_configs": [{"targets": ["localhost:9000"]}],
                "metrics_path": "/metrics",
                "scrape_interval": "10s",
            },
            {
                "job_name": "observatory",
                "static_configs": [{"targets": ["localhost:8080"]}],
                "metrics_path": "/metrics",
                "scrape_interval": "15s",
            },
        ],
    }

    # Write YAML config
    config_file = Path("prometheus/prometheus-simple.yml")
    config_file.parent.mkdir(exist_ok=True)

    import yaml

    with open(config_file, "w") as f:
        yaml.dump(config, f, default_flow_style=False)

    logger.info(f"Created simplified config: {config_file}")
    return config_file


async def main():
    """Main setup function"""
    logger.info("Setting up Prometheus monitoring...")

    try:
        # Try Docker first
        result = subprocess.run(["docker", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            logger.info("Docker available - you can use docker-compose up -d")

    except FileNotFoundError:
        logger.info("Docker not available, setting up local Prometheus...")

        # Create simple config
        create_simple_config()

        # Start Prometheus
        process = await start_prometheus()
        if process:
            logger.info("Prometheus monitoring setup complete!")
            logger.info("Access points:")
            logger.info("  - Prometheus: http://localhost:9090")
            logger.info("  - API Gateway metrics: http://localhost:9000/metrics")
            logger.info("  - Observatory metrics: http://localhost:8080/metrics")

            # Keep running
            try:
                process.wait()
            except KeyboardInterrupt:
                logger.info("Stopping Prometheus...")
                process.terminate()


if __name__ == "__main__":
    asyncio.run(main())
