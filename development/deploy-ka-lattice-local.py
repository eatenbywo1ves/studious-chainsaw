#!/usr/bin/env python3
"""
Local Production Deployment Script for KA Lattice Framework
Deploys and manages the catalytic computing production cycle on local system
"""

import asyncio
import sys
import argparse
import signal
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional
import json
import yaml
import numpy as np

# Add development directory to path
sys.path.insert(0, str(Path(__file__).parent))

from apps.catalytic.ka_lattice import (
    KALatticeOrchestrator,
    OrchestratorConfig,
    KnowledgeStore,
    PatternLibrary
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('ka_lattice_production.log')
    ]
)
logger = logging.getLogger(__name__)


class LocalProductionDeployment:
    """
    Manages local production deployment of KA Lattice
    """

    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize deployment

        Args:
            config_file: Optional configuration file path
        """
        self.config_file = config_file
        self.orchestrator: Optional[KALatticeOrchestrator] = None
        self.knowledge_store: Optional[KnowledgeStore] = None
        self.pattern_library: PatternLibrary = PatternLibrary()
        self.running = False

        # Load configuration
        self.config = self._load_configuration()

        logger.info("Local Production Deployment initialized")

    def _load_configuration(self) -> dict:
        """Load deployment configuration"""
        default_config = {
            'orchestrator': {
                'max_instances': 4,
                'auto_scaling': True,
                'scale_up_threshold': 0.8,
                'scale_down_threshold': 0.3,
                'health_check_interval': 30,
                'persistence_path': './ka_lattice_state',
                'enable_monitoring': True,
                'monitoring_port': 9090
            },
            'knowledge': {
                'storage_path': './ka_knowledge',
                'cleanup_days': 30,
                'cache_size': 100
            },
            'production': {
                'warmup_iterations': 100,
                'optimization_interval': 300,
                'enable_gpu': True,
                'target_throughput': 1000.0
            },
            'monitoring': {
                'enable_prometheus': True,
                'prometheus_port': 9090,
                'enable_grafana': False,
                'grafana_port': 3000
            }
        }

        if self.config_file and Path(self.config_file).exists():
            with open(self.config_file, 'r') as f:
                if self.config_file.endswith('.yaml') or self.config_file.endswith('.yml'):
                    user_config = yaml.safe_load(f)
                else:
                    user_config = json.load(f)

                # Merge configurations
                self._merge_config(default_config, user_config)

        return default_config

    def _merge_config(self, base: dict, override: dict):
        """Recursively merge configuration dictionaries"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value

    async def deploy(self):
        """Deploy KA Lattice in production mode"""
        logger.info("=== Starting KA Lattice Production Deployment ===")
        self.running = True

        try:
            # Initialize components
            await self._initialize_components()

            # Start orchestrator
            await self._start_orchestrator()

            # Start monitoring
            if self.config['monitoring']['enable_prometheus']:
                await self._start_monitoring()

            # Run production workload
            await self._run_production()

        except Exception as e:
            logger.error(f"Deployment error: {e}")
            raise

        finally:
            await self.shutdown()

    async def _initialize_components(self):
        """Initialize deployment components"""
        logger.info("Initializing components...")

        # Create knowledge store
        knowledge_path = Path(self.config['knowledge']['storage_path'])
        self.knowledge_store = KnowledgeStore(knowledge_path)

        # Create orchestrator
        orchestrator_config = OrchestratorConfig(
            max_instances=self.config['orchestrator']['max_instances'],
            auto_scaling=self.config['orchestrator']['auto_scaling'],
            scale_up_threshold=self.config['orchestrator']['scale_up_threshold'],
            scale_down_threshold=self.config['orchestrator']['scale_down_threshold'],
            health_check_interval=self.config['orchestrator']['health_check_interval'],
            persistence_path=Path(self.config['orchestrator']['persistence_path']),
            enable_monitoring=self.config['orchestrator']['enable_monitoring'],
            monitoring_port=self.config['orchestrator']['monitoring_port']
        )

        self.orchestrator = KALatticeOrchestrator(orchestrator_config)

        logger.info("Components initialized successfully")

    async def _start_orchestrator(self):
        """Start the KA Lattice orchestrator"""
        logger.info("Starting orchestrator...")
        await self.orchestrator.start()
        logger.info("Orchestrator started")

    async def _start_monitoring(self):
        """Start monitoring services"""
        logger.info("Starting monitoring services...")

        if self.config['monitoring']['enable_prometheus']:
            # Start Prometheus metrics server
            from prometheus_client import start_http_server, Counter, Histogram, Gauge

            # Define metrics
            self.metrics = {
                'requests_total': Counter('ka_lattice_requests_total', 'Total requests'),
                'requests_success': Counter('ka_lattice_requests_success', 'Successful requests'),
                'requests_failed': Counter('ka_lattice_requests_failed', 'Failed requests'),
                'computation_duration': Histogram('ka_lattice_computation_duration_seconds', 'Computation duration'),
                'active_instances': Gauge('ka_lattice_active_instances', 'Active lattice instances'),
                'memory_usage': Gauge('ka_lattice_memory_usage_bytes', 'Memory usage'),
                'knowledge_patterns': Gauge('ka_lattice_knowledge_patterns', 'Knowledge patterns stored')
            }

            # Start metrics server
            start_http_server(self.config['monitoring']['prometheus_port'])
            logger.info(f"Prometheus metrics server started on port {self.config['monitoring']['prometheus_port']}")

    async def _run_production(self):
        """Run production workload"""
        logger.info("Starting production workload...")

        # Simulate production workload
        workload_count = 0
        start_time = datetime.now()

        while self.running:
            try:
                # Generate workload
                workload = self._generate_workload()

                # Submit to orchestrator
                result = await self.orchestrator.submit_computation(
                    operation=workload['operation'],
                    input_data=workload['data'],
                    parameters=workload['parameters']
                )

                # Update metrics
                if hasattr(self, 'metrics'):
                    self.metrics['requests_total'].inc()
                    if result.result_data is not None:
                        self.metrics['requests_success'].inc()
                    else:
                        self.metrics['requests_failed'].inc()
                    self.metrics['computation_duration'].observe(result.execution_time_ms / 1000)

                workload_count += 1

                # Log progress
                if workload_count % 100 == 0:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    throughput = workload_count / elapsed if elapsed > 0 else 0
                    logger.info(f"Processed {workload_count} workloads, "
                              f"Throughput: {throughput:.2f}/s")

                # Brief pause
                await asyncio.sleep(0.001)

            except KeyboardInterrupt:
                logger.info("Received interrupt signal")
                break
            except Exception as e:
                logger.error(f"Production error: {e}")
                await asyncio.sleep(1)

    def _generate_workload(self) -> dict:
        """Generate synthetic workload for testing"""
        operations = ['transform', 'reduce', 'pathfind', 'analyze']
        operation = np.random.choice(operations)

        if operation == 'transform':
            return {
                'operation': 'transform',
                'data': np.random.randn(100, 100).astype(np.float32),
                'parameters': {'type': 'normalize'}
            }
        elif operation == 'reduce':
            return {
                'operation': 'reduce',
                'data': np.random.randn(1000).astype(np.float32),
                'parameters': {'operation': 'sum'}
            }
        elif operation == 'pathfind':
            return {
                'operation': 'pathfind',
                'data': np.array([]),
                'parameters': {'start': 0, 'end': 100}
            }
        else:  # analyze
            return {
                'operation': 'analyze',
                'data': np.random.randn(50, 50).astype(np.float32),
                'parameters': {}
            }

    async def benchmark(self):
        """Run performance benchmark"""
        logger.info("=== Running Performance Benchmark ===")

        # Initialize components
        await self._initialize_components()
        await self._start_orchestrator()

        # Warmup
        logger.info("Warming up...")
        for _ in range(100):
            workload = self._generate_workload()
            await self.orchestrator.submit_computation(
                workload['operation'],
                workload['data'],
                workload['parameters']
            )

        # Benchmark
        logger.info("Running benchmark...")
        operations = ['transform', 'reduce', 'pathfind', 'analyze']
        results = {}

        for operation in operations:
            times = []
            for _ in range(100):
                workload = {
                    'operation': operation,
                    'data': np.random.randn(100, 100).astype(np.float32),
                    'parameters': {}
                }

                result = await self.orchestrator.submit_computation(
                    workload['operation'],
                    workload['data'],
                    workload['parameters']
                )

                times.append(result.execution_time_ms)

            results[operation] = {
                'mean_ms': np.mean(times),
                'std_ms': np.std(times),
                'min_ms': np.min(times),
                'max_ms': np.max(times),
                'p50_ms': np.percentile(times, 50),
                'p95_ms': np.percentile(times, 95),
                'p99_ms': np.percentile(times, 99)
            }

        # Print results
        logger.info("\n=== Benchmark Results ===")
        for operation, metrics in results.items():
            logger.info(f"\n{operation.upper()}:")
            logger.info(f"  Mean: {metrics['mean_ms']:.2f}ms ± {metrics['std_ms']:.2f}ms")
            logger.info(f"  Min/Max: {metrics['min_ms']:.2f}ms / {metrics['max_ms']:.2f}ms")
            logger.info(f"  Percentiles - P50: {metrics['p50_ms']:.2f}ms, "
                       f"P95: {metrics['p95_ms']:.2f}ms, P99: {metrics['p99_ms']:.2f}ms")

        # Get orchestrator status
        status = self.orchestrator.get_status()
        logger.info("\nOrchestrator Status:")
        logger.info(f"  Instances: {len(status['instances'])}")
        logger.info(f"  Total Requests: {status['metrics']['total_requests']}")
        logger.info(f"  Success Rate: {status['metrics']['successful_requests'] / max(status['metrics']['total_requests'], 1) * 100:.2f}%")
        logger.info(f"  Average Latency: {status['metrics']['average_latency_ms']:.2f}ms")

        # Knowledge store statistics
        if self.knowledge_store:
            kb_stats = self.knowledge_store.get_statistics()
            logger.info("\nKnowledge Store:")
            logger.info(f"  Patterns: {kb_stats['total_patterns']}")
            logger.info(f"  Avg Confidence: {kb_stats['average_confidence']:.3f}")

    async def shutdown(self):
        """Shutdown deployment gracefully"""
        logger.info("Shutting down deployment...")
        self.running = False

        if self.orchestrator:
            await self.orchestrator.stop()

        logger.info("Deployment shutdown complete")

    def handle_signal(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}")
        self.running = False


async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="KA Lattice Local Production Deployment"
    )

    parser.add_argument(
        '--config',
        type=str,
        help='Configuration file (JSON or YAML)'
    )

    parser.add_argument(
        '--mode',
        choices=['production', 'benchmark', 'test'],
        default='production',
        help='Deployment mode'
    )

    parser.add_argument(
        '--duration',
        type=int,
        default=0,
        help='Run duration in seconds (0 for continuous)'
    )

    args = parser.parse_args()

    # Create deployment
    deployment = LocalProductionDeployment(args.config)

    # Setup signal handlers
    signal.signal(signal.SIGINT, deployment.handle_signal)
    signal.signal(signal.SIGTERM, deployment.handle_signal)

    try:
        if args.mode == 'benchmark':
            await deployment.benchmark()
        elif args.mode == 'test':
            # Quick test mode
            await deployment._initialize_components()
            await deployment._start_orchestrator()

            # Run a few test computations
            for _ in range(10):
                workload = deployment._generate_workload()
                result = await deployment.orchestrator.submit_computation(
                    workload['operation'],
                    workload['data'],
                    workload['parameters']
                )
                logger.info(f"Test computation: {result.execution_time_ms:.2f}ms")

            await deployment.shutdown()
        else:  # production
            if args.duration > 0:
                # Run for specified duration
                task = asyncio.create_task(deployment.deploy())
                await asyncio.sleep(args.duration)
                deployment.running = False
                await task
            else:
                # Run continuously
                await deployment.deploy()

    except Exception as e:
        logger.error(f"Deployment failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
