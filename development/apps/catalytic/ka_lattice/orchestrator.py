"""
KA Lattice Orchestrator for Local Production Deployment
Manages multiple lattice instances and coordinates production workloads
"""

import asyncio
import threading
from typing import Dict, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import json
import logging
from pathlib import Path
import numpy as np

from .ka_core import KALatticeCore, ComputationResult
from .production_cycle import ProductionCycleManager, ProductionConfig
from libs.config import get_settings

logger = logging.getLogger(__name__)


@dataclass
class LatticeInstance:
    """Single lattice instance in the orchestration"""

    id: str
    lattice: KALatticeCore
    cycle_manager: ProductionCycleManager
    workload_queue: asyncio.Queue = field(default_factory=asyncio.Queue)
    status: str = "idle"
    created_at: datetime = field(default_factory=datetime.now)
    last_computation: Optional[datetime] = None
    total_computations: int = 0


@dataclass
class OrchestratorConfig:
    """Configuration for the orchestrator"""

    max_instances: int = 4
    auto_scaling: bool = True
    scale_up_threshold: float = 0.8  # CPU/memory threshold
    scale_down_threshold: float = 0.3
    health_check_interval: int = 30
    persistence_path: Path = field(default_factory=lambda: Path("./ka_lattice_state"))
    enable_monitoring: bool = True
    monitoring_port: int = 9090


class KALatticeOrchestrator:
    """
    Orchestrates multiple KA Lattice instances for production workloads
    Provides load balancing, auto-scaling, and fault tolerance
    """

    def __init__(self, config: Optional[OrchestratorConfig] = None):
        """
        Initialize the orchestrator

        Args:
            config: Orchestrator configuration
        """
        self.config = config or OrchestratorConfig()
        self.settings = get_settings()

        # Instance management
        self.instances: Dict[str, LatticeInstance] = {}
        self._instance_counter = 0
        self._instance_lock = threading.Lock()

        # Orchestration control
        self._running = False
        self._stop_event = asyncio.Event()
        self._main_loop: Optional[asyncio.Task] = None

        # Monitoring
        self.metrics = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "average_latency_ms": 0.0,
            "current_load": 0.0,
        }

        # Ensure persistence directory exists
        self.config.persistence_path.mkdir(parents=True, exist_ok=True)

        logger.info("KA Lattice Orchestrator initialized")

    async def start(self):
        """Start the orchestrator"""
        if self._running:
            logger.warning("Orchestrator already running")
            return

        logger.info("Starting KA Lattice Orchestrator...")
        self._running = True
        self._stop_event.clear()

        try:
            # Create initial instances
            await self._create_initial_instances()

            # Start main orchestration loop
            self._main_loop = asyncio.create_task(self._orchestration_loop())

            # Start monitoring if enabled
            if self.config.enable_monitoring:
                asyncio.create_task(self._monitoring_loop())

            logger.info("Orchestrator started successfully")

        except Exception as e:
            logger.error(f"Failed to start orchestrator: {e}")
            self._running = False
            raise

    async def stop(self):
        """Stop the orchestrator gracefully"""
        if not self._running:
            return

        logger.info("Stopping KA Lattice Orchestrator...")
        self._running = False
        self._stop_event.set()

        # Stop all instances
        await self._stop_all_instances()

        # Cancel main loop
        if self._main_loop:
            self._main_loop.cancel()
            try:
                await self._main_loop
            except asyncio.CancelledError:
                pass

        logger.info("Orchestrator stopped")

    async def _create_initial_instances(self):
        """Create initial lattice instances"""
        # Determine optimal number based on system resources
        import psutil

        cpu_count = psutil.cpu_count()
        initial_count = min(cpu_count // 2, self.config.max_instances, 2)

        logger.info(f"Creating {initial_count} initial lattice instances...")

        for _ in range(initial_count):
            await self._create_instance()

    async def _create_instance(self) -> LatticeInstance:
        """Create a new lattice instance"""
        with self._instance_lock:
            instance_id = f"lattice_{self._instance_counter}"
            self._instance_counter += 1

        logger.info(f"Creating lattice instance: {instance_id}")

        # Determine dimensions based on load
        dimensions = 4  # Default
        size = 10  # Default

        # Create KA Lattice with appropriate backend
        lattice = KALatticeCore(
            dimensions=dimensions,
            size=size,
            knowledge_capacity=5000,
            learning_enabled=True,
            enable_gpu=self._should_use_gpu(),
        )

        # Create production cycle manager
        production_config = ProductionConfig(
            warmup_iterations=50, optimization_interval_seconds=300, enable_auto_optimization=True
        )
        cycle_manager = ProductionCycleManager(lattice, production_config)

        # Create instance
        instance = LatticeInstance(
            id=instance_id, lattice=lattice, cycle_manager=cycle_manager, status="starting"
        )

        # Start production cycle
        asyncio.create_task(self._run_instance_cycle(instance))

        # Add to instances
        self.instances[instance_id] = instance

        logger.info(f"Created instance {instance_id} with {dimensions}D lattice")
        return instance

    async def _run_instance_cycle(self, instance: LatticeInstance):
        """Run production cycle for an instance"""
        try:
            instance.status = "running"
            await instance.cycle_manager.start_production_cycle()
        except Exception as e:
            logger.error(f"Instance {instance.id} cycle error: {e}")
            instance.status = "error"

    async def _orchestration_loop(self):
        """Main orchestration loop"""
        while self._running and not self._stop_event.is_set():
            try:
                # Check system health
                await self._check_system_health()

                # Auto-scaling if enabled
                if self.config.auto_scaling:
                    await self._auto_scale()

                # Rebalance workloads
                await self._rebalance_workloads()

                # Brief pause
                await asyncio.sleep(5)

            except Exception as e:
                logger.error(f"Orchestration loop error: {e}")

    async def _check_system_health(self):
        """Check overall system health"""
        unhealthy_instances = []

        for instance_id, instance in self.instances.items():
            if instance.status == "error":
                unhealthy_instances.append(instance_id)

        # Replace unhealthy instances
        for instance_id in unhealthy_instances:
            logger.warning(f"Replacing unhealthy instance: {instance_id}")
            await self._replace_instance(instance_id)

    async def _replace_instance(self, instance_id: str):
        """Replace a failed instance"""
        # Stop old instance
        if instance_id in self.instances:
            old_instance = self.instances[instance_id]
            try:
                await old_instance.cycle_manager.stop_production_cycle()
            except Exception as e:
                logger.warning(f"Error stopping instance {instance_id}: {e}")
            del self.instances[instance_id]

        # Create new instance
        await self._create_instance()

    async def _auto_scale(self):
        """Auto-scale instances based on load"""
        import psutil

        # Get current system load
        cpu_percent = psutil.cpu_percent(interval=1)
        memory_percent = psutil.virtual_memory().percent

        current_load = max(cpu_percent, memory_percent) / 100.0
        self.metrics["current_load"] = current_load

        # Scale up if needed
        if current_load > self.config.scale_up_threshold:
            if len(self.instances) < self.config.max_instances:
                logger.info(f"Scaling up due to high load ({current_load:.2%})")
                await self._create_instance()

        # Scale down if needed
        elif current_load < self.config.scale_down_threshold:
            if len(self.instances) > 1:
                logger.info(f"Scaling down due to low load ({current_load:.2%})")
                await self._remove_least_used_instance()

    async def _remove_least_used_instance(self):
        """Remove the least used instance"""
        if not self.instances:
            return

        # Find least used instance
        least_used = min(self.instances.values(), key=lambda x: x.total_computations)

        logger.info(f"Removing instance {least_used.id}")

        # Stop and remove
        try:
            await least_used.cycle_manager.stop_production_cycle()
        except Exception as e:
            logger.warning(f"Error stopping instance {least_used.id}: {e}")

        del self.instances[least_used.id]

    async def _rebalance_workloads(self):
        """Rebalance workloads across instances"""
        if len(self.instances) <= 1:
            return

        # Get instance loads
        loads = {
            instance_id: instance.workload_queue.qsize()
            for instance_id, instance in self.instances.items()
        }

        # Check if rebalancing needed
        if max(loads.values()) - min(loads.values()) > 10:
            logger.debug("Rebalancing workloads across instances")
            # In a real implementation, would move tasks between queues

    async def _monitoring_loop(self):
        """Monitoring and metrics collection loop"""
        while self._running:
            try:
                # Collect metrics from all instances
                total_computations = sum(
                    inst.total_computations for inst in self.instances.values()
                )

                # Log summary
                logger.info(
                    f"Orchestrator Status: {len(self.instances)} instances, "
                    f"{total_computations} total computations, "
                    f"Load: {self.metrics['current_load']:.2%}"
                )

                # Save state
                await self._save_orchestrator_state()

                await asyncio.sleep(self.config.health_check_interval)

            except Exception as e:
                logger.error(f"Monitoring error: {e}")

    async def _stop_all_instances(self):
        """Stop all lattice instances"""
        logger.info(f"Stopping {len(self.instances)} instances...")

        tasks = []
        for instance in self.instances.values():
            tasks.append(instance.cycle_manager.stop_production_cycle())

        await asyncio.gather(*tasks, return_exceptions=True)

        self.instances.clear()

    def _should_use_gpu(self) -> bool:
        """Determine if GPU should be used for new instance"""
        # Check GPU availability and current usage
        try:
            import torch

            if torch.cuda.is_available():
                # Check memory availability
                free_memory = torch.cuda.mem_get_info()[0] / (1024**3)  # GB
                return free_memory > 2.0  # Need at least 2GB free
        except Exception as e:
            logger.debug(f"GPU check failed: {e}")
        return False

    async def submit_computation(
        self, operation: str, input_data: np.ndarray, parameters: Optional[Dict[str, Any]] = None
    ) -> ComputationResult:
        """
        Submit a computation to the orchestrator

        Args:
            operation: Operation to perform
            input_data: Input data
            parameters: Operation parameters

        Returns:
            Computation result
        """
        if not self.instances:
            raise RuntimeError("No lattice instances available")

        # Select instance with lowest load
        instance = min(self.instances.values(), key=lambda x: x.workload_queue.qsize())

        # Submit computation
        instance.last_computation = datetime.now()
        instance.total_computations += 1

        result = await asyncio.get_event_loop().run_in_executor(
            None, instance.lattice.compute_with_knowledge, operation, input_data, parameters
        )

        # Update metrics
        self.metrics["total_requests"] += 1
        if result.result_data is not None:
            self.metrics["successful_requests"] += 1
        else:
            self.metrics["failed_requests"] += 1

        # Update average latency
        n = self.metrics["total_requests"]
        avg = self.metrics["average_latency_ms"]
        self.metrics["average_latency_ms"] = (avg * (n - 1) + result.execution_time_ms) / n

        return result

    async def _save_orchestrator_state(self):
        """Save orchestrator state to disk"""
        state_file = self.config.persistence_path / "orchestrator_state.json"

        state = {
            "timestamp": datetime.now().isoformat(),
            "instances": {
                instance_id: {
                    "status": instance.status,
                    "created_at": instance.created_at.isoformat(),
                    "total_computations": instance.total_computations,
                }
                for instance_id, instance in self.instances.items()
            },
            "metrics": self.metrics,
        }

        with open(state_file, "w") as f:
            json.dump(state, f, indent=2)

    def get_status(self) -> Dict[str, Any]:
        """Get orchestrator status"""
        return {
            "running": self._running,
            "instances": {
                instance_id: {
                    "status": instance.status,
                    "computations": instance.total_computations,
                    "queue_size": instance.workload_queue.qsize(),
                }
                for instance_id, instance in self.instances.items()
            },
            "metrics": self.metrics,
            "config": {
                "max_instances": self.config.max_instances,
                "auto_scaling": self.config.auto_scaling,
            },
        }
