"""
Production Cycle Manager for KA Lattice
Manages the complete lifecycle of catalytic computing in production
"""

import asyncio
import time
import threading
from typing import Dict, List, Optional, Callable, Any
from enum import Enum
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import logging
import json

from .ka_core import KALatticeCore, LatticeState, ComputationResult
from libs.utils.exceptions import CatalyticException

logger = logging.getLogger(__name__)


class CyclePhase(Enum):
    """Production cycle phases"""
    INITIALIZATION = "initialization"
    WARMUP = "warmup"
    PRODUCTION = "production"
    OPTIMIZATION = "optimization"
    MAINTENANCE = "maintenance"
    COOLDOWN = "cooldown"
    SHUTDOWN = "shutdown"


@dataclass
class CycleMetrics:
    """Metrics for a production cycle"""
    phase: CyclePhase
    start_time: datetime
    end_time: Optional[datetime] = None
    computations_processed: int = 0
    errors_encountered: int = 0
    average_latency_ms: float = 0.0
    throughput_per_second: float = 0.0
    memory_peak_mb: float = 0.0
    knowledge_improvements: int = 0


@dataclass
class ProductionConfig:
    """Configuration for production cycle"""
    warmup_iterations: int = 100
    optimization_interval_seconds: int = 300
    maintenance_window_seconds: int = 60
    max_errors_before_maintenance: int = 10
    target_throughput_per_second: float = 1000.0
    enable_auto_optimization: bool = True
    enable_health_checks: bool = True
    health_check_interval_seconds: int = 30


class ProductionCycleManager:
    """
    Manages the production lifecycle of KA Lattice
    Handles initialization, warmup, production, optimization, and maintenance cycles
    """

    def __init__(
        self,
        lattice: KALatticeCore,
        config: Optional[ProductionConfig] = None
    ):
        """
        Initialize production cycle manager

        Args:
            lattice: KA Lattice instance to manage
            config: Production configuration
        """
        self.lattice = lattice
        self.config = config or ProductionConfig()

        # State management
        self.current_phase = CyclePhase.INITIALIZATION
        self.phase_history: List[CycleMetrics] = []
        self.current_metrics: Optional[CycleMetrics] = None

        # Production control
        self._running = False
        self._stop_event = threading.Event()
        self._production_thread: Optional[threading.Thread] = None
        self._optimization_thread: Optional[threading.Thread] = None
        self._health_thread: Optional[threading.Thread] = None

        # Callbacks
        self.phase_callbacks: Dict[CyclePhase, List[Callable]] = {
            phase: [] for phase in CyclePhase
        }

        # Error tracking
        self.error_count = 0
        self.last_error_time: Optional[datetime] = None

        # Performance tracking
        self.total_computations = 0
        self.successful_computations = 0
        self.computation_times: List[float] = []

    def register_phase_callback(self, phase: CyclePhase, callback: Callable):
        """Register callback for phase transition"""
        self.phase_callbacks[phase].append(callback)

    def _transition_phase(self, new_phase: CyclePhase):
        """Transition to new phase"""
        # Complete current metrics
        if self.current_metrics:
            self.current_metrics.end_time = datetime.now()
            self.phase_history.append(self.current_metrics)

        # Start new phase
        old_phase = self.current_phase
        self.current_phase = new_phase
        self.current_metrics = CycleMetrics(
            phase=new_phase,
            start_time=datetime.now()
        )

        logger.info(f"Production cycle transition: {old_phase} → {new_phase}")

        # Execute callbacks
        for callback in self.phase_callbacks[new_phase]:
            try:
                callback(self, old_phase, new_phase)
            except Exception as e:
                logger.error(f"Phase callback error: {e}")

    async def start_production_cycle(self):
        """Start the production cycle"""
        if self._running:
            raise CatalyticException("Production cycle already running")

        logger.info("Starting production cycle...")
        self._running = True
        self._stop_event.clear()

        try:
            # Initialization phase
            await self._initialize_phase()

            # Warmup phase
            await self._warmup_phase()

            # Start background threads
            self._start_background_tasks()

            # Production phase
            await self._production_phase()

        except Exception as e:
            logger.error(f"Production cycle error: {e}")
            self._transition_phase(CyclePhase.SHUTDOWN)
            raise

        finally:
            # Ensure cleanup
            await self._shutdown_phase()

    async def _initialize_phase(self):
        """Initialization phase"""
        self._transition_phase(CyclePhase.INITIALIZATION)

        # Verify lattice is ready
        if self.lattice.state != LatticeState.READY:
            raise CatalyticException(f"Lattice not ready: {self.lattice.state}")

        # Load previous knowledge if available
        knowledge_file = "ka_knowledge_backup.json"
        try:
            with open(knowledge_file, 'r') as f:
                knowledge_data = json.load(f)
                self.lattice.import_knowledge(knowledge_data)
                logger.info("Loaded previous knowledge base")
        except FileNotFoundError:
            logger.info("No previous knowledge base found")
        except Exception as e:
            logger.warning(f"Failed to load knowledge base: {e}")

        # Initialize metrics
        self.error_count = 0
        self.total_computations = 0
        self.successful_computations = 0

        logger.info("Initialization phase complete")

    async def _warmup_phase(self):
        """Warmup phase to prepare lattice for production"""
        self._transition_phase(CyclePhase.WARMUP)

        logger.info(f"Starting warmup with {self.config.warmup_iterations} iterations...")

        # Perform warmup computations
        warmup_data = np.random.randn(100, 100).astype(np.float32)

        for i in range(self.config.warmup_iterations):
            if self._stop_event.is_set():
                break

            try:
                result = self.lattice.compute_with_knowledge(
                    operation="transform",
                    input_data=warmup_data,
                    parameters={'type': 'normalize'}
                )

                self.current_metrics.computations_processed += 1

                # Small delay to prevent overwhelming
                await asyncio.sleep(0.001)

            except Exception as e:
                logger.warning(f"Warmup computation {i} failed: {e}")

        logger.info(f"Warmup phase complete: {self.current_metrics.computations_processed} iterations")

    async def _production_phase(self):
        """Main production phase"""
        self._transition_phase(CyclePhase.PRODUCTION)

        logger.info("Entering production phase...")

        # Production loop
        while self._running and not self._stop_event.is_set():
            try:
                # Check if maintenance needed
                if self._needs_maintenance():
                    await self._maintenance_phase()

                # Process production workload
                await self._process_production_workload()

                # Brief pause
                await asyncio.sleep(0.001)

            except Exception as e:
                logger.error(f"Production phase error: {e}")
                self.error_count += 1
                self.last_error_time = datetime.now()

                if self.error_count >= self.config.max_errors_before_maintenance:
                    await self._maintenance_phase()

    async def _process_production_workload(self):
        """Process production workload (override in subclass for actual workload)"""
        # This is a placeholder - in real production, this would process actual requests
        import numpy as np

        # Simulate production computation
        data = np.random.randn(50, 50).astype(np.float32)

        start_time = time.perf_counter()

        result = self.lattice.compute_with_knowledge(
            operation="reduce",
            input_data=data,
            parameters={'operation': 'sum'}
        )

        exec_time = (time.perf_counter() - start_time) * 1000

        # Update metrics
        self.total_computations += 1
        if result.result_data is not None:
            self.successful_computations += 1

        self.computation_times.append(exec_time)
        if len(self.computation_times) > 1000:
            self.computation_times = self.computation_times[-500:]

        self.current_metrics.computations_processed += 1
        self.current_metrics.average_latency_ms = np.mean(self.computation_times)

        # Calculate throughput
        if self.current_metrics.start_time:
            elapsed = (datetime.now() - self.current_metrics.start_time).total_seconds()
            if elapsed > 0:
                self.current_metrics.throughput_per_second = (
                    self.current_metrics.computations_processed / elapsed
                )

    async def _optimization_phase(self):
        """Optimization phase to improve performance"""
        self._transition_phase(CyclePhase.OPTIMIZATION)

        logger.info("Starting optimization phase...")

        # Optimize knowledge base
        self.lattice.optimize_knowledge_base()

        # Analyze performance and adjust
        knowledge_stats = self.lattice.get_knowledge_stats()

        if knowledge_stats['hit_rate'] < 50:
            logger.info("Low knowledge hit rate - increasing learning")
            self.lattice.learning_enabled = True

        # Record improvements
        self.current_metrics.knowledge_improvements = knowledge_stats['learning_cycles']

        logger.info("Optimization phase complete")

        # Return to production
        self._transition_phase(CyclePhase.PRODUCTION)

    async def _maintenance_phase(self):
        """Maintenance phase for cleanup and recovery"""
        self._transition_phase(CyclePhase.MAINTENANCE)

        logger.info("Entering maintenance phase...")

        # Reset error count
        self.error_count = 0

        # Clear computation history if too large
        if len(self.computation_times) > 10000:
            self.computation_times = self.computation_times[-1000:]

        # Backup knowledge base
        try:
            knowledge_data = self.lattice.export_knowledge()
            with open("ka_knowledge_backup.json", 'w') as f:
                json.dump(knowledge_data, f)
            logger.info("Knowledge base backed up")
        except Exception as e:
            logger.error(f"Failed to backup knowledge: {e}")

        # Wait for maintenance window
        await asyncio.sleep(self.config.maintenance_window_seconds)

        logger.info("Maintenance phase complete")

        # Return to production
        self._transition_phase(CyclePhase.PRODUCTION)

    async def _cooldown_phase(self):
        """Cooldown phase before shutdown"""
        self._transition_phase(CyclePhase.COOLDOWN)

        logger.info("Starting cooldown phase...")

        # Stop accepting new work
        self._running = False

        # Wait for pending computations
        await asyncio.sleep(5)

        # Final knowledge backup
        knowledge_data = self.lattice.export_knowledge()
        with open("ka_knowledge_final.json", 'w') as f:
            json.dump(knowledge_data, f)

        logger.info("Cooldown phase complete")

    async def _shutdown_phase(self):
        """Shutdown phase"""
        self._transition_phase(CyclePhase.SHUTDOWN)

        logger.info("Starting shutdown phase...")

        # Stop background tasks
        self._stop_background_tasks()

        # Shutdown lattice
        self.lattice.shutdown()

        # Final metrics
        self._log_final_metrics()

        logger.info("Shutdown phase complete")

    def _needs_maintenance(self) -> bool:
        """Check if maintenance is needed"""
        # Check error threshold
        if self.error_count >= self.config.max_errors_before_maintenance:
            return True

        # Check performance degradation
        if self.current_metrics and self.current_metrics.average_latency_ms > 100:
            return True

        return False

    def _start_background_tasks(self):
        """Start background monitoring and optimization tasks"""
        if self.config.enable_auto_optimization:
            self._optimization_thread = threading.Thread(
                target=self._optimization_loop,
                daemon=True
            )
            self._optimization_thread.start()

        if self.config.enable_health_checks:
            self._health_thread = threading.Thread(
                target=self._health_check_loop,
                daemon=True
            )
            self._health_thread.start()

    def _stop_background_tasks(self):
        """Stop background tasks"""
        self._stop_event.set()

        if self._optimization_thread:
            self._optimization_thread.join(timeout=5)

        if self._health_thread:
            self._health_thread.join(timeout=5)

    def _optimization_loop(self):
        """Background optimization loop"""
        while not self._stop_event.is_set():
            time.sleep(self.config.optimization_interval_seconds)

            if self.current_phase == CyclePhase.PRODUCTION:
                try:
                    asyncio.run(self._optimization_phase())
                except Exception as e:
                    logger.error(f"Background optimization error: {e}")

    def _health_check_loop(self):
        """Background health check loop"""
        while not self._stop_event.is_set():
            time.sleep(self.config.health_check_interval_seconds)

            try:
                # Check lattice health
                if self.lattice.state == LatticeState.ERROR:
                    logger.warning("Lattice in error state - triggering maintenance")
                    self.error_count = self.config.max_errors_before_maintenance

                # Log metrics
                if self.current_metrics:
                    logger.debug(f"Health: Phase={self.current_phase}, "
                               f"Throughput={self.current_metrics.throughput_per_second:.2f}/s, "
                               f"Latency={self.current_metrics.average_latency_ms:.2f}ms")

            except Exception as e:
                logger.error(f"Health check error: {e}")

    def _log_final_metrics(self):
        """Log final production metrics"""
        logger.info("=== Production Cycle Summary ===")
        logger.info(f"Total computations: {self.total_computations}")
        logger.info(f"Successful computations: {self.successful_computations}")

        if self.total_computations > 0:
            success_rate = (self.successful_computations / self.total_computations) * 100
            logger.info(f"Success rate: {success_rate:.2f}%")

        if self.computation_times:
            logger.info(f"Average latency: {np.mean(self.computation_times):.2f}ms")
            logger.info(f"P95 latency: {np.percentile(self.computation_times, 95):.2f}ms")
            logger.info(f"P99 latency: {np.percentile(self.computation_times, 99):.2f}ms")

        knowledge_stats = self.lattice.get_knowledge_stats()
        logger.info(f"Knowledge entries: {knowledge_stats['total_entries']}")
        logger.info(f"Knowledge hit rate: {knowledge_stats['hit_rate']:.2f}%")

    async def stop_production_cycle(self):
        """Stop the production cycle gracefully"""
        if not self._running:
            return

        logger.info("Stopping production cycle...")

        # Transition to cooldown
        await self._cooldown_phase()

        # Stop event
        self._stop_event.set()
        self._running = False

    def get_metrics(self) -> Dict[str, Any]:
        """Get current production metrics"""
        return {
            'current_phase': self.current_phase.value,
            'total_computations': self.total_computations,
            'successful_computations': self.successful_computations,
            'error_count': self.error_count,
            'current_metrics': {
                'computations': self.current_metrics.computations_processed,
                'latency_ms': self.current_metrics.average_latency_ms,
                'throughput_per_second': self.current_metrics.throughput_per_second
            } if self.current_metrics else None,
            'knowledge_stats': self.lattice.get_knowledge_stats()
        }