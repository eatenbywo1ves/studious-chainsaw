"""
GPU Memory Manager - Real-time monitoring, cleanup, and pressure management
Supports PyTorch and CuPy backends with unified interface
"""

import logging
import time
import gc
from typing import Dict, Optional, List, Tuple, Callable
from dataclasses import dataclass
from enum import Enum
from threading import Lock
import warnings

logger = logging.getLogger(__name__)


class MemoryPressure(Enum):
    """GPU memory pressure levels"""
    LOW = "low"          # <60% used
    MODERATE = "moderate"  # 60-80% used
    HIGH = "high"        # 80-90% used
    CRITICAL = "critical"  # >90% used


@dataclass
class MemorySnapshot:
    """Snapshot of GPU memory state at a point in time"""
    timestamp: float
    allocated_mb: float
    reserved_mb: float
    total_mb: float
    available_mb: float
    utilization: float  # Percentage 0-100
    pressure: MemoryPressure
    backend: str  # "pytorch", "cupy", or "unknown"
    device_id: int = 0


@dataclass
class MemoryStats:
    """Aggregated memory statistics"""
    current_snapshot: MemorySnapshot
    peak_allocated_mb: float
    peak_reserved_mb: float
    total_allocations: int
    total_deallocations: int
    total_gc_runs: int
    allocation_failures: int
    last_cleanup_time: float
    avg_utilization: float
    pressure_events: Dict[MemoryPressure, int]


class GPUMemoryMonitor:
    """
    Monitor GPU memory usage across different backends (PyTorch, CuPy)
    Provides real-time tracking, pressure detection, and cleanup strategies
    """

    # Memory pressure thresholds (percentage of total memory)
    PRESSURE_THRESHOLDS = {
        MemoryPressure.LOW: 0.6,
        MemoryPressure.MODERATE: 0.8,
        MemoryPressure.HIGH: 0.9,
        MemoryPressure.CRITICAL: 0.95
    }

    def __init__(
        self,
        device_id: int = 0,
        enable_auto_cleanup: bool = True,
        cleanup_threshold: float = 0.85,
        enable_leak_detection: bool = True
    ):
        """
        Initialize GPU memory monitor

        Args:
            device_id: GPU device ID to monitor
            enable_auto_cleanup: Enable automatic cleanup on high pressure
            cleanup_threshold: Memory utilization threshold for auto cleanup (0-1)
            enable_leak_detection: Enable memory leak detection
        """
        self.device_id = device_id
        self.enable_auto_cleanup = enable_auto_cleanup
        self.cleanup_threshold = cleanup_threshold
        self.enable_leak_detection = enable_leak_detection

        # Thread safety
        self._lock = Lock()

        # Detect available backends
        self.pytorch_available = False
        self.cupy_available = False
        self._detect_backends()

        # Statistics tracking
        self._snapshots: List[MemorySnapshot] = []
        self._max_snapshots = 1000  # Keep last 1000 snapshots
        self._peak_allocated = 0.0
        self._peak_reserved = 0.0
        self._total_allocations = 0
        self._total_deallocations = 0
        self._total_gc_runs = 0
        self._allocation_failures = 0
        self._last_cleanup_time = time.time()
        self._pressure_events = {level: 0 for level in MemoryPressure}

        # Leak detection
        self._allocation_history: List[Tuple[float, float]] = []  # (timestamp, allocated_mb)
        self._leak_detection_interval = 60.0  # Check every 60 seconds

        # Cleanup callbacks
        self._cleanup_callbacks: List[Callable[[], None]] = []

        logger.info(f"GPUMemoryMonitor initialized: device={device_id}, "
                   f"auto_cleanup={enable_auto_cleanup}, threshold={cleanup_threshold:.1%}")

    def _detect_backends(self):
        """Detect available GPU backends"""
        try:
            import torch
            if torch.cuda.is_available():
                self.pytorch_available = True
                logger.debug("PyTorch CUDA backend detected")
        except ImportError:
            pass

        try:
            import cupy as cp
            if cp.cuda.is_available():
                self.cupy_available = True
                logger.debug("CuPy backend detected")
        except ImportError:
            pass

        if not self.pytorch_available and not self.cupy_available:
            logger.warning("No GPU backends detected - memory monitoring limited")

    def get_memory_snapshot(self) -> MemorySnapshot:
        """
        Get current memory snapshot

        Returns:
            MemorySnapshot with current memory state
        """
        if self.pytorch_available:
            return self._get_pytorch_snapshot()
        elif self.cupy_available:
            return self._get_cupy_snapshot()
        else:
            return self._get_fallback_snapshot()

    def _get_pytorch_snapshot(self) -> MemorySnapshot:
        """Get memory snapshot from PyTorch"""
        try:
            import torch

            # Get memory stats
            allocated = torch.cuda.memory_allocated(self.device_id) / (1024 ** 2)
            reserved = torch.cuda.memory_reserved(self.device_id) / (1024 ** 2)

            # Get total memory
            props = torch.cuda.get_device_properties(self.device_id)
            total = props.total_memory / (1024 ** 2)

            available = total - allocated
            utilization = (allocated / total) * 100 if total > 0 else 0
            pressure = self._calculate_pressure(utilization)

            return MemorySnapshot(
                timestamp=time.time(),
                allocated_mb=allocated,
                reserved_mb=reserved,
                total_mb=total,
                available_mb=available,
                utilization=utilization,
                pressure=pressure,
                backend="pytorch",
                device_id=self.device_id
            )
        except Exception as e:
            logger.error(f"Error getting PyTorch memory snapshot: {e}")
            return self._get_fallback_snapshot()

    def _get_cupy_snapshot(self) -> MemorySnapshot:
        """Get memory snapshot from CuPy"""
        try:
            import cupy as cp

            # Get memory pool
            mempool = cp.get_default_memory_pool()

            # Get memory stats
            used = mempool.used_bytes() / (1024 ** 2)
            total_bytes = mempool.total_bytes() / (1024 ** 2)

            # Get device properties
            device = cp.cuda.Device(self.device_id)
            total_device = device.mem_info[1] / (1024 ** 2)  # Total memory

            # Use device total if pool total is not set
            total = total_device if total_device > 0 else total_bytes
            allocated = used
            reserved = total_bytes
            available = total - allocated
            utilization = (allocated / total) * 100 if total > 0 else 0
            pressure = self._calculate_pressure(utilization)

            return MemorySnapshot(
                timestamp=time.time(),
                allocated_mb=allocated,
                reserved_mb=reserved,
                total_mb=total,
                available_mb=available,
                utilization=utilization,
                pressure=pressure,
                backend="cupy",
                device_id=self.device_id
            )
        except Exception as e:
            logger.error(f"Error getting CuPy memory snapshot: {e}")
            return self._get_fallback_snapshot()

    def _get_fallback_snapshot(self) -> MemorySnapshot:
        """Fallback snapshot when no backend available"""
        return MemorySnapshot(
            timestamp=time.time(),
            allocated_mb=0.0,
            reserved_mb=0.0,
            total_mb=0.0,
            available_mb=0.0,
            utilization=0.0,
            pressure=MemoryPressure.LOW,
            backend="unknown",
            device_id=self.device_id
        )

    def _calculate_pressure(self, utilization: float) -> MemoryPressure:
        """Calculate memory pressure level from utilization percentage"""
        util_fraction = utilization / 100.0

        if util_fraction >= self.PRESSURE_THRESHOLDS[MemoryPressure.CRITICAL]:
            return MemoryPressure.CRITICAL
        elif util_fraction >= self.PRESSURE_THRESHOLDS[MemoryPressure.HIGH]:
            return MemoryPressure.HIGH
        elif util_fraction >= self.PRESSURE_THRESHOLDS[MemoryPressure.MODERATE]:
            return MemoryPressure.MODERATE
        else:
            return MemoryPressure.LOW

    def record_snapshot(self) -> MemorySnapshot:
        """
        Record a memory snapshot and store in history

        Returns:
            The recorded snapshot
        """
        with self._lock:
            snapshot = self.get_memory_snapshot()

            # Store snapshot
            self._snapshots.append(snapshot)
            if len(self._snapshots) > self._max_snapshots:
                self._snapshots.pop(0)

            # Update peak values
            if snapshot.allocated_mb > self._peak_allocated:
                self._peak_allocated = snapshot.allocated_mb

            if snapshot.reserved_mb > self._peak_reserved:
                self._peak_reserved = snapshot.reserved_mb

            # Track pressure events
            self._pressure_events[snapshot.pressure] += 1

            # Trigger auto cleanup if needed
            if self.enable_auto_cleanup:
                if snapshot.utilization / 100.0 >= self.cleanup_threshold:
                    logger.info(f"Auto cleanup triggered: {snapshot.utilization:.1f}% utilization")
                    self.cleanup_memory()

            # Check for memory leaks
            if self.enable_leak_detection:
                self._check_for_leaks(snapshot)

            return snapshot

    def _check_for_leaks(self, snapshot: MemorySnapshot):
        """Check for potential memory leaks"""
        self._allocation_history.append((snapshot.timestamp, snapshot.allocated_mb))

        # Keep only recent history (last 5 minutes)
        cutoff_time = snapshot.timestamp - 300
        self._allocation_history = [
            (t, mb) for t, mb in self._allocation_history if t >= cutoff_time
        ]

        # Need at least 10 samples for leak detection
        if len(self._allocation_history) < 10:
            return

        # Check if memory is consistently increasing
        allocations = [mb for _, mb in self._allocation_history]

        # Simple trend detection: compare first and last thirds
        third = len(allocations) // 3
        first_third_avg = sum(allocations[:third]) / third
        last_third_avg = sum(allocations[-third:]) / third

        # If memory increased by >20% consistently, possible leak
        if last_third_avg > first_third_avg * 1.2:
            increase_pct = ((last_third_avg - first_third_avg) / first_third_avg) * 100
            logger.warning(f"Potential memory leak detected: {increase_pct:.1f}% increase over 5 min")

    def cleanup_memory(self) -> Dict[str, float]:
        """
        Perform GPU memory cleanup

        Returns:
            Dict with cleanup results (before/after memory usage)
        """
        with self._lock:
            snapshot_before = self.get_memory_snapshot()

            logger.info(f"Starting memory cleanup: {snapshot_before.utilization:.1f}% used")

            # Run cleanup callbacks
            for callback in self._cleanup_callbacks:
                try:
                    callback()
                except Exception as e:
                    logger.error(f"Cleanup callback failed: {e}")

            # Backend-specific cleanup
            if self.pytorch_available:
                self._cleanup_pytorch()

            if self.cupy_available:
                self._cleanup_cupy()

            # Python garbage collection
            gc.collect()

            snapshot_after = self.get_memory_snapshot()
            freed_mb = snapshot_before.allocated_mb - snapshot_after.allocated_mb

            self._total_gc_runs += 1
            self._last_cleanup_time = time.time()

            logger.info(f"Memory cleanup complete: freed {freed_mb:.2f}MB, "
                       f"now {snapshot_after.utilization:.1f}% used")

            return {
                'before_mb': snapshot_before.allocated_mb,
                'after_mb': snapshot_after.allocated_mb,
                'freed_mb': freed_mb,
                'before_util': snapshot_before.utilization,
                'after_util': snapshot_after.utilization
            }

    def _cleanup_pytorch(self):
        """PyTorch-specific cleanup"""
        try:
            import torch
            torch.cuda.empty_cache()
            logger.debug("PyTorch cache cleared")
        except Exception as e:
            logger.error(f"PyTorch cleanup failed: {e}")

    def _cleanup_cupy(self):
        """CuPy-specific cleanup"""
        try:
            import cupy as cp
            mempool = cp.get_default_memory_pool()
            mempool.free_all_blocks()
            logger.debug("CuPy memory pool freed")
        except Exception as e:
            logger.error(f"CuPy cleanup failed: {e}")

    def register_cleanup_callback(self, callback: Callable[[], None]):
        """
        Register a callback to be called during cleanup

        Args:
            callback: Function to call during cleanup
        """
        self._cleanup_callbacks.append(callback)
        logger.debug(f"Registered cleanup callback: {callback.__name__}")

    def get_stats(self) -> MemoryStats:
        """
        Get aggregated memory statistics

        Returns:
            MemoryStats with current and historical data
        """
        with self._lock:
            current = self.get_memory_snapshot()

            # Calculate average utilization
            if self._snapshots:
                avg_util = sum(s.utilization for s in self._snapshots) / len(self._snapshots)
            else:
                avg_util = current.utilization

            return MemoryStats(
                current_snapshot=current,
                peak_allocated_mb=self._peak_allocated,
                peak_reserved_mb=self._peak_reserved,
                total_allocations=self._total_allocations,
                total_deallocations=self._total_deallocations,
                total_gc_runs=self._total_gc_runs,
                allocation_failures=self._allocation_failures,
                last_cleanup_time=self._last_cleanup_time,
                avg_utilization=avg_util,
                pressure_events=self._pressure_events.copy()
            )

    def get_pressure(self) -> MemoryPressure:
        """Get current memory pressure level"""
        snapshot = self.get_memory_snapshot()
        return snapshot.pressure

    def is_low_memory(self, threshold_mb: Optional[float] = None) -> bool:
        """
        Check if available memory is below threshold

        Args:
            threshold_mb: Memory threshold in MB (default: 500MB)

        Returns:
            True if available memory is below threshold
        """
        if threshold_mb is None:
            threshold_mb = 500.0

        snapshot = self.get_memory_snapshot()
        return snapshot.available_mb < threshold_mb

    def can_allocate(self, size_mb: float, safety_margin: float = 0.1) -> bool:
        """
        Check if we can safely allocate size_mb of memory

        Args:
            size_mb: Size to allocate in MB
            safety_margin: Safety margin (default: 10%)

        Returns:
            True if allocation should succeed
        """
        snapshot = self.get_memory_snapshot()
        required_mb = size_mb * (1 + safety_margin)
        return snapshot.available_mb >= required_mb

    def get_snapshot_history(self, last_n: Optional[int] = None) -> List[MemorySnapshot]:
        """
        Get historical snapshots

        Args:
            last_n: Number of recent snapshots to return (None = all)

        Returns:
            List of memory snapshots
        """
        with self._lock:
            if last_n is None:
                return self._snapshots.copy()
            else:
                return self._snapshots[-last_n:]

    def reset_stats(self):
        """Reset all statistics (useful for benchmarking)"""
        with self._lock:
            self._snapshots.clear()
            self._peak_allocated = 0.0
            self._peak_reserved = 0.0
            self._total_allocations = 0
            self._total_deallocations = 0
            self._total_gc_runs = 0
            self._allocation_failures = 0
            self._pressure_events = {level: 0 for level in MemoryPressure}
            self._allocation_history.clear()
            logger.info("Memory statistics reset")


# Global singleton instance
_global_memory_monitor: Optional[GPUMemoryMonitor] = None
_monitor_lock = Lock()


def get_memory_monitor(
    device_id: int = 0,
    enable_auto_cleanup: bool = True,
    cleanup_threshold: float = 0.85
) -> GPUMemoryMonitor:
    """
    Get global memory monitor instance (singleton)

    Args:
        device_id: GPU device ID
        enable_auto_cleanup: Enable automatic cleanup
        cleanup_threshold: Cleanup threshold

    Returns:
        GPUMemoryMonitor instance
    """
    global _global_memory_monitor

    with _monitor_lock:
        if _global_memory_monitor is None:
            _global_memory_monitor = GPUMemoryMonitor(
                device_id=device_id,
                enable_auto_cleanup=enable_auto_cleanup,
                cleanup_threshold=cleanup_threshold
            )

        return _global_memory_monitor