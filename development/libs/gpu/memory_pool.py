"""
GPU Memory Pool Manager - Reuse allocations to reduce overhead
Provides memory pooling for frequently used allocation sizes
"""

import logging
import time
from typing import Dict, Optional, List, Tuple, Any
from dataclasses import dataclass
from collections import defaultdict
from threading import Lock
import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class PooledAllocation:
    """Represents a pooled memory allocation"""
    size_mb: float
    allocated_time: float
    last_used_time: float
    use_count: int
    backend: str  # "pytorch", "cupy"
    data: Any  # The actual allocated buffer
    in_use: bool = False


class GPUMemoryPool:
    """
    Memory pool for GPU allocations
    Reuses allocations to reduce overhead and fragmentation
    """

    def __init__(
        self,
        device_id: int = 0,
        max_pool_size_mb: float = 2048.0,
        max_unused_time: float = 300.0,  # 5 minutes
        enable_size_rounding: bool = True
    ):
        """
        Initialize memory pool

        Args:
            device_id: GPU device ID
            max_pool_size_mb: Maximum total pool size in MB
            max_unused_time: Max time unused allocation kept (seconds)
            enable_size_rounding: Round allocation sizes to reduce fragmentation
        """
        self.device_id = device_id
        self.max_pool_size_mb = max_pool_size_mb
        self.max_unused_time = max_unused_time
        self.enable_size_rounding = enable_size_rounding

        # Thread safety
        self._lock = Lock()

        # Pool storage: {size_mb: [PooledAllocation, ...]}
        self._pool: Dict[float, List[PooledAllocation]] = defaultdict(list)

        # Statistics
        self._total_allocations = 0
        self._pool_hits = 0
        self._pool_misses = 0
        self._total_size_mb = 0.0

        # Detect backends
        self.pytorch_available = False
        self.cupy_available = False
        self._detect_backends()

        logger.info(f"GPUMemoryPool initialized: device={device_id}, "
                   f"max_size={max_pool_size_mb}MB, max_unused={max_unused_time}s")

    def _detect_backends(self):
        """Detect available GPU backends"""
        try:
            import torch
            if torch.cuda.is_available():
                self.pytorch_available = True
        except ImportError:
            pass

        try:
            import cupy as cp
            if cp.cuda.is_available():
                self.cupy_available = True
        except ImportError:
            pass

    def _round_size(self, size_mb: float) -> float:
        """
        Round allocation size to reduce fragmentation

        Args:
            size_mb: Requested size in MB

        Returns:
            Rounded size in MB
        """
        if not self.enable_size_rounding:
            return size_mb

        # Rounding strategy:
        # <1MB: round to 0.1MB
        # 1-10MB: round to 1MB
        # 10-100MB: round to 10MB
        # >100MB: round to 50MB

        if size_mb < 1.0:
            return np.ceil(size_mb * 10) / 10
        elif size_mb < 10.0:
            return np.ceil(size_mb)
        elif size_mb < 100.0:
            return np.ceil(size_mb / 10) * 10
        else:
            return np.ceil(size_mb / 50) * 50

    def allocate(
        self,
        size_mb: float,
        backend: str = "pytorch",
        dtype: Any = None
    ) -> Optional[Any]:
        """
        Allocate memory from pool or create new allocation

        Args:
            size_mb: Size in MB
            backend: Backend to use ("pytorch" or "cupy")
            dtype: Data type for allocation

        Returns:
            Allocated buffer or None on failure
        """
        with self._lock:
            rounded_size = self._round_size(size_mb)

            # Try to get from pool
            if rounded_size in self._pool and self._pool[rounded_size]:
                for allocation in self._pool[rounded_size]:
                    if not allocation.in_use and allocation.backend == backend:
                        # Reuse existing allocation
                        allocation.in_use = True
                        allocation.last_used_time = time.time()
                        allocation.use_count += 1
                        self._pool_hits += 1

                        logger.debug(f"Pool HIT: {rounded_size}MB from {backend} pool "
                                   f"(use_count={allocation.use_count})")
                        return allocation.data

            # Pool miss - create new allocation
            self._pool_misses += 1

            # Check if we have room in pool
            if self._total_size_mb + rounded_size > self.max_pool_size_mb:
                logger.warning(f"Pool full ({self._total_size_mb:.1f}MB / {self.max_pool_size_mb:.1f}MB), "
                             f"cleaning up unused allocations")
                self._cleanup_unused()

                # Still no room? Fail
                if self._total_size_mb + rounded_size > self.max_pool_size_mb:
                    logger.error(f"Cannot allocate {rounded_size}MB: pool exhausted")
                    return None

            # Create new allocation
            try:
                data = self._create_allocation(rounded_size, backend, dtype)

                allocation = PooledAllocation(
                    size_mb=rounded_size,
                    allocated_time=time.time(),
                    last_used_time=time.time(),
                    use_count=1,
                    backend=backend,
                    data=data,
                    in_use=True
                )

                self._pool[rounded_size].append(allocation)
                self._total_allocations += 1
                self._total_size_mb += rounded_size

                logger.debug(f"Pool MISS: allocated {rounded_size}MB from {backend} "
                           f"(total pool: {self._total_size_mb:.1f}MB)")

                return data

            except Exception as e:
                logger.error(f"Failed to allocate {rounded_size}MB: {e}")
                return None

    def _create_allocation(self, size_mb: float, backend: str, dtype: Any) -> Any:
        """Create a new GPU allocation"""
        size_bytes = int(size_mb * 1024 * 1024)

        if backend == "pytorch" and self.pytorch_available:
            import torch
            if dtype is None:
                dtype = torch.float32
            # Calculate number of elements based on dtype
            element_size = torch.finfo(dtype).bits // 8 if torch.is_floating_point(torch.tensor(0, dtype=dtype)) else 4
            num_elements = size_bytes // element_size
            return torch.zeros(num_elements, dtype=dtype, device=f'cuda:{self.device_id}')

        elif backend == "cupy" and self.cupy_available:
            import cupy as cp
            if dtype is None:
                dtype = cp.float32
            # Calculate number of elements
            element_size = cp.dtype(dtype).itemsize
            num_elements = size_bytes // element_size
            return cp.zeros(num_elements, dtype=dtype)

        else:
            raise ValueError(f"Backend {backend} not available or not supported")

    def release(self, data: Any, backend: str):
        """
        Release allocation back to pool

        Args:
            data: The allocated buffer
            backend: Backend used
        """
        with self._lock:
            # Find the allocation
            for size_mb, allocations in self._pool.items():
                for allocation in allocations:
                    if allocation.data is data and allocation.backend == backend:
                        allocation.in_use = False
                        allocation.last_used_time = time.time()
                        logger.debug(f"Released {size_mb}MB allocation back to pool")
                        return

            logger.warning(f"Attempted to release allocation not in pool")

    def _cleanup_unused(self):
        """Clean up unused allocations that haven't been used recently"""
        current_time = time.time()
        freed_mb = 0.0
        freed_count = 0

        for size_mb in list(self._pool.keys()):
            allocations_to_keep = []

            for allocation in self._pool[size_mb]:
                # Keep if in use or recently used
                age = current_time - allocation.last_used_time
                if allocation.in_use or age < self.max_unused_time:
                    allocations_to_keep.append(allocation)
                else:
                    # Free this allocation
                    self._free_allocation(allocation)
                    freed_mb += allocation.size_mb
                    freed_count += 1

            if allocations_to_keep:
                self._pool[size_mb] = allocations_to_keep
            else:
                del self._pool[size_mb]

        self._total_size_mb -= freed_mb

        if freed_count > 0:
            logger.info(f"Cleanup freed {freed_count} allocations ({freed_mb:.1f}MB)")

    def _free_allocation(self, allocation: PooledAllocation):
        """Free a single allocation"""
        try:
            # Backend-specific cleanup
            if allocation.backend == "pytorch":
                # PyTorch will automatically free on delete
                del allocation.data
            elif allocation.backend == "cupy":
                # CuPy will automatically free on delete
                del allocation.data
        except Exception as e:
            logger.error(f"Error freeing allocation: {e}")

    def clear(self):
        """Clear all pooled allocations"""
        with self._lock:
            freed_count = 0
            for size_mb, allocations in self._pool.items():
                for allocation in allocations:
                    if not allocation.in_use:
                        self._free_allocation(allocation)
                        freed_count += 1

            self._pool.clear()
            self._total_size_mb = 0.0

            logger.info(f"Pool cleared: {freed_count} allocations freed")

    def get_stats(self) -> Dict[str, Any]:
        """
        Get pool statistics

        Returns:
            Dict with pool statistics
        """
        with self._lock:
            total_allocations = sum(len(allocs) for allocs in self._pool.values())
            in_use_count = sum(
                1 for allocs in self._pool.values()
                for alloc in allocs if alloc.in_use
            )

            hit_rate = (self._pool_hits / (self._pool_hits + self._pool_misses) * 100
                       if (self._pool_hits + self._pool_misses) > 0 else 0)

            return {
                'total_allocations': total_allocations,
                'in_use_count': in_use_count,
                'available_count': total_allocations - in_use_count,
                'total_size_mb': self._total_size_mb,
                'max_size_mb': self.max_pool_size_mb,
                'utilization': (self._total_size_mb / self.max_pool_size_mb * 100
                               if self.max_pool_size_mb > 0 else 0),
                'pool_hits': self._pool_hits,
                'pool_misses': self._pool_misses,
                'hit_rate': hit_rate,
                'unique_sizes': len(self._pool)
            }

    def print_stats(self):
        """Print pool statistics"""
        stats = self.get_stats()
        print(f"\n{'='*60}")
        print("GPU MEMORY POOL STATISTICS")
        print(f"{'='*60}")
        print(f"Total Allocations: {stats['total_allocations']}")
        print(f"In Use: {stats['in_use_count']}")
        print(f"Available: {stats['available_count']}")
        print(f"Total Size: {stats['total_size_mb']:.1f}MB / {stats['max_size_mb']:.1f}MB ({stats['utilization']:.1f}%)")
        print(f"Pool Hits: {stats['pool_hits']}")
        print(f"Pool Misses: {stats['pool_misses']}")
        print(f"Hit Rate: {stats['hit_rate']:.1f}%")
        print(f"Unique Sizes: {stats['unique_sizes']}")
        print(f"{'='*60}\n")


# Global singleton
_global_memory_pool: Optional[GPUMemoryPool] = None
_pool_lock = Lock()


def get_memory_pool(
    device_id: int = 0,
    max_pool_size_mb: float = 2048.0
) -> GPUMemoryPool:
    """
    Get global memory pool instance (singleton)

    Args:
        device_id: GPU device ID
        max_pool_size_mb: Maximum pool size

    Returns:
        GPUMemoryPool instance
    """
    global _global_memory_pool

    with _pool_lock:
        if _global_memory_pool is None:
            _global_memory_pool = GPUMemoryPool(
                device_id=device_id,
                max_pool_size_mb=max_pool_size_mb
            )

        return _global_memory_pool