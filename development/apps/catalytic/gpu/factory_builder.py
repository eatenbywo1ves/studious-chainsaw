"""
GPU Factory Builder Pattern
Provides fluent API for complex GPU lattice configurations
"""

from typing import Optional, Dict, Any, List
import logging

from libs.config import GPUBackend
from .backend_selector import (
    BackendRequirements,
    BackendSelectionStrategy,
    AutoBackendSelector,
    PerformanceBackendSelector,
    MemoryOptimizedBackendSelector,
)
from .factory_refactored import GPUFactoryRefactored
from .base import BaseLatticeGPU

logger = logging.getLogger(__name__)


class LatticeBuilder:
    """
    Builder for creating GPU lattice instances with fluent API.

    Example usage:
    ```python
    lattice = (LatticeBuilder()
        .with_dimensions(4)
        .with_size(10)
        .prefer_backend(GPUBackend.PYTORCH)
        .require_memory_mb(500)
        .optimize_for_performance()
        .build())
    ```
    """

    def __init__(self):
        """Initialize builder with default values"""
        self._dimensions: Optional[int] = None
        self._size: Optional[int] = None
        self._backend: Optional[GPUBackend] = None
        self._device_id: Optional[int] = None
        self._requirements = BackendRequirements()
        self._selection_strategy: BackendSelectionStrategy = AutoBackendSelector()
        self._extra_kwargs: Dict[str, Any] = {}

    def with_dimensions(self, dimensions: int) -> "LatticeBuilder":
        """Set number of dimensions"""
        self._dimensions = dimensions
        return self

    def with_size(self, size: int) -> "LatticeBuilder":
        """Set size in each dimension"""
        self._size = size
        return self

    def prefer_backend(self, backend: GPUBackend) -> "LatticeBuilder":
        """Prefer specific backend"""
        self._requirements.preferred_backend = backend
        return self

    def with_device(self, device_id: int) -> "LatticeBuilder":
        """Use specific device ID"""
        self._device_id = device_id
        return self

    def require_memory_mb(self, memory_mb: float) -> "LatticeBuilder":
        """Require minimum memory"""
        self._requirements.min_memory_mb = memory_mb
        return self

    def require_double_precision(self, required: bool = True) -> "LatticeBuilder":
        """Require double precision support"""
        self._requirements.require_double_precision = required
        return self

    def require_tensor_cores(self, required: bool = True) -> "LatticeBuilder":
        """Require tensor core support"""
        self._requirements.require_tensor_cores = required
        return self

    def allow_cpu_fallback(self, allowed: bool = True) -> "LatticeBuilder":
        """Allow CPU fallback if GPU unavailable"""
        self._requirements.allow_cpu_fallback = allowed
        return self

    def with_fallback_order(self, backends: List[GPUBackend]) -> "LatticeBuilder":
        """Set custom fallback order"""
        self._requirements.fallback_order = backends
        return self

    def optimize_for_performance(self) -> "LatticeBuilder":
        """Use performance-optimized backend selection"""
        self._selection_strategy = PerformanceBackendSelector()
        return self

    def optimize_for_memory(self) -> "LatticeBuilder":
        """Use memory-optimized backend selection"""
        self._selection_strategy = MemoryOptimizedBackendSelector()
        return self

    def with_custom_strategy(self, strategy: BackendSelectionStrategy) -> "LatticeBuilder":
        """Use custom backend selection strategy"""
        self._selection_strategy = strategy
        return self

    def with_kwargs(self, **kwargs) -> "LatticeBuilder":
        """Add extra keyword arguments for implementation"""
        self._extra_kwargs.update(kwargs)
        return self

    def build(self) -> BaseLatticeGPU:
        """
        Build the GPU lattice instance

        Returns:
            Configured GPU lattice

        Raises:
            ValueError: If required parameters not set
        """
        # Validate required parameters
        if self._dimensions is None:
            raise ValueError("Dimensions must be set")
        if self._size is None:
            raise ValueError("Size must be set")

        # Create factory
        factory = GPUFactoryRefactored()

        # Build lattice
        lattice = factory.create_with_strategy(
            dimensions=self._dimensions,
            size=self._size,
            requirements=self._requirements,
            strategy=self._selection_strategy,
            device_id=self._device_id,
            **self._extra_kwargs,
        )

        return lattice

    def estimate_memory_requirements(self) -> float:
        """
        Estimate memory requirements in MB

        Returns:
            Estimated memory in MB
        """
        if self._dimensions is None or self._size is None:
            raise ValueError("Dimensions and size must be set to estimate memory")

        n_points = self._size**self._dimensions
        # Adjacency matrix: n_points x n_points x 8 bytes (float64)
        estimated_memory_mb = (n_points * n_points * 8) / (1024**2)

        return estimated_memory_mb

    def validate(self) -> bool:
        """
        Validate configuration without building

        Returns:
            True if configuration is valid
        """
        try:
            if self._dimensions is None or self._size is None:
                return False

            # Check memory requirements
            estimated_memory = self.estimate_memory_requirements()

            # Warn if memory requirement is very high
            if estimated_memory > 1000:  # > 1GB
                logger.warning(
                    f"High memory requirement: {estimated_memory:.2f} MB. "
                    "Consider reducing dimensions or size."
                )

            return True

        except Exception as e:
            logger.error(f"Validation failed: {e}")
            return False

    def describe(self) -> Dict[str, Any]:
        """
        Get description of current configuration

        Returns:
            Dictionary describing the configuration
        """
        estimated_memory = None
        if self._dimensions and self._size:
            estimated_memory = self.estimate_memory_requirements()

        return {
            "dimensions": self._dimensions,
            "size": self._size,
            "preferred_backend": (
                self._requirements.preferred_backend.value
                if self._requirements.preferred_backend
                else None
            ),
            "device_id": self._device_id,
            "min_memory_mb": self._requirements.min_memory_mb,
            "estimated_memory_mb": estimated_memory,
            "require_double_precision": self._requirements.require_double_precision,
            "require_tensor_cores": self._requirements.require_tensor_cores,
            "allow_cpu_fallback": self._requirements.allow_cpu_fallback,
            "selection_strategy": type(self._selection_strategy).__name__,
            "extra_kwargs": self._extra_kwargs,
        }


# Convenience functions for common configurations


def create_small_lattice(**kwargs) -> BaseLatticeGPU:
    """Create small lattice (4D, size 5)"""
    return (
        LatticeBuilder()
        .with_dimensions(4)
        .with_size(5)
        .allow_cpu_fallback(True)
        .with_kwargs(**kwargs)
        .build()
    )


def create_medium_lattice(**kwargs) -> BaseLatticeGPU:
    """Create medium lattice (4D, size 10)"""
    return (
        LatticeBuilder()
        .with_dimensions(4)
        .with_size(10)
        .require_memory_mb(500)
        .optimize_for_performance()
        .with_kwargs(**kwargs)
        .build()
    )


def create_large_lattice(**kwargs) -> BaseLatticeGPU:
    """Create large lattice (5D, size 10)"""
    return (
        LatticeBuilder()
        .with_dimensions(5)
        .with_size(10)
        .require_memory_mb(2000)
        .optimize_for_memory()
        .allow_cpu_fallback(False)
        .with_kwargs(**kwargs)
        .build()
    )


def create_high_performance_lattice(dimensions: int, size: int, **kwargs) -> BaseLatticeGPU:
    """Create high-performance optimized lattice"""
    return (
        LatticeBuilder()
        .with_dimensions(dimensions)
        .with_size(size)
        .optimize_for_performance()
        .require_tensor_cores(False)  # Not required but preferred
        .with_kwargs(**kwargs)
        .build()
    )
