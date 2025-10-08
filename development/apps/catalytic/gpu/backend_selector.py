"""
GPU Backend Selection Strategy
Separates backend selection logic from factory creation logic
"""

from typing import Optional, List, Protocol
from dataclasses import dataclass
import logging

from libs.config import GPUBackend
from libs.utils.exceptions import GPUNotAvailableError
from .manager import get_gpu_manager

logger = logging.getLogger(__name__)


@dataclass
class BackendRequirements:
    """Requirements for backend selection"""

    preferred_backend: Optional[GPUBackend] = None
    min_memory_mb: Optional[float] = None
    require_double_precision: bool = False
    require_tensor_cores: bool = False
    allow_cpu_fallback: bool = True
    fallback_order: Optional[List[GPUBackend]] = None


class BackendSelectionStrategy(Protocol):
    """Protocol for backend selection strategies"""

    def select_backend(
        self, requirements: BackendRequirements, available_backends: List[GPUBackend]
    ) -> GPUBackend:
        """
        Select appropriate backend based on requirements

        Args:
            requirements: Backend requirements
            available_backends: List of available backends

        Returns:
            Selected backend

        Raises:
            GPUNotAvailableError: If no suitable backend available
        """
        ...


class AutoBackendSelector:
    """
    Automatic backend selection based on availability and requirements.

    Strategy:
    1. Check if preferred backend is available
    2. Check against requirements (memory, precision, etc.)
    3. Fall back to alternative backends in order
    4. Use CPU as last resort if allowed
    """

    def select_backend(
        self, requirements: BackendRequirements, available_backends: List[GPUBackend]
    ) -> GPUBackend:
        """Select backend using auto-selection strategy"""

        gpu_manager = get_gpu_manager()

        # If preferred backend specified and available, try it first
        if requirements.preferred_backend:
            if requirements.preferred_backend in available_backends:
                if self._meets_requirements(requirements.preferred_backend, requirements):
                    logger.info(f"Using preferred backend: {requirements.preferred_backend.value}")
                    return requirements.preferred_backend
                else:
                    logger.warning(
                        f"Preferred backend {requirements.preferred_backend.value} "
                        "doesn't meet requirements"
                    )

        # Try detected GPU backend
        detected_backend = gpu_manager.get_backend()
        if detected_backend in available_backends and detected_backend != GPUBackend.CPU:
            if self._meets_requirements(detected_backend, requirements):
                logger.info(f"Using auto-detected backend: {detected_backend.value}")
                return detected_backend

        # Try fallback backends
        fallback_order = requirements.fallback_order or [
            GPUBackend.PYTORCH,
            GPUBackend.CUPY,
            GPUBackend.CUDA,
        ]

        for backend in fallback_order:
            if backend in available_backends:
                if self._meets_requirements(backend, requirements):
                    logger.info(f"Using fallback backend: {backend.value}")
                    return backend

        # Try CPU fallback
        if requirements.allow_cpu_fallback and GPUBackend.CPU in available_backends:
            logger.info("Using CPU fallback")
            return GPUBackend.CPU

        # No suitable backend found
        raise GPUNotAvailableError("No suitable GPU backend available for given requirements")

    def _meets_requirements(self, backend: GPUBackend, requirements: BackendRequirements) -> bool:
        """Check if backend meets requirements"""

        # CPU always meets basic requirements
        if backend == GPUBackend.CPU:
            return True

        gpu_manager = get_gpu_manager()

        # Check if GPU available at all
        if not gpu_manager.is_gpu_available():
            return False

        try:
            # Get device capabilities
            devices = gpu_manager.get_all_devices()
            if not devices:
                return False

            # Check memory requirement
            if requirements.min_memory_mb:
                max_available_memory = max(d.available_memory_mb for d in devices.values())
                if max_available_memory < requirements.min_memory_mb:
                    logger.debug(
                        f"Backend {backend.value} doesn't meet memory requirement: "
                        f"{max_available_memory:.2f} MB < {requirements.min_memory_mb} MB"
                    )
                    return False

            # Check double precision requirement
            if requirements.require_double_precision:
                # All modern GPUs support double precision
                # Could add more specific checks here
                pass

            # Check tensor core requirement
            if requirements.require_tensor_cores:
                # Check if any device has tensor cores
                has_tensor_cores = any(d.supports_tensor_cores for d in devices.values())
                if not has_tensor_cores:
                    logger.debug(f"Backend {backend.value} doesn't have tensor cores")
                    return False

            return True

        except Exception as e:
            logger.warning(f"Error checking backend {backend.value}: {e}")
            return False


class PerformanceBackendSelector:
    """
    Select backend based on performance characteristics.

    Prefers backends in order of typical performance:
    1. CUDA (lowest level, maximum control)
    2. PyTorch (highly optimized, good for tensor operations)
    3. CuPy (NumPy-like interface)
    4. CPU (fallback)
    """

    PERFORMANCE_ORDER = [
        GPUBackend.CUDA,
        GPUBackend.PYTORCH,
        GPUBackend.CUPY,
    ]

    def select_backend(
        self, requirements: BackendRequirements, available_backends: List[GPUBackend]
    ) -> GPUBackend:
        """Select backend prioritizing performance"""

        selector = AutoBackendSelector()

        # Try backends in performance order
        for backend in self.PERFORMANCE_ORDER:
            if backend in available_backends:
                if selector._meets_requirements(backend, requirements):
                    logger.info(f"Selected high-performance backend: {backend.value}")
                    return backend

        # Fall back to CPU if allowed
        if requirements.allow_cpu_fallback and GPUBackend.CPU in available_backends:
            logger.info("Using CPU fallback for performance selector")
            return GPUBackend.CPU

        raise GPUNotAvailableError("No performance backend available")


class MemoryOptimizedBackendSelector:
    """
    Select backend optimized for memory efficiency.

    Considers:
    - Available device memory
    - Backend memory management overhead
    - Ability to use unified memory
    """

    def select_backend(
        self, requirements: BackendRequirements, available_backends: List[GPUBackend]
    ) -> GPUBackend:
        """Select backend optimized for memory usage"""

        gpu_manager = get_gpu_manager()
        selector = AutoBackendSelector()

        if not gpu_manager.is_gpu_available():
            if requirements.allow_cpu_fallback and GPUBackend.CPU in available_backends:
                return GPUBackend.CPU
            raise GPUNotAvailableError("No GPU available")

        # Find backend with best memory availability
        best_backend = None
        max_memory = 0

        for backend in available_backends:
            if backend == GPUBackend.CPU:
                continue

            if selector._meets_requirements(backend, requirements):
                devices = gpu_manager.get_all_devices()
                total_memory = sum(d.available_memory_mb for d in devices.values())

                if total_memory > max_memory:
                    max_memory = total_memory
                    best_backend = backend

        if best_backend:
            logger.info(
                f"Selected memory-optimized backend: {best_backend.value} "
                f"({max_memory:.2f} MB available)"
            )
            return best_backend

        # Fall back to auto selection
        return selector.select_backend(requirements, available_backends)
