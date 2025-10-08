"""
Refactored GPU Factory with Strategy Pattern
Clean separation of concerns with better error handling
"""

from typing import Optional, Dict, Type, List
import logging

from libs.config import GPUBackend
from libs.utils.exceptions import GPUNotAvailableError
from .base import BaseLatticeGPU
from .manager import get_gpu_manager
from .backend_selector import (
    BackendSelectionStrategy,
    BackendRequirements,
    AutoBackendSelector,
)

logger = logging.getLogger(__name__)


class DeviceSelector:
    """
    Handles device selection logic separately from factory.

    Responsibilities:
    - Select best available device based on requirements
    - Validate device availability
    - Handle device allocation failures
    """

    @staticmethod
    def select_device(
        backend: GPUBackend,
        device_id: Optional[int] = None,
        min_memory_mb: Optional[float] = None,
    ) -> int:
        """
        Select appropriate device ID

        Args:
            backend: Backend type
            device_id: Preferred device ID (None = auto-select)
            min_memory_mb: Minimum required memory

        Returns:
            Selected device ID

        Raises:
            GPUNotAvailableError: If no suitable device available
        """
        # CPU always uses device 0
        if backend == GPUBackend.CPU:
            return 0

        gpu_manager = get_gpu_manager()

        # If specific device requested, validate it
        if device_id is not None:
            devices = gpu_manager.get_all_devices()
            if device_id not in devices:
                raise GPUNotAvailableError(f"Device {device_id} not available")

            device = devices[device_id]

            # Check memory requirement
            if min_memory_mb and device.available_memory_mb < min_memory_mb:
                raise GPUNotAvailableError(
                    f"Device {device_id} has insufficient memory: "
                    f"{device.available_memory_mb:.2f} MB < {min_memory_mb} MB"
                )

            return device_id

        # Auto-select best device
        try:
            best_device_id = gpu_manager.get_best_device()

            # Validate memory if required
            if min_memory_mb:
                devices = gpu_manager.get_all_devices()
                if best_device_id in devices:
                    device = devices[best_device_id]
                    if device.available_memory_mb < min_memory_mb:
                        # Try to find device with enough memory
                        for dev_id, dev in devices.items():
                            if dev.available_memory_mb >= min_memory_mb:
                                logger.info(
                                    f"Selected device {dev_id} with "
                                    f"{dev.available_memory_mb:.2f} MB"
                                )
                                return dev_id

                        raise GPUNotAvailableError(f"No device with {min_memory_mb} MB available")

            return best_device_id

        except GPUNotAvailableError:
            raise
        except Exception as e:
            raise GPUNotAvailableError(f"Device selection failed: {e}")


class GPUFactoryRefactored:
    """
    Refactored GPU Factory with clean architecture.

    Improvements:
    - Strategy pattern for backend selection
    - Separated device selection logic
    - Better error handling with specific exception types
    - Cleaner registration mechanism
    - Support for dependency injection of strategies
    """

    # Registry of available implementations
    _implementations: Dict[GPUBackend, Type[BaseLatticeGPU]] = {}

    @classmethod
    def register(cls, backend: GPUBackend, implementation: Type[BaseLatticeGPU]):
        """Register a GPU implementation"""
        cls._implementations[backend] = implementation
        logger.debug(f"Registered {backend.value} implementation: {implementation.__name__}")

    @classmethod
    def unregister(cls, backend: GPUBackend):
        """Unregister a backend (useful for testing)"""
        if backend in cls._implementations:
            del cls._implementations[backend]

    @classmethod
    def list_available_backends(cls) -> List[GPUBackend]:
        """List all registered backends"""
        return list(cls._implementations.keys())

    @classmethod
    def is_backend_available(cls, backend: GPUBackend) -> bool:
        """Check if a specific backend is registered"""
        return backend in cls._implementations

    @classmethod
    def create(
        cls,
        dimensions: int,
        size: int,
        backend: Optional[GPUBackend] = None,
        device_id: Optional[int] = None,
        **kwargs,
    ) -> BaseLatticeGPU:
        """
        Create a GPU lattice instance (backward compatible API)

        Args:
            dimensions: Number of dimensions
            size: Size in each dimension
            backend: Specific backend (auto-detect if None)
            device_id: Specific device ID (auto-select if None)
            **kwargs: Additional arguments for implementation

        Returns:
            GPU lattice instance

        Raises:
            GPUNotAvailableError: If no suitable backend available
        """
        # Use auto selector if no backend specified
        if backend is None:
            requirements = BackendRequirements()
            strategy = AutoBackendSelector()
            return cls.create_with_strategy(
                dimensions=dimensions,
                size=size,
                requirements=requirements,
                strategy=strategy,
                device_id=device_id,
                **kwargs,
            )

        # Create with specific backend
        return cls._create_instance(
            backend=backend, dimensions=dimensions, size=size, device_id=device_id, **kwargs
        )

    @classmethod
    def create_with_strategy(
        cls,
        dimensions: int,
        size: int,
        requirements: BackendRequirements,
        strategy: BackendSelectionStrategy,
        device_id: Optional[int] = None,
        **kwargs,
    ) -> BaseLatticeGPU:
        """
        Create instance using backend selection strategy

        Args:
            dimensions: Number of dimensions
            size: Size in each dimension
            requirements: Backend requirements
            strategy: Selection strategy
            device_id: Specific device ID
            **kwargs: Additional arguments

        Returns:
            GPU lattice instance
        """
        # Select backend using strategy
        available_backends = cls.list_available_backends()
        backend = strategy.select_backend(requirements, available_backends)

        # Create instance
        return cls._create_instance(
            backend=backend,
            dimensions=dimensions,
            size=size,
            device_id=device_id,
            min_memory_mb=requirements.min_memory_mb,
            **kwargs,
        )

    @classmethod
    def _create_instance(
        cls,
        backend: GPUBackend,
        dimensions: int,
        size: int,
        device_id: Optional[int] = None,
        min_memory_mb: Optional[float] = None,
        **kwargs,
    ) -> BaseLatticeGPU:
        """
        Internal method to create instance with selected backend

        Args:
            backend: Selected backend
            dimensions: Number of dimensions
            size: Size in each dimension
            device_id: Specific device ID
            min_memory_mb: Minimum required memory
            **kwargs: Additional arguments

        Returns:
            GPU lattice instance

        Raises:
            GPUNotAvailableError: If creation fails
        """
        # Get implementation class
        implementation_class = cls._implementations.get(backend)
        if implementation_class is None:
            raise GPUNotAvailableError(f"No implementation available for backend: {backend.value}")

        # Select device
        device_selector = DeviceSelector()
        selected_device = device_selector.select_device(
            backend=backend,
            device_id=device_id,
            min_memory_mb=min_memory_mb,
        )

        logger.info(
            f"Creating {backend.value} lattice "
            f"(device={selected_device}, dimensions={dimensions}, size={size})"
        )

        try:
            # Create instance
            instance = implementation_class(
                dimensions=dimensions, size=size, device_id=selected_device, **kwargs
            )

            # Initialize the device
            if not instance.initialize_device():
                raise GPUNotAvailableError(f"Failed to initialize {backend.value} device")

            logger.info(f"✅ {backend.value} lattice created successfully")
            return instance

        except GPUNotAvailableError:
            raise
        except Exception as e:
            logger.error(f"Failed to create {backend.value} implementation: {e}")
            raise GPUNotAvailableError(f"Failed to create {backend.value} lattice: {e}")

    @classmethod
    def benchmark_backends(cls, dimensions: int = 4, size: int = 10) -> Dict[str, Dict]:
        """
        Benchmark all available backends

        Args:
            dimensions: Test dimensions
            size: Test size

        Returns:
            Benchmark results for each backend
        """
        results = {}

        for backend in cls._implementations:
            try:
                logger.info(f"Benchmarking {backend.value}")
                instance = cls.create(dimensions=dimensions, size=size, backend=backend)

                with instance:
                    benchmark_results = instance.benchmark()
                    results[backend.value] = {**benchmark_results, "status": "success"}

            except Exception as e:
                logger.warning(f"Failed to benchmark {backend.value}: {e}")
                results[backend.value] = {"status": "failed", "error": str(e)}

        return results


# Import and register implementations
def register_implementations():
    """Register all available GPU implementations"""
    try:
        from .cuda_impl import CUDALatticeGPU

        GPUFactoryRefactored.register(GPUBackend.CUDA, CUDALatticeGPU)
    except ImportError:
        logger.debug("CUDA implementation not available")

    try:
        from .cupy_impl import CuPyLatticeGPU

        GPUFactoryRefactored.register(GPUBackend.CUPY, CuPyLatticeGPU)
    except ImportError:
        logger.debug("CuPy implementation not available")

    try:
        from .pytorch_impl import PyTorchLatticeGPU

        GPUFactoryRefactored.register(GPUBackend.PYTORCH, PyTorchLatticeGPU)
    except ImportError:
        logger.debug("PyTorch implementation not available")

    # CPU fallback is always available
    from .cpu_impl import CPULattice

    GPUFactoryRefactored.register(GPUBackend.CPU, CPULattice)


# Auto-register on import
register_implementations()
