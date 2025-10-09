"""
GPU Factory - Creates appropriate GPU implementation based on configuration and availability
"""

from typing import Optional, Dict, Type, List
import logging

from libs.config import get_settings, GPUBackend
from libs.utils.exceptions import GPUNotAvailableError
from .base import BaseLatticeGPU
from .manager import get_gpu_manager

logger = logging.getLogger(__name__)


class GPUFactory:
    """
    Factory class for creating GPU lattice implementations
    Uses strategy pattern to select appropriate backend
    """

    # Registry of available implementations
    _implementations: Dict[GPUBackend, Type[BaseLatticeGPU]] = {}

    @classmethod
    def register(cls, backend: GPUBackend, implementation: Type[BaseLatticeGPU]):
        """
        Register a GPU implementation

        Args:
            backend: Backend identifier
            implementation: Implementation class
        """
        cls._implementations[backend] = implementation
        logger.debug(f"Registered {backend.value} implementation: {implementation.__name__}")

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
        Create a GPU lattice instance with the appropriate backend

        Args:
            dimensions: Number of dimensions
            size: Size in each dimension
            backend: Specific backend to use (auto-detect if None)
            device_id: Specific device ID (auto-select if None)
            **kwargs: Additional arguments for the implementation

        Returns:
            GPU lattice instance

        Raises:
            GPUNotAvailableError: If no suitable backend is available
        """
        config = get_settings()
        gpu_manager = get_gpu_manager()

        # Determine backend to use
        if backend is None:
            # Auto-detect based on availability
            backend = gpu_manager.get_backend()
            logger.info(f"Auto-detected backend: {backend.value}")
        else:
            # Verify requested backend is available
            if backend != gpu_manager.get_backend() and backend != GPUBackend.CPU:
                logger.warning(
                    f"Requested backend {backend.value} not available, using {gpu_manager.get_backend().value}"
                )
                backend = gpu_manager.get_backend()

        # Get implementation class
        implementation_class = cls._implementations.get(backend)
        if implementation_class is None:
            # Try fallback backends
            fallbacks = config.gpu.fallback_backends
            for fallback in fallbacks:
                if fallback in cls._implementations:
                    logger.info(f"Using fallback backend: {fallback.value}")
                    backend = fallback
                    implementation_class = cls._implementations[fallback]
                    break

        if implementation_class is None:
            raise GPUNotAvailableError(f"No implementation available for backend: {backend.value}")

        # Select device
        if device_id is None and backend != GPUBackend.CPU:
            try:
                device_id = gpu_manager.get_best_device()
            except GPUNotAvailableError:
                # Fallback to CPU if no GPU available
                logger.warning("No GPU devices available, falling back to CPU")
                backend = GPUBackend.CPU
                implementation_class = cls._implementations.get(GPUBackend.CPU)
                if implementation_class is None:
                    raise GPUNotAvailableError("No CPU fallback implementation available")
                device_id = 0

        # Create instance
        logger.info(
            f"Creating {backend.value} lattice (device={device_id}, dimensions={dimensions}, size={size})"
        )

        try:
            instance = implementation_class(
                dimensions=dimensions, size=size, device_id=device_id or 0, **kwargs
            )

            # Initialize the device
            if not instance.initialize_device():
                raise GPUNotAvailableError(f"Failed to initialize {backend.value} device")

            return instance

        except Exception as e:
            logger.error(f"Failed to create {backend.value} implementation: {e}")

            # Try CPU fallback
            if backend != GPUBackend.CPU and GPUBackend.CPU in cls._implementations:
                logger.info("Attempting CPU fallback")
                return cls.create(
                    dimensions=dimensions, size=size, backend=GPUBackend.CPU, device_id=0, **kwargs
                )
            raise

    @classmethod
    def create_best(
        cls, dimensions: int, size: int, prefer_memory: bool = False, **kwargs
    ) -> BaseLatticeGPU:
        """
        Create the best available GPU lattice based on requirements

        Args:
            dimensions: Number of dimensions
            size: Size in each dimension
            prefer_memory: Prefer device with more memory over speed
            **kwargs: Additional arguments

        Returns:
            Best available GPU lattice instance
        """
        gpu_manager = get_gpu_manager()

        # Estimate memory requirements
        n_points = size**dimensions
        estimated_memory_mb = (n_points * n_points * 8) / (1024**2)

        logger.info(f"Estimated memory requirement: {estimated_memory_mb:.2f} MB")

        if prefer_memory and gpu_manager.is_gpu_available():
            # Find device with most available memory
            devices = gpu_manager.get_all_devices()
            best_device = max(devices.items(), key=lambda x: x[1].available_memory_mb)

            if best_device[1].available_memory_mb >= estimated_memory_mb:
                logger.info(
                    f"Selected device {best_device[0]} with {best_device[1].available_memory_mb:.2f} MB available"
                )
                return cls.create(
                    dimensions=dimensions, size=size, device_id=best_device[0], **kwargs
                )

        # Default to auto-selection
        return cls.create(dimensions=dimensions, size=size, **kwargs)

    @classmethod
    def list_available_backends(cls) -> List[GPUBackend]:
        """
        List all registered backends

        Returns:
            List of available backends
        """
        return list(cls._implementations.keys())

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
                    results[backend.value] = instance.benchmark()
                    results[backend.value]["status"] = "success"

            except Exception as e:
                logger.warning(f"Failed to benchmark {backend.value}: {e}")
                results[backend.value] = {"status": "failed", "error": str(e)}

        return results


# Import and register implementations
def register_implementations():
    """Register all available GPU implementations"""
    try:
        from .cuda_impl import CUDALatticeGPU

        GPUFactory.register(GPUBackend.CUDA, CUDALatticeGPU)
    except ImportError:
        logger.debug("CUDA implementation not available")

    try:
        from .cupy_impl import CuPyLatticeGPU

        GPUFactory.register(GPUBackend.CUPY, CuPyLatticeGPU)
    except ImportError:
        logger.debug("CuPy implementation not available")

    try:
        from .pytorch_impl import PyTorchLatticeGPU

        GPUFactory.register(GPUBackend.PYTORCH, PyTorchLatticeGPU)
    except ImportError:
        logger.debug("PyTorch implementation not available")

    # CPU fallback is always available
    from .cpu_impl import CPULattice

    GPUFactory.register(GPUBackend.CPU, CPULattice)


# Auto-register on import
register_implementations()
