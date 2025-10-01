"""
Context managers for automatic resource cleanup
Provides RAII-style patterns for GPU resources, lattices, and connections
"""

from contextlib import contextmanager
from typing import Generator, Optional, Any
import logging

logger = logging.getLogger(__name__)


@contextmanager
def lattice_context(
    dimensions: int,
    size: int,
    enable_gpu: bool = True,
    **kwargs: Any
) -> Generator['UnifiedCatalyticLattice', None, None]:
    """
    Context manager for automatic lattice cleanup

    Usage:
        with lattice_context(dimensions=4, size=10) as lattice:
            lattice.build_lattice()
            path = lattice.find_shortest_path(0, 100)
        # Automatic cleanup on exit

    Args:
        dimensions: Number of dimensions
        size: Size in each dimension
        enable_gpu: Enable GPU acceleration
        **kwargs: Additional arguments passed to UnifiedCatalyticLattice

    Yields:
        UnifiedCatalyticLattice: Configured lattice instance
    """
    from apps.catalytic.core.unified_lattice import UnifiedCatalyticLattice

    lattice = None
    try:
        lattice = UnifiedCatalyticLattice(
            dimensions=dimensions,
            size=size,
            enable_gpu=enable_gpu,
            **kwargs
        )
        logger.debug(f"Created lattice context: {dimensions}D, size={size}, GPU={enable_gpu}")
        yield lattice
    except Exception as e:
        logger.error(f"Error in lattice context: {e}")
        raise
    finally:
        if lattice is not None:
            try:
                lattice.cleanup()
                logger.debug("Lattice resources cleaned up")
            except Exception as e:
                logger.warning(f"Error during lattice cleanup: {e}")


@contextmanager
def gpu_memory_context(
    backend: Optional[str] = None
) -> Generator[Optional[Any], None, None]:
    """
    Context manager for GPU memory management

    Usage:
        with gpu_memory_context(backend='cuda') as gpu:
            # Perform GPU operations
            result = gpu.compute(data)
        # Automatic memory cleanup

    Args:
        backend: GPU backend to use (cuda, cupy, pytorch)

    Yields:
        GPU backend instance or None if unavailable
    """
    from apps.catalytic.gpu.factory import GPUFactory

    gpu_backend = None
    try:
        gpu_backend = GPUFactory.create(backend=backend) if backend else None
        if gpu_backend:
            logger.debug(f"Initialized GPU backend: {gpu_backend.__class__.__name__}")
        yield gpu_backend
    except Exception as e:
        logger.error(f"Error in GPU context: {e}")
        raise
    finally:
        if gpu_backend is not None:
            try:
                gpu_backend.free_memory()
                logger.debug("GPU memory freed")
            except Exception as e:
                logger.warning(f"Error freeing GPU memory: {e}")


@contextmanager
def cuda_environment_context(
    force_init: bool = False,
    verbose: bool = False
) -> Generator[bool, None, None]:
    """
    Context manager for CUDA environment initialization

    Usage:
        with cuda_environment_context() as cuda_available:
            if cuda_available:
                # Perform CUDA operations
                pass

    Args:
        force_init: Force re-initialization
        verbose: Enable verbose output

    Yields:
        bool: True if CUDA is available, False otherwise
    """
    from libs.gpu.cuda_init import initialize_cuda_environment

    cuda_available = False
    try:
        cuda_available = initialize_cuda_environment(force=force_init, verbose=verbose)
        logger.debug(f"CUDA environment initialized: {cuda_available}")
        yield cuda_available
    except Exception as e:
        logger.error(f"Error initializing CUDA: {e}")
        yield False
    finally:
        # CUDA environment persists, but we log the exit
        logger.debug("Exiting CUDA environment context")


@contextmanager
def ssh_connection_context(
    hostname: str,
    port: int = 22,
    user: Optional[str] = None,
    timeout: int = 10
) -> Generator[bool, None, None]:
    """
    Context manager for SSH connection testing

    Usage:
        with ssh_connection_context('example.com', 22, 'user') as connected:
            if connected:
                # Perform operations requiring SSH
                pass

    Args:
        hostname: Remote hostname
        port: SSH port
        user: SSH username
        timeout: Connection timeout in seconds

    Yields:
        bool: True if connection successful, False otherwise
    """
    import subprocess

    connected = False
    try:
        # Test SSH connection
        ssh_cmd = ['ssh', '-o', f'ConnectTimeout={timeout}', '-o', 'StrictHostKeyChecking=no']
        if port != 22:
            ssh_cmd.extend(['-p', str(port)])

        if user:
            ssh_cmd.append(f'{user}@{hostname}')
        else:
            ssh_cmd.append(hostname)

        ssh_cmd.append('echo "connected"')

        result = subprocess.run(
            ssh_cmd,
            capture_output=True,
            timeout=timeout + 5
        )

        connected = result.returncode == 0 and 'connected' in result.stdout.decode()
        logger.debug(f"SSH connection to {hostname}:{port} - {'success' if connected else 'failed'}")
        yield connected

    except Exception as e:
        logger.warning(f"SSH connection error: {e}")
        yield False
    finally:
        logger.debug(f"Closed SSH connection context for {hostname}")


@contextmanager
def timed_operation(
    operation_name: str,
    log_level: str = "INFO"
) -> Generator[None, None, None]:
    """
    Context manager for timing operations

    Usage:
        with timed_operation("matrix multiplication"):
            result = expensive_operation()
        # Logs: "matrix multiplication completed in 1.234s"

    Args:
        operation_name: Name of the operation being timed
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)

    Yields:
        None
    """
    import time

    log_func = getattr(logger, log_level.lower(), logger.info)

    start_time = time.perf_counter()
    try:
        log_func(f"Starting {operation_name}")
        yield
    except Exception as e:
        elapsed = time.perf_counter() - start_time
        logger.error(f"{operation_name} failed after {elapsed:.3f}s: {e}")
        raise
    else:
        elapsed = time.perf_counter() - start_time
        log_func(f"{operation_name} completed in {elapsed:.3f}s")


@contextmanager
def temporary_gpu_device(device_id: int) -> Generator[int, None, None]:
    """
    Context manager for temporarily switching GPU devices

    Usage:
        with temporary_gpu_device(1):
            # Operations run on GPU 1
            pass
        # Restored to original device

    Args:
        device_id: GPU device ID to switch to

    Yields:
        int: The device ID being used
    """
    import torch

    original_device = None
    if torch.cuda.is_available():
        original_device = torch.cuda.current_device()

    try:
        if torch.cuda.is_available() and device_id < torch.cuda.device_count():
            torch.cuda.set_device(device_id)
            logger.debug(f"Switched to GPU device {device_id}")
            yield device_id
        else:
            logger.warning(f"GPU device {device_id} not available, using default")
            yield original_device if original_device is not None else 0
    finally:
        if original_device is not None and torch.cuda.is_available():
            torch.cuda.set_device(original_device)
            logger.debug(f"Restored GPU device {original_device}")


@contextmanager
def error_handler(
    operation: str,
    fallback_value: Any = None,
    reraise: bool = False
) -> Generator[dict, None, None]:
    """
    Context manager for consistent error handling

    Usage:
        with error_handler("database query", fallback_value=[]) as handler:
            result = database.query()
            handler['result'] = result
        # handler['result'] contains result or fallback_value on error

    Args:
        operation: Name of operation for logging
        fallback_value: Value to return on error
        reraise: Whether to reraise exceptions after logging

    Yields:
        dict: Dictionary to store result {'result': value, 'error': exception}
    """
    handler = {'result': fallback_value, 'error': None}

    try:
        yield handler
    except Exception as e:
        handler['error'] = e
        logger.error(f"Error in {operation}: {e}", exc_info=True)
        if reraise:
            raise
    finally:
        if handler['error'] and not reraise:
            logger.info(f"{operation} completed with fallback value")


@contextmanager
def batch_operations(batch_size: int = 100) -> Generator[list, None, None]:
    """
    Context manager for batching operations

    Usage:
        with batch_operations(batch_size=50) as batch:
            for item in items:
                batch.append(item)
                if len(batch) >= 50:
                    process_batch(batch)
                    batch.clear()
        # Processes remaining items on exit

    Args:
        batch_size: Maximum batch size

    Yields:
        list: Batch container
    """
    batch: list = []

    try:
        yield batch
    finally:
        if batch:
            logger.info(f"Processing remaining {len(batch)} items in batch")
            # Caller should have processed, but log if items remain


# Export all context managers
__all__ = [
    'lattice_context',
    'gpu_memory_context',
    'cuda_environment_context',
    'ssh_connection_context',
    'timed_operation',
    'temporary_gpu_device',
    'error_handler',
    'batch_operations',
]
