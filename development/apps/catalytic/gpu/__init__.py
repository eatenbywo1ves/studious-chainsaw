"""
GPU acceleration module for Catalytic Computing
Provides unified interface for multiple GPU backends

IMPORTANT: This module auto-initializes CUDA environment on import.
Requires Python 3.12 with PyTorch 2.5.1+cu121 for full GPU support.
"""

# Initialize CUDA environment before importing GPU components
# This solves CURAND_STATUS_INITIALIZATION_FAILED issues
try:
    from libs.gpu.cuda_init import initialize_cuda_environment
    initialize_cuda_environment(verbose=False)
except Exception as e:
    import logging
    logging.getLogger(__name__).warning(f"CUDA initialization failed: {e}")

from .base import BaseLatticeGPU, GPUCapabilities
from .manager import GPUManager
from .factory import GPUFactory

# Import concrete implementations
from .cuda_impl import CUDALatticeGPU
from .cupy_impl import CuPyLatticeGPU
from .pytorch_impl import PyTorchLatticeGPU
from .cpu_impl import CPULattice

__all__ = [
    'BaseLatticeGPU',
    'GPUCapabilities',
    'GPUManager',
    'GPUFactory',
    'CUDALatticeGPU',
    'CuPyLatticeGPU',
    'PyTorchLatticeGPU',
    'CPULattice'
]