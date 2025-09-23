"""
GPU acceleration module for Catalytic Computing
Provides unified interface for multiple GPU backends
"""

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