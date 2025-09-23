"""
Pure CUDA implementation using PyCUDA for lattice operations
"""

import time
import logging
from typing import Tuple, List, Optional, Any
import numpy as np

from .cupy_impl import CuPyLatticeGPU
from libs.utils.exceptions import GPUNotAvailableError

logger = logging.getLogger(__name__)


class CUDALatticeGPU(CuPyLatticeGPU):
    """
    CUDA implementation for lattice operations
    Currently inherits from CuPy implementation as CuPy provides
    excellent CUDA support. Can be replaced with PyCUDA if needed.
    """

    def __init__(self, dimensions: int, size: int, device_id: int = 0):
        """Initialize CUDA lattice GPU"""
        try:
            super().__init__(dimensions, size, device_id)
            logger.info("Using CUDA backend via CuPy")
        except ImportError:
            raise GPUNotAvailableError("CUDA backend requires CuPy to be installed")

    def get_device_capabilities(self):
        """Get CUDA device capabilities"""
        caps = super().get_device_capabilities()
        caps.backend_name = "cuda"
        return caps