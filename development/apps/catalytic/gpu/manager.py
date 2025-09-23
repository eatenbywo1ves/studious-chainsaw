"""
GPU Manager - Singleton for managing GPU resources and device selection
"""

import os
import threading
from typing import Optional, List, Dict, Any
from enum import Enum
import logging

from libs.config import get_settings, GPUBackend
from libs.utils.exceptions import GPUNotAvailableError, GPUException
from .base import GPUCapabilities

logger = logging.getLogger(__name__)


class GPUStatus(Enum):
    """GPU availability status"""
    AVAILABLE = "available"
    BUSY = "busy"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class GPUManager:
    """
    Singleton manager for GPU resources
    Handles device detection, selection, and resource management
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """Initialize GPU manager (only runs once due to singleton)"""
        if self._initialized:
            return

        self.config = get_settings()
        self.devices: Dict[int, GPUCapabilities] = {}
        self.device_status: Dict[int, GPUStatus] = {}
        self.selected_device_id: Optional[int] = None
        self.backend: Optional[GPUBackend] = None

        # Detect available devices
        self._detect_devices()
        self._initialized = True

    def _detect_devices(self):
        """Detect available GPU devices across all backends"""
        self.devices.clear()
        self.device_status.clear()

        # Try CUDA devices
        if self._detect_cuda_devices():
            self.backend = GPUBackend.CUDA
        # Try CuPy
        elif self._detect_cupy_devices():
            self.backend = GPUBackend.CUPY
        # Try PyTorch
        elif self._detect_pytorch_devices():
            self.backend = GPUBackend.PYTORCH
        # Fallback to CPU
        else:
            logger.info("No GPU devices found, using CPU backend")
            self.backend = GPUBackend.CPU
            self.devices[0] = GPUCapabilities(
                device_name="CPU",
                device_id=0,
                total_memory_mb=self._get_cpu_memory(),
                available_memory_mb=self._get_cpu_memory() * 0.8,
                backend_name="cpu"
            )
            self.device_status[0] = GPUStatus.AVAILABLE

    def _detect_cuda_devices(self) -> bool:
        """Detect CUDA devices using pycuda or torch"""
        try:
            import torch
            if not torch.cuda.is_available():
                return False

            device_count = torch.cuda.device_count()
            for i in range(device_count):
                props = torch.cuda.get_device_properties(i)
                total_mem = props.total_memory / (1024 ** 2)

                # Get available memory
                torch.cuda.set_device(i)
                free_mem = torch.cuda.mem_get_info()[0] / (1024 ** 2)

                self.devices[i] = GPUCapabilities(
                    device_name=props.name,
                    device_id=i,
                    total_memory_mb=total_mem,
                    available_memory_mb=free_mem,
                    compute_capability=(props.major, props.minor),
                    max_threads_per_block=props.max_threads_per_block,
                    max_blocks=props.max_threads_per_multiprocessor,
                    warp_size=props.warp_size,
                    backend_name="cuda"
                )
                self.device_status[i] = GPUStatus.AVAILABLE

            logger.info(f"Detected {device_count} CUDA devices")
            return device_count > 0

        except ImportError:
            logger.debug("PyTorch not available for CUDA detection")
        except Exception as e:
            logger.warning(f"Error detecting CUDA devices: {e}")

        return False

    def _detect_cupy_devices(self) -> bool:
        """Detect CuPy GPU devices"""
        try:
            import cupy as cp

            device_count = cp.cuda.runtime.getDeviceCount()
            for i in range(device_count):
                cp.cuda.Device(i).use()
                props = cp.cuda.runtime.getDeviceProperties(i)

                mem_info = cp.cuda.runtime.memGetInfo()
                free_mem = mem_info[0] / (1024 ** 2)
                total_mem = mem_info[1] / (1024 ** 2)

                self.devices[i] = GPUCapabilities(
                    device_name=props['name'].decode('utf-8') if isinstance(props['name'], bytes) else props['name'],
                    device_id=i,
                    total_memory_mb=total_mem,
                    available_memory_mb=free_mem,
                    compute_capability=(props['major'], props['minor']),
                    max_threads_per_block=props['maxThreadsPerBlock'],
                    backend_name="cupy"
                )
                self.device_status[i] = GPUStatus.AVAILABLE

            logger.info(f"Detected {device_count} CuPy devices")
            return device_count > 0

        except ImportError:
            logger.debug("CuPy not available")
        except Exception as e:
            logger.warning(f"Error detecting CuPy devices: {e}")

        return False

    def _detect_pytorch_devices(self) -> bool:
        """Detect PyTorch GPU devices"""
        try:
            import torch
            if torch.cuda.is_available():
                # Already detected via CUDA
                return False

            # Check for other accelerators (MPS on Mac, etc.)
            if hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
                self.devices[0] = GPUCapabilities(
                    device_name="Apple Metal Performance Shaders",
                    device_id=0,
                    total_memory_mb=8192,  # Default estimate
                    available_memory_mb=6144,
                    backend_name="pytorch-mps"
                )
                self.device_status[0] = GPUStatus.AVAILABLE
                logger.info("Detected MPS device")
                return True

        except ImportError:
            logger.debug("PyTorch not available")
        except Exception as e:
            logger.warning(f"Error detecting PyTorch devices: {e}")

        return False

    def _get_cpu_memory(self) -> float:
        """Get available CPU memory in MB"""
        try:
            import psutil
            return psutil.virtual_memory().available / (1024 ** 2)
        except ImportError:
            # Fallback to a reasonable default
            return 8192.0

    def get_best_device(self) -> int:
        """
        Select the best available GPU device based on memory and status

        Returns:
            Device ID of the best available device
        """
        if not self.devices:
            raise GPUNotAvailableError("No GPU devices available")

        # Filter available devices
        available = [
            (id, caps) for id, caps in self.devices.items()
            if self.device_status.get(id) == GPUStatus.AVAILABLE
        ]

        if not available:
            raise GPUNotAvailableError("All GPU devices are busy or unavailable")

        # Sort by available memory
        available.sort(key=lambda x: x[1].available_memory_mb, reverse=True)

        # Check if auto-select is enabled
        if self.config.gpu.auto_select_device:
            selected_id = available[0][0]
            logger.info(f"Auto-selected device {selected_id}: {available[0][1].device_name}")
        else:
            # Use configured device if available
            configured_id = self.config.gpu.cuda_device_id
            if configured_id in dict(available):
                selected_id = configured_id
            else:
                selected_id = available[0][0]
                logger.warning(f"Configured device {configured_id} not available, using {selected_id}")

        self.selected_device_id = selected_id
        return selected_id

    def acquire_device(self, device_id: Optional[int] = None) -> int:
        """
        Acquire a GPU device for exclusive use

        Args:
            device_id: Specific device to acquire, or None for auto-select

        Returns:
            Acquired device ID
        """
        if device_id is None:
            device_id = self.get_best_device()

        if device_id not in self.devices:
            raise GPUException(f"Device {device_id} not found")

        if self.device_status.get(device_id) != GPUStatus.AVAILABLE:
            raise GPUException(f"Device {device_id} is not available")

        self.device_status[device_id] = GPUStatus.BUSY
        logger.debug(f"Acquired device {device_id}")
        return device_id

    def release_device(self, device_id: int):
        """
        Release a GPU device

        Args:
            device_id: Device to release
        """
        if device_id in self.device_status:
            self.device_status[device_id] = GPUStatus.AVAILABLE
            logger.debug(f"Released device {device_id}")

    def get_device_info(self, device_id: Optional[int] = None) -> GPUCapabilities:
        """
        Get device capabilities

        Args:
            device_id: Device ID, or None for selected device

        Returns:
            Device capabilities
        """
        if device_id is None:
            device_id = self.selected_device_id or 0

        if device_id not in self.devices:
            raise GPUException(f"Device {device_id} not found")

        return self.devices[device_id]

    def get_all_devices(self) -> Dict[int, GPUCapabilities]:
        """Get all detected devices"""
        return self.devices.copy()

    def get_backend(self) -> GPUBackend:
        """Get the active backend"""
        return self.backend or GPUBackend.CPU

    def is_gpu_available(self) -> bool:
        """Check if any GPU is available"""
        return self.backend != GPUBackend.CPU and len(self.devices) > 0

    def get_memory_info(self, device_id: Optional[int] = None) -> Dict[str, float]:
        """
        Get current memory information for a device

        Args:
            device_id: Device ID, or None for selected device

        Returns:
            Dictionary with memory information in MB
        """
        caps = self.get_device_info(device_id)
        return {
            'total_mb': caps.total_memory_mb,
            'available_mb': caps.available_memory_mb,
            'used_mb': caps.total_memory_mb - caps.available_memory_mb,
            'usage_percent': ((caps.total_memory_mb - caps.available_memory_mb) / caps.total_memory_mb) * 100
        }

    def reset(self):
        """Reset the GPU manager and re-detect devices"""
        with self._lock:
            self.devices.clear()
            self.device_status.clear()
            self.selected_device_id = None
            self.backend = None
            self._detect_devices()
            logger.info("GPU manager reset completed")

    @classmethod
    def clear_instance(cls):
        """Clear the singleton instance (mainly for testing)"""
        with cls._lock:
            cls._instance = None

    def __repr__(self) -> str:
        """String representation"""
        return f"GPUManager(backend={self.backend}, devices={len(self.devices)}, selected={self.selected_device_id})"


# Global instance getter
def get_gpu_manager() -> GPUManager:
    """Get the GPU manager singleton instance"""
    return GPUManager()