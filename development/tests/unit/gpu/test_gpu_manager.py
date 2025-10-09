"""
Unit tests for GPU Manager singleton
Tests device detection, selection, and resource management
"""

import pytest
from unittest.mock import MagicMock, patch
import threading

from apps.catalytic.gpu.manager import GPUManager, GPUStatus, get_gpu_manager
from apps.catalytic.gpu.base import GPUCapabilities
from libs.config import GPUBackend
from libs.utils.exceptions import GPUNotAvailableError, GPUException


class TestGPUManagerSingleton:
    """Test GPU Manager singleton behavior"""

    def test_singleton_instance(self):
        """Test that GPUManager returns the same instance"""
        manager1 = GPUManager()
        manager2 = GPUManager()
        assert manager1 is manager2
        assert id(manager1) == id(manager2)

    def test_singleton_thread_safe(self):
        """Test thread-safe singleton creation"""
        GPUManager.clear_instance()
        instances = []

        def create_instance():
            instances.append(GPUManager())

        threads = [threading.Thread(target=create_instance) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All instances should be the same
        assert all(inst is instances[0] for inst in instances)

    def test_clear_instance(self):
        """Test clearing singleton instance"""
        manager1 = GPUManager()
        GPUManager.clear_instance()
        manager2 = GPUManager()
        assert manager1 is not manager2


class TestGPUDeviceDetection:
    """Test GPU device detection across backends"""

    @patch("apps.catalytic.gpu.manager.torch")
    def test_detect_cuda_devices(self, mock_torch):
        """Test CUDA device detection"""
        # Setup mocks
        mock_torch.cuda.is_available.return_value = True
        mock_torch.cuda.device_count.return_value = 2

        mock_props = MagicMock()
        mock_props.name = "NVIDIA GeForce GTX 1080"
        mock_props.total_memory = 8 * 1024**3  # 8GB
        mock_props.major = 6
        mock_props.minor = 1
        mock_props.max_threads_per_block = 1024
        mock_props.max_threads_per_multiprocessor = 2048
        mock_props.warp_size = 32

        mock_torch.cuda.get_device_properties.return_value = mock_props
        mock_torch.cuda.mem_get_info.return_value = (6 * 1024**3, 8 * 1024**3)

        # Create manager and detect devices
        GPUManager.clear_instance()
        manager = GPUManager()

        # Verify detection
        assert manager.backend == GPUBackend.CUDA
        assert len(manager.devices) == 2
        assert manager.devices[0].device_name == "NVIDIA GeForce GTX 1080"
        assert manager.devices[0].total_memory_mb == 8192
        assert manager.devices[0].compute_capability == (6, 1)

    @patch("apps.catalytic.gpu.manager.cp")
    def test_detect_cupy_devices(self, mock_cp):
        """Test CuPy device detection"""
        # Setup mocks
        mock_cp.cuda.runtime.getDeviceCount.return_value = 1

        mock_props = {"name": b"Tesla V100", "major": 7, "minor": 0, "maxThreadsPerBlock": 1024}
        mock_cp.cuda.runtime.getDeviceProperties.return_value = mock_props
        mock_cp.cuda.runtime.memGetInfo.return_value = (
            12 * 1024**3,  # 12GB free
            16 * 1024**3,  # 16GB total
        )

        # Create manager with no CUDA available
        with patch("apps.catalytic.gpu.manager.torch", None):
            GPUManager.clear_instance()
            manager = GPUManager()

        # Verify CuPy detection
        assert manager.backend == GPUBackend.CUPY
        assert len(manager.devices) == 1
        assert manager.devices[0].device_name == "Tesla V100"

    def test_cpu_fallback(self):
        """Test CPU fallback when no GPU available"""
        # Mock all GPU imports to fail
        with patch("apps.catalytic.gpu.manager.torch", None):
            with patch("apps.catalytic.gpu.manager.cp", None):
                GPUManager.clear_instance()
                manager = GPUManager()

                assert manager.backend == GPUBackend.CPU
                assert len(manager.devices) == 1
                assert manager.devices[0].device_name == "CPU"
                assert manager.devices[0].backend_name == "cpu"


class TestGPUDeviceSelection:
    """Test GPU device selection strategies"""

    @pytest.fixture
    def manager_with_devices(self):
        """Create manager with mock devices"""
        GPUManager.clear_instance()
        manager = GPUManager()

        # Add mock devices
        manager.devices = {
            0: GPUCapabilities(
                device_name="GPU 0",
                device_id=0,
                total_memory_mb=8192,
                available_memory_mb=6144,
                backend_name="cuda",
            ),
            1: GPUCapabilities(
                device_name="GPU 1",
                device_id=1,
                total_memory_mb=16384,
                available_memory_mb=14336,
                backend_name="cuda",
            ),
            2: GPUCapabilities(
                device_name="GPU 2",
                device_id=2,
                total_memory_mb=4096,
                available_memory_mb=2048,
                backend_name="cuda",
            ),
        }

        # Set all devices as available
        for device_id in manager.devices:
            manager.device_status[device_id] = GPUStatus.AVAILABLE

        manager.backend = GPUBackend.CUDA
        return manager

    def test_get_best_device_by_memory(self, manager_with_devices):
        """Test selecting device with most available memory"""
        best_id = manager_with_devices.get_best_device()
        assert best_id == 1  # GPU 1 has most available memory

    def test_get_best_device_auto_select_disabled(self, manager_with_devices):
        """Test device selection with auto-select disabled"""
        with patch.object(manager_with_devices.config.gpu, "auto_select_device", False):
            with patch.object(manager_with_devices.config.gpu, "cuda_device_id", 2):
                best_id = manager_with_devices.get_best_device()
                assert best_id == 2  # Uses configured device

    def test_get_best_device_configured_unavailable(self, manager_with_devices):
        """Test fallback when configured device is unavailable"""
        manager_with_devices.device_status[2] = GPUStatus.BUSY

        with patch.object(manager_with_devices.config.gpu, "auto_select_device", False):
            with patch.object(manager_with_devices.config.gpu, "cuda_device_id", 2):
                best_id = manager_with_devices.get_best_device()
                assert best_id == 1  # Falls back to best available

    def test_get_best_device_none_available(self, manager_with_devices):
        """Test error when no devices available"""
        for device_id in manager_with_devices.devices:
            manager_with_devices.device_status[device_id] = GPUStatus.BUSY

        with pytest.raises(GPUNotAvailableError):
            manager_with_devices.get_best_device()


class TestGPUDeviceAcquisition:
    """Test GPU device acquisition and release"""

    @pytest.fixture
    def manager(self):
        """Create manager with single device"""
        GPUManager.clear_instance()
        manager = GPUManager()
        manager.devices = {
            0: GPUCapabilities(
                device_name="Test GPU",
                device_id=0,
                total_memory_mb=8192,
                available_memory_mb=6144,
                backend_name="cuda",
            )
        }
        manager.device_status[0] = GPUStatus.AVAILABLE
        manager.backend = GPUBackend.CUDA
        return manager

    def test_acquire_device_success(self, manager):
        """Test successful device acquisition"""
        device_id = manager.acquire_device()
        assert device_id == 0
        assert manager.device_status[0] == GPUStatus.BUSY

    def test_acquire_specific_device(self, manager):
        """Test acquiring specific device"""
        device_id = manager.acquire_device(device_id=0)
        assert device_id == 0
        assert manager.device_status[0] == GPUStatus.BUSY

    def test_acquire_device_already_busy(self, manager):
        """Test error when device is already busy"""
        manager.device_status[0] = GPUStatus.BUSY

        with pytest.raises(GPUException):
            manager.acquire_device(device_id=0)

    def test_acquire_nonexistent_device(self, manager):
        """Test error when device doesn't exist"""
        with pytest.raises(GPUException):
            manager.acquire_device(device_id=99)

    def test_release_device(self, manager):
        """Test releasing acquired device"""
        device_id = manager.acquire_device()
        assert manager.device_status[device_id] == GPUStatus.BUSY

        manager.release_device(device_id)
        assert manager.device_status[device_id] == GPUStatus.AVAILABLE

    def test_release_nonexistent_device(self, manager):
        """Test releasing non-existent device (should not error)"""
        manager.release_device(99)  # Should complete without error


class TestGPUMemoryInfo:
    """Test GPU memory information retrieval"""

    @pytest.fixture
    def manager(self):
        """Create manager with device"""
        GPUManager.clear_instance()
        manager = GPUManager()
        manager.devices = {
            0: GPUCapabilities(
                device_name="Test GPU",
                device_id=0,
                total_memory_mb=8192,
                available_memory_mb=6144,
                backend_name="cuda",
            )
        }
        manager.selected_device_id = 0
        return manager

    def test_get_memory_info(self, manager):
        """Test getting memory information"""
        mem_info = manager.get_memory_info(0)

        assert mem_info["total_mb"] == 8192
        assert mem_info["available_mb"] == 6144
        assert mem_info["used_mb"] == 2048
        assert mem_info["usage_percent"] == 25.0

    def test_get_memory_info_default_device(self, manager):
        """Test getting memory info for selected device"""
        mem_info = manager.get_memory_info()
        assert mem_info["total_mb"] == 8192

    def test_get_memory_info_nonexistent_device(self, manager):
        """Test error for non-existent device"""
        with pytest.raises(GPUException):
            manager.get_memory_info(99)


class TestGPUManagerUtilities:
    """Test GPU manager utility methods"""

    @pytest.fixture
    def manager(self):
        """Create basic manager"""
        GPUManager.clear_instance()
        return GPUManager()

    def test_is_gpu_available_with_gpu(self, manager):
        """Test GPU availability check with GPU"""
        manager.backend = GPUBackend.CUDA
        manager.devices = {0: MagicMock()}
        assert manager.is_gpu_available() is True

    def test_is_gpu_available_cpu_only(self, manager):
        """Test GPU availability check with CPU only"""
        manager.backend = GPUBackend.CPU
        assert manager.is_gpu_available() is False

    def test_get_backend(self, manager):
        """Test getting current backend"""
        manager.backend = GPUBackend.CUPY
        assert manager.get_backend() == GPUBackend.CUPY

    def test_get_all_devices(self, manager):
        """Test getting all devices"""
        test_devices = {0: MagicMock(), 1: MagicMock()}
        manager.devices = test_devices

        all_devices = manager.get_all_devices()
        assert len(all_devices) == 2
        assert all_devices == test_devices
        assert all_devices is not test_devices  # Should be a copy

    def test_reset(self, manager):
        """Test resetting GPU manager"""
        # Set some state
        manager.devices = {0: MagicMock()}
        manager.selected_device_id = 0
        manager.backend = GPUBackend.CUDA

        # Reset
        with patch.object(manager, "_detect_devices"):
            manager.reset()

        # State should be cleared
        assert len(manager.devices) == 0
        assert manager.selected_device_id is None
        assert manager.backend is None


class TestGlobalGPUManagerGetter:
    """Test global GPU manager getter function"""

    def test_get_gpu_manager_returns_singleton(self):
        """Test that get_gpu_manager returns singleton instance"""
        manager1 = get_gpu_manager()
        manager2 = get_gpu_manager()
        assert manager1 is manager2
        assert isinstance(manager1, GPUManager)
