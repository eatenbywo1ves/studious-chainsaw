"""
Unit tests for GPU Factory
Tests factory pattern implementation and backend selection
"""

import pytest
from unittest.mock import MagicMock, patch

from apps.catalytic.gpu.factory import GPUFactory
from apps.catalytic.gpu.base import BaseLatticeGPU, GPUCapabilities
from libs.config import GPUBackend
from libs.utils.exceptions import GPUNotAvailableError


class MockGPUImplementation(BaseLatticeGPU):
    """Mock GPU implementation for testing"""

    def initialize_device(self) -> bool:
        return True

    def get_device_capabilities(self) -> GPUCapabilities:
        return GPUCapabilities(
            device_name="Mock GPU",
            device_id=0,
            total_memory_mb=8192,
            available_memory_mb=6144,
            backend_name="mock"
        )

    def build_lattice(self):
        return {}

    def allocate_memory(self, size_mb: float) -> bool:
        return True

    def free_memory(self):
        pass

    def transfer_to_device(self, data):
        return data

    def transfer_from_device(self, gpu_data):
        return gpu_data

    def xor_transform(self, data, key=None):
        return data

    def find_shortest_path(self, start: int, end: int):
        return [start, end], 1.0

    def matrix_multiply(self, A, B):
        return A @ B

    def parallel_reduce(self, data, operation="sum"):
        return float(data.sum())


class TestGPUFactoryRegistration:
    """Test GPU implementation registration"""

    def setup_method(self):
        """Clear factory registry before each test"""
        GPUFactory._implementations.clear()

    def test_register_implementation(self):
        """Test registering new GPU implementation"""
        GPUFactory.register(GPUBackend.CUDA, MockGPUImplementation)

        assert GPUBackend.CUDA in GPUFactory._implementations
        assert GPUFactory._implementations[GPUBackend.CUDA] == MockGPUImplementation

    def test_register_multiple_implementations(self):
        """Test registering multiple implementations"""
        class MockCUDA(MockGPUImplementation):
            pass

        class MockCuPy(MockGPUImplementation):
            pass

        GPUFactory.register(GPUBackend.CUDA, MockCUDA)
        GPUFactory.register(GPUBackend.CUPY, MockCuPy)

        assert len(GPUFactory._implementations) == 2
        assert GPUFactory._implementations[GPUBackend.CUDA] == MockCUDA
        assert GPUFactory._implementations[GPUBackend.CUPY] == MockCuPy

    def test_list_available_backends(self):
        """Test listing registered backends"""
        GPUFactory.register(GPUBackend.CUDA, MockGPUImplementation)
        GPUFactory.register(GPUBackend.CPU, MockGPUImplementation)

        backends = GPUFactory.list_available_backends()
        assert GPUBackend.CUDA in backends
        assert GPUBackend.CPU in backends
        assert len(backends) == 2


class TestGPUFactoryCreation:
    """Test GPU instance creation"""

    def setup_method(self):
        """Setup factory with mock implementations"""
        GPUFactory._implementations.clear()
        GPUFactory.register(GPUBackend.CUDA, MockGPUImplementation)
        GPUFactory.register(GPUBackend.CPU, MockGPUImplementation)

    @patch('apps.catalytic.gpu.factory.get_gpu_manager')
    def test_create_with_specific_backend(self, mock_get_manager):
        """Test creating instance with specific backend"""
        mock_manager = MagicMock()
        mock_manager.get_backend.return_value = GPUBackend.CUDA
        mock_manager.get_best_device.return_value = 0
        mock_get_manager.return_value = mock_manager

        instance = GPUFactory.create(
            dimensions=4,
            size=10,
            backend=GPUBackend.CUDA
        )

        assert isinstance(instance, MockGPUImplementation)
        assert instance.dimensions == 4
        assert instance.size == 10

    @patch('apps.catalytic.gpu.factory.get_gpu_manager')
    def test_create_with_auto_detect(self, mock_get_manager):
        """Test creating instance with auto-detected backend"""
        mock_manager = MagicMock()
        mock_manager.get_backend.return_value = GPUBackend.CPU
        mock_get_manager.return_value = mock_manager

        instance = GPUFactory.create(
            dimensions=3,
            size=5,
            backend=None  # Auto-detect
        )

        assert isinstance(instance, MockGPUImplementation)
        mock_manager.get_backend.assert_called()

    @patch('apps.catalytic.gpu.factory.get_gpu_manager')
    def test_create_with_unavailable_backend(self, mock_get_manager):
        """Test fallback when requested backend unavailable"""
        mock_manager = MagicMock()
        mock_manager.get_backend.return_value = GPUBackend.CPU
        mock_get_manager.return_value = mock_manager

        # Request CUDA but only CPU available
        instance = GPUFactory.create(
            dimensions=2,
            size=8,
            backend=GPUBackend.CUDA
        )

        # Should fallback to CPU
        assert isinstance(instance, MockGPUImplementation)

    def test_create_no_implementation_available(self):
        """Test error when no implementation available"""
        GPUFactory._implementations.clear()  # Remove all implementations

        with pytest.raises(GPUNotAvailableError):
            GPUFactory.create(
                dimensions=4,
                size=10,
                backend=GPUBackend.CUDA
            )

    @patch('apps.catalytic.gpu.factory.get_gpu_manager')
    @patch('apps.catalytic.gpu.factory.get_settings')
    def test_create_with_fallback_chain(self, mock_settings, mock_get_manager):
        """Test fallback through configured backends"""
        # Setup fallback configuration
        mock_config = MagicMock()
        mock_config.gpu.fallback_backends = [GPUBackend.CUPY, GPUBackend.CPU]
        mock_settings.return_value = mock_config

        mock_manager = MagicMock()
        mock_manager.get_backend.return_value = GPUBackend.CUDA
        mock_get_manager.return_value = mock_manager

        # Clear CUDA implementation, keep CPU
        GPUFactory._implementations = {GPUBackend.CPU: MockGPUImplementation}

        instance = GPUFactory.create(
            dimensions=3,
            size=7,
            backend=GPUBackend.CUDA  # Request unavailable backend
        )

        # Should fallback to CPU
        assert isinstance(instance, MockGPUImplementation)

    @patch('apps.catalytic.gpu.factory.get_gpu_manager')
    def test_create_with_device_id(self, mock_get_manager):
        """Test creating instance with specific device ID"""
        mock_manager = MagicMock()
        mock_manager.get_backend.return_value = GPUBackend.CUDA
        mock_get_manager.return_value = mock_manager

        instance = GPUFactory.create(
            dimensions=4,
            size=10,
            backend=GPUBackend.CUDA,
            device_id=2
        )

        assert instance.device_id == 2

    @patch('apps.catalytic.gpu.factory.get_gpu_manager')
    def test_create_initialization_failure(self, mock_get_manager):
        """Test handling initialization failure"""
        mock_manager = MagicMock()
        mock_manager.get_backend.return_value = GPUBackend.CUDA
        mock_get_manager.return_value = mock_manager

        class FailingGPU(MockGPUImplementation):
            def initialize_device(self):
                return False

        GPUFactory._implementations[GPUBackend.CUDA] = FailingGPU

        with pytest.raises(GPUNotAvailableError):
            GPUFactory.create(
                dimensions=4,
                size=10,
                backend=GPUBackend.CUDA
            )


class TestGPUFactoryCreateBest:
    """Test best GPU selection based on requirements"""

    def setup_method(self):
        """Setup factory with mock implementation"""
        GPUFactory._implementations.clear()
        GPUFactory.register(GPUBackend.CUDA, MockGPUImplementation)
        GPUFactory.register(GPUBackend.CPU, MockGPUImplementation)

    @patch('apps.catalytic.gpu.factory.get_gpu_manager')
    def test_create_best_default(self, mock_get_manager):
        """Test create_best with default selection"""
        mock_manager = MagicMock()
        mock_manager.is_gpu_available.return_value = True
        mock_manager.get_backend.return_value = GPUBackend.CUDA
        mock_manager.get_best_device.return_value = 0
        mock_get_manager.return_value = mock_manager

        instance = GPUFactory.create_best(
            dimensions=4,
            size=10
        )

        assert isinstance(instance, MockGPUImplementation)

    @patch('apps.catalytic.gpu.factory.get_gpu_manager')
    def test_create_best_prefer_memory(self, mock_get_manager):
        """Test create_best with memory preference"""
        mock_manager = MagicMock()
        mock_manager.is_gpu_available.return_value = True
        mock_manager.get_all_devices.return_value = {
            0: GPUCapabilities(
                device_name="Small GPU",
                device_id=0,
                total_memory_mb=4096,
                available_memory_mb=2048,
                backend_name="cuda"
            ),
            1: GPUCapabilities(
                device_name="Large GPU",
                device_id=1,
                total_memory_mb=16384,
                available_memory_mb=14336,
                backend_name="cuda"
            )
        }
        mock_get_manager.return_value = mock_manager

        instance = GPUFactory.create_best(
            dimensions=4,
            size=10,
            prefer_memory=True
        )

        # Should select device 1 with more memory
        assert instance.device_id == 1

    @patch('apps.catalytic.gpu.factory.get_gpu_manager')
    def test_create_best_insufficient_memory(self, mock_get_manager):
        """Test create_best when memory insufficient"""
        mock_manager = MagicMock()
        mock_manager.is_gpu_available.return_value = True
        mock_manager.get_all_devices.return_value = {
            0: GPUCapabilities(
                device_name="Small GPU",
                device_id=0,
                total_memory_mb=1024,
                available_memory_mb=512,  # Very small
                backend_name="cuda"
            )
        }
        mock_manager.get_backend.return_value = GPUBackend.CUDA
        mock_manager.get_best_device.return_value = 0
        mock_get_manager.return_value = mock_manager

        # Large lattice requiring lots of memory
        instance = GPUFactory.create_best(
            dimensions=10,
            size=50,
            prefer_memory=True
        )

        # Should still create instance (fallback logic)
        assert isinstance(instance, MockGPUImplementation)


class TestGPUFactoryBenchmark:
    """Test factory benchmarking capabilities"""

    def setup_method(self):
        """Setup factory with mock implementations"""
        GPUFactory._implementations.clear()

    @patch('apps.catalytic.gpu.factory.logger')
    def test_benchmark_backends_success(self, mock_logger):
        """Test benchmarking available backends"""
        class BenchmarkGPU(MockGPUImplementation):
            def benchmark(self):
                return {
                    'matrix_multiply': {'gpu_ms': 10, 'cpu_ms': 100, 'speedup': 10},
                    'xor_transform': {'gpu_ms': 5}
                }

        GPUFactory.register(GPUBackend.CUDA, BenchmarkGPU)
        GPUFactory.register(GPUBackend.CPU, BenchmarkGPU)

        results = GPUFactory.benchmark_backends(dimensions=3, size=5)

        assert 'cuda' in results
        assert 'cpu' in results
        assert results['cuda']['status'] == 'success'
        assert 'matrix_multiply' in results['cuda']

    def test_benchmark_backends_failure(self):
        """Test benchmarking with failing backend"""
        class FailingGPU(MockGPUImplementation):
            def initialize_device(self):
                raise RuntimeError("GPU initialization failed")

        GPUFactory.register(GPUBackend.CUDA, FailingGPU)

        results = GPUFactory.benchmark_backends(dimensions=3, size=5)

        assert 'cuda' in results
        assert results['cuda']['status'] == 'failed'
        assert 'error' in results['cuda']

    def test_benchmark_backends_empty(self):
        """Test benchmarking with no backends"""
        GPUFactory._implementations.clear()

        results = GPUFactory.benchmark_backends()
        assert results == {}


class TestGPUFactoryWithAdditionalArgs:
    """Test factory with additional constructor arguments"""

    def setup_method(self):
        """Setup factory"""
        GPUFactory._implementations.clear()

    def test_create_with_kwargs(self):
        """Test passing additional kwargs to implementation"""
        class CustomGPU(MockGPUImplementation):
            def __init__(self, dimensions, size, device_id=0, custom_param=None):
                super().__init__(dimensions, size, device_id)
                self.custom_param = custom_param

        GPUFactory.register(GPUBackend.CUDA, CustomGPU)

        with patch('apps.catalytic.gpu.factory.get_gpu_manager') as mock_manager:
            mock_mgr = MagicMock()
            mock_mgr.get_backend.return_value = GPUBackend.CUDA
            mock_mgr.get_best_device.return_value = 0
            mock_manager.return_value = mock_mgr

            instance = GPUFactory.create(
                dimensions=4,
                size=10,
                backend=GPUBackend.CUDA,
                custom_param="test_value"
            )

            assert instance.custom_param == "test_value"
