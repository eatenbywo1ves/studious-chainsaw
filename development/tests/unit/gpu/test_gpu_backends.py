"""
Unit tests for GPU backend implementations
Tests CuPy, PyTorch, CUDA, and CPU implementations
"""

import pytest
import numpy as np
from unittest.mock import MagicMock, patch

from apps.catalytic.gpu.base import GPUCapabilities
from apps.catalytic.gpu.cpu_impl import CPULattice
from libs.utils.exceptions import GPUNotAvailableError


class TestCPULatticeImplementation:
    """Test CPU fallback implementation"""

    @pytest.fixture
    def cpu_lattice(self):
        """Create CPU lattice instance"""
        return CPULattice(dimensions=3, size=5)

    def test_cpu_initialization(self, cpu_lattice):
        """Test CPU lattice initialization"""
        assert cpu_lattice.initialize_device() is True
        assert cpu_lattice._capabilities is not None
        assert "CPU" in cpu_lattice._capabilities.device_name
        assert cpu_lattice._capabilities.backend_name == "cpu"

    def test_cpu_memory_allocation(self, cpu_lattice):
        """Test memory allocation on CPU"""
        cpu_lattice.initialize_device()
        assert cpu_lattice.allocate_memory(10.0) is True
        assert cpu_lattice.auxiliary_memory is not None

    def test_cpu_memory_allocation_failure(self, cpu_lattice):
        """Test memory allocation failure"""
        cpu_lattice.initialize_device()
        # Try to allocate huge amount
        with patch("numpy.zeros", side_effect=MemoryError()):
            assert cpu_lattice.allocate_memory(1000000.0) is False

    def test_cpu_build_lattice(self, cpu_lattice):
        """Test building lattice structure on CPU"""
        cpu_lattice.initialize_device()
        adjacency = cpu_lattice.build_lattice()

        assert adjacency is not None
        assert cpu_lattice.adjacency_matrix is not None
        # 3D lattice with size 5 = 125 vertices
        assert cpu_lattice.adjacency_matrix.shape == (125, 125)

    def test_cpu_xor_transform(self, cpu_lattice):
        """Test XOR transformation on CPU"""
        data = np.array([1, 2, 3, 4, 5], dtype=np.uint8)
        key = np.array([5, 4, 3, 2, 1], dtype=np.uint8)

        result = cpu_lattice.xor_transform(data, key)
        expected = np.bitwise_xor(data, key)

        np.testing.assert_array_equal(result, expected)

    def test_cpu_xor_transform_auto_key(self, cpu_lattice):
        """Test XOR with auto-generated key"""
        data = np.random.randint(0, 256, 100, dtype=np.uint8)
        result = cpu_lattice.xor_transform(data)

        # Should produce different result
        assert not np.array_equal(data, result)
        assert result.dtype == np.uint8

    def test_cpu_find_shortest_path(self, cpu_lattice):
        """Test shortest path finding on CPU"""
        cpu_lattice.initialize_device()
        cpu_lattice.build_lattice()

        path, exec_time = cpu_lattice.find_shortest_path(0, 10)

        assert isinstance(path, list)
        assert path[0] == 0
        assert path[-1] == 10
        assert exec_time > 0

    def test_cpu_matrix_multiply(self, cpu_lattice):
        """Test matrix multiplication on CPU"""
        A = np.random.randn(100, 100).astype(np.float32)
        B = np.random.randn(100, 100).astype(np.float32)

        result = cpu_lattice.matrix_multiply(A, B)
        expected = np.matmul(A, B)

        np.testing.assert_allclose(result, expected, rtol=1e-5)

    def test_cpu_parallel_reduce(self, cpu_lattice):
        """Test parallel reduction operations"""
        data = np.array([1, 2, 3, 4, 5], dtype=np.float32)

        # Test sum
        assert cpu_lattice.parallel_reduce(data, "sum") == 15.0

        # Test max
        assert cpu_lattice.parallel_reduce(data, "max") == 5.0

        # Test min
        assert cpu_lattice.parallel_reduce(data, "min") == 1.0

    def test_cpu_parallel_reduce_invalid_operation(self, cpu_lattice):
        """Test error on invalid reduction operation"""
        data = np.array([1, 2, 3])

        with pytest.raises(ValueError):
            cpu_lattice.parallel_reduce(data, "invalid")

    def test_cpu_transfer_operations(self, cpu_lattice):
        """Test data transfer operations (no-op for CPU)"""
        data = np.array([1, 2, 3, 4, 5])

        # Transfer to "device"
        device_data = cpu_lattice.transfer_to_device(data)
        assert np.array_equal(device_data, data)
        assert device_data is not data  # Should be a copy

        # Transfer from "device"
        cpu_data = cpu_lattice.transfer_from_device(device_data)
        assert np.array_equal(cpu_data, data)

    def test_cpu_free_memory(self, cpu_lattice):
        """Test memory cleanup"""
        cpu_lattice.initialize_device()
        cpu_lattice.allocate_memory(10.0)
        cpu_lattice.build_lattice()

        assert cpu_lattice.auxiliary_memory is not None
        assert cpu_lattice.adjacency_matrix is not None

        cpu_lattice.free_memory()

        assert cpu_lattice.auxiliary_memory is None
        assert cpu_lattice.adjacency_matrix is None

    def test_cpu_get_capabilities(self, cpu_lattice):
        """Test getting CPU capabilities"""
        cpu_lattice.initialize_device()
        caps = cpu_lattice.get_device_capabilities()

        assert isinstance(caps, GPUCapabilities)
        assert caps.device_id == 0
        assert caps.backend_name == "cpu"
        assert caps.total_memory_mb > 0
        assert caps.available_memory_mb > 0


class TestCuPyImplementation:
    """Test CuPy GPU implementation"""

    @pytest.fixture
    def mock_cupy(self):
        """Mock CuPy module"""
        mock_cp = MagicMock()
        mock_cp.cuda.runtime.getDeviceCount.return_value = 1
        mock_cp.cuda.runtime.memGetInfo.return_value = (
            6 * 1024**3,  # 6GB free
            8 * 1024**3,  # 8GB total
        )
        mock_cp.cuda.runtime.getDeviceProperties.return_value = {
            "name": b"Test GPU",
            "major": 7,
            "minor": 5,
            "maxThreadsPerBlock": 1024,
            "multiProcessorCount": 68,
            "warpSize": 32,
        }
        mock_cp.zeros.return_value = MagicMock()
        mock_cp.cuda.Stream.return_value = MagicMock()
        mock_cp.cuda.Device.return_value = MagicMock()
        return mock_cp

    @patch("apps.catalytic.gpu.cupy_impl.cp")
    @patch("apps.catalytic.gpu.cupy_impl.CUPY_AVAILABLE", True)
    def test_cupy_initialization_success(self, mock_cp):
        """Test successful CuPy initialization"""
        from apps.catalytic.gpu.cupy_impl import CuPyLatticeGPU

        mock_cp.cuda.runtime.getDeviceCount.return_value = 1
        mock_cp.cuda.Device.return_value.use.return_value = None
        mock_cp.cuda.Stream.return_value = MagicMock()

        lattice = CuPyLatticeGPU(dimensions=3, size=5, device_id=0)
        assert lattice.initialize_device() is True

    @patch("apps.catalytic.gpu.cupy_impl.CUPY_AVAILABLE", False)
    def test_cupy_not_available(self):
        """Test error when CuPy not installed"""
        from apps.catalytic.gpu.cupy_impl import CuPyLatticeGPU

        with pytest.raises(GPUNotAvailableError):
            CuPyLatticeGPU(dimensions=3, size=5)

    @patch("apps.catalytic.gpu.cupy_impl.cp")
    @patch("apps.catalytic.gpu.cupy_impl.CUPY_AVAILABLE", True)
    def test_cupy_xor_transform(self, mock_cp):
        """Test XOR transformation with CuPy"""
        from apps.catalytic.gpu.cupy_impl import CuPyLatticeGPU

        # Setup mocks
        mock_cp.asarray.side_effect = lambda x, **kwargs: MagicMock(shape=x.shape)
        mock_cp.bitwise_xor.return_value = MagicMock()
        mock_cp.asnumpy.return_value = np.array([4, 6, 0, 6, 4], dtype=np.uint8)

        lattice = CuPyLatticeGPU(dimensions=2, size=4)
        lattice.device = MagicMock()
        lattice.stream = MagicMock()

        data = np.array([1, 2, 3, 4, 5], dtype=np.uint8)
        key = np.array([5, 4, 3, 2, 1], dtype=np.uint8)

        result = lattice.xor_transform(data, key)

        mock_cp.bitwise_xor.assert_called_once()
        assert isinstance(result, np.ndarray)

    @patch("apps.catalytic.gpu.cupy_impl.cp")
    @patch("apps.catalytic.gpu.cupy_impl.CUPY_AVAILABLE", True)
    def test_cupy_matrix_multiply(self, mock_cp):
        """Test matrix multiplication with CuPy"""
        from apps.catalytic.gpu.cupy_impl import CuPyLatticeGPU

        # Setup mocks
        mock_result = MagicMock()
        mock_cp.matmul.return_value = mock_result
        mock_cp.asnumpy.return_value = np.eye(3)

        lattice = CuPyLatticeGPU(dimensions=2, size=4)
        lattice.device = MagicMock()
        lattice.stream = MagicMock()

        A = np.random.randn(3, 3).astype(np.float32)
        B = np.random.randn(3, 3).astype(np.float32)

        result = lattice.matrix_multiply(A, B)

        mock_cp.matmul.assert_called_once()
        assert isinstance(result, np.ndarray)
