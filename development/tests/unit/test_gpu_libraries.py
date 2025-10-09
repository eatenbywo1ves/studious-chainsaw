"""
Unit tests for GPU library integration and functionality.
"""

import pytest
import numpy as np


class TestGPULibraries:
    """Test GPU library availability and basic functionality."""

    @pytest.mark.gpu
    def test_pytorch_availability(self):
        """Test PyTorch GPU availability and basic operations."""
        torch = pytest.importorskip("torch")

        assert torch.cuda.is_available(), "CUDA should be available"
        assert torch.cuda.device_count() > 0, "At least one GPU should be detected"

        # Test basic tensor operations
        device = torch.device("cuda:0")
        a = torch.randn(100, 100, device=device)
        b = torch.randn(100, 100, device=device)
        c = torch.mm(a, b)

        assert c.device.type == "cuda", "Result should be on GPU"
        assert c.shape == (100, 100), "Result shape should be correct"

    @pytest.mark.gpu
    def test_cupy_availability(self):
        """Test CuPy GPU availability and basic operations."""
        cupy = pytest.importorskip("cupy")

        assert cupy.cuda.is_available(), "CUDA should be available for CuPy"
        assert cupy.cuda.runtime.getDeviceCount() > 0, "At least one GPU should be detected"

        # Test basic array operations
        a = cupy.random.randn(100, 100)
        b = cupy.random.randn(100, 100)
        c = cupy.dot(a, b)

        assert isinstance(c, cupy.ndarray), "Result should be CuPy array"
        assert c.shape == (100, 100), "Result shape should be correct"

    @pytest.mark.gpu
    def test_numba_availability(self):
        """Test Numba CUDA availability and basic operations."""
        numba_cuda = pytest.importorskip("numba.cuda")

        assert numba_cuda.is_available(), "CUDA should be available for Numba"
        assert len(numba_cuda.list_devices()) > 0, "At least one GPU should be detected"

        # Test basic kernel compilation
        @numba_cuda.jit
        def add_kernel(a, b, c):
            idx = numba_cuda.grid(1)
            if idx < a.size:
                c[idx] = a[idx] + b[idx]

        # This should compile without errors
        assert callable(add_kernel), "Kernel should be callable"

    def test_cpu_fallback(self):
        """Test that operations work with CPU fallback when GPU unavailable."""
        try:
            import torch

            # Test CPU operations
            a = torch.randn(10, 10)
            b = torch.randn(10, 10)
            c = torch.mm(a, b)

            assert c.device.type == "cpu", "Should work on CPU"
            assert c.shape == (10, 10), "Result shape should be correct"
        except ImportError:
            pytest.skip("PyTorch not available")


class TestPerformanceBaseline:
    """Test performance baseline measurements."""

    @pytest.mark.performance
    @pytest.mark.gpu
    def test_matrix_multiplication_performance(self, benchmark):
        """Benchmark matrix multiplication performance."""
        torch = pytest.importorskip("torch")

        if not torch.cuda.is_available():
            pytest.skip("GPU not available")

        device = torch.device("cuda:0")

        def matrix_multiply():
            a = torch.randn(1024, 1024, device=device)
            b = torch.randn(1024, 1024, device=device)
            return torch.mm(a, b)

        result = benchmark(matrix_multiply)
        assert result.shape == (1024, 1024)

    @pytest.mark.performance
    def test_cpu_performance_baseline(self, benchmark):
        """Benchmark CPU performance as baseline."""

        def cpu_matrix_multiply():
            a = np.random.randn(512, 512)
            b = np.random.randn(512, 512)
            return np.dot(a, b)

        result = benchmark(cpu_matrix_multiply)
        assert result.shape == (512, 512)


class TestMemoryManagement:
    """Test GPU memory management."""

    @pytest.mark.gpu
    def test_memory_allocation(self):
        """Test GPU memory allocation and deallocation."""
        torch = pytest.importorskip("torch")

        if not torch.cuda.is_available():
            pytest.skip("GPU not available")

        device = torch.device("cuda:0")
        initial_memory = torch.cuda.memory_allocated(device)

        # Allocate memory
        tensors = []
        for _ in range(10):
            tensor = torch.randn(100, 100, device=device)
            tensors.append(tensor)

        allocated_memory = torch.cuda.memory_allocated(device)
        assert allocated_memory > initial_memory, "Memory should increase"

        # Clear memory
        del tensors
        torch.cuda.empty_cache()

        final_memory = torch.cuda.memory_allocated(device)
        assert final_memory <= allocated_memory, "Memory should be freed"

    @pytest.mark.gpu
    def test_memory_efficiency(self):
        """Test memory efficiency of operations."""
        torch = pytest.importorskip("torch")

        if not torch.cuda.is_available():
            pytest.skip("GPU not available")

        device = torch.device("cuda:0")

        # Test in-place operations for memory efficiency
        a = torch.randn(1000, 1000, device=device)
        initial_memory = torch.cuda.memory_allocated(device)

        # In-place operation should not allocate additional memory
        a.add_(1.0)

        after_inplace = torch.cuda.memory_allocated(device)
        assert after_inplace == initial_memory, (
            "In-place operation should not allocate extra memory"
        )
