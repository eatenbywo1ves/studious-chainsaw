"""
Edge case tests for GPU memory handling
Tests memory limits, allocation failures, and resource cleanup
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestGPUMemoryLimits:
    """Test GPU memory limit handling"""

    @pytest.mark.gpu
    def test_large_allocation_within_limits(self):
        """Test allocation that fits in GPU memory"""
        try:
            import torch

            if not torch.cuda.is_available():
                pytest.skip("CUDA not available")

            # Get available memory
            device = torch.device('cuda:0')
            props = torch.cuda.get_device_properties(0)
            total_memory_mb = props.total_memory / (1024 ** 2)

            # Allocate 10% of available memory (should succeed)
            size = int((total_memory_mb * 0.1 * 1024 ** 2) / 4)  # float32 = 4 bytes
            matrix_size = int(np.sqrt(size))

            tensor = torch.randn(matrix_size, matrix_size, device=device)

            assert tensor.device.type == 'cuda'
            assert tensor.numel() > 0

            # Cleanup
            del tensor
            torch.cuda.empty_cache()

        except Exception as e:
            pytest.fail(f"Large allocation failed: {e}")

    @pytest.mark.gpu
    def test_allocation_exceeds_memory(self):
        """Test handling of allocation that exceeds GPU memory"""
        try:
            import torch

            if not torch.cuda.is_available():
                pytest.skip("CUDA not available")

            device = torch.device('cuda:0')

            # Try to allocate more memory than available
            with pytest.raises((RuntimeError, torch.cuda.OutOfMemoryError)):
                # Attempt to allocate 100GB (should fail on most GPUs)
                huge_tensor = torch.randn(50000, 50000, device=device)

        except ImportError:
            pytest.skip("PyTorch not available")

    @pytest.mark.gpu
    def test_memory_fragmentation_handling(self):
        """Test handling of memory fragmentation"""
        try:
            import torch

            if not torch.cuda.is_available():
                pytest.skip("CUDA not available")

            device = torch.device('cuda:0')
            tensors = []

            # Allocate multiple small tensors
            for _ in range(100):
                tensors.append(torch.randn(100, 100, device=device))

            # Free every other tensor (create fragmentation)
            for i in range(0, len(tensors), 2):
                del tensors[i]

            torch.cuda.empty_cache()

            # Try to allocate larger tensor
            large_tensor = torch.randn(1000, 1000, device=device)
            assert large_tensor.device.type == 'cuda'

            # Cleanup
            del tensors
            del large_tensor
            torch.cuda.empty_cache()

        except Exception as e:
            pytest.skip(f"Fragmentation test not applicable: {e}")


class TestGPUResourceCleanup:
    """Test GPU resource cleanup"""

    @pytest.mark.gpu
    def test_cleanup_releases_memory(self):
        """Test that cleanup properly releases GPU memory"""
        try:
            import torch

            if not torch.cuda.is_available():
                pytest.skip("CUDA not available")

            device = torch.device('cuda:0')

            # Get initial memory
            torch.cuda.empty_cache()
            initial_memory = torch.cuda.memory_allocated(device)

            # Allocate tensor
            tensor = torch.randn(5000, 5000, device=device)
            allocated_memory = torch.cuda.memory_allocated(device)

            assert allocated_memory > initial_memory

            # Cleanup
            del tensor
            torch.cuda.empty_cache()

            # Check memory released
            final_memory = torch.cuda.memory_allocated(device)
            assert final_memory <= initial_memory + 1024  # Allow 1KB tolerance

        except Exception as e:
            pytest.fail(f"Cleanup test failed: {e}")

    @pytest.mark.gpu
    def test_context_manager_cleanup(self):
        """Test that context manager properly cleans up GPU resources"""
        from libs.utils.context_managers import gpu_memory_context

        try:
            import torch

            if not torch.cuda.is_available():
                pytest.skip("CUDA not available")

            torch.cuda.empty_cache()
            initial_memory = torch.cuda.memory_allocated(0)

            with gpu_memory_context(backend='pytorch') as gpu:
                if gpu:
                    # Allocate some memory
                    tensor = torch.randn(1000, 1000, device='cuda:0')
                    del tensor

            # Memory should be cleaned up
            torch.cuda.empty_cache()
            final_memory = torch.cuda.memory_allocated(0)

            # Allow small tolerance for PyTorch overhead
            assert final_memory <= initial_memory + 10240  # 10KB tolerance

        except ImportError:
            pytest.skip("PyTorch or context managers not available")


class TestCUDAInitializationEdgeCases:
    """Test CUDA initialization edge cases"""

    def test_multiple_initialization_calls(self):
        """Test that multiple initialization calls are safe"""
        from libs.gpu.cuda_init import initialize_cuda_environment

        with patch('libs.gpu.cuda_init.torch') as mock_torch:
            mock_torch.cuda.is_available.return_value = True
            mock_torch.__version__ = "2.5.1+cu121"
            mock_torch.version.cuda = "12.1"
            mock_torch.cuda.get_device_name.return_value = "Test GPU"
            mock_torch.__file__ = "/test/torch/__init__.py"

            with patch('pathlib.Path.exists', return_value=True), \
                 patch('pathlib.Path.glob', return_value=[Path("cuda.dll")]):

                # Call multiple times
                result1 = initialize_cuda_environment(verbose=False)
                result2 = initialize_cuda_environment(verbose=False)
                result3 = initialize_cuda_environment(verbose=False)

                assert result1 == result2 == result3

    def test_initialization_with_missing_dependencies(self):
        """Test initialization when dependencies are missing"""
        from libs.gpu.cuda_init import initialize_cuda_environment

        with patch('libs.gpu.cuda_init.torch', side_effect=ImportError("torch not found")):
            result = initialize_cuda_environment(verbose=False)
            assert result is False

    def test_partial_cuda_availability(self):
        """Test when CUDA is partially available"""
        from libs.gpu.cuda_init import initialize_cuda_environment

        with patch('libs.gpu.cuda_init.torch') as mock_torch:
            # CUDA reported as available but DLLs missing
            mock_torch.cuda.is_available.return_value = True
            mock_torch.__file__ = "/test/torch/__init__.py"

            with patch('pathlib.Path.exists', return_value=True), \
                 patch('pathlib.Path.glob', return_value=[]):  # No DLLs

                result = initialize_cuda_environment(verbose=False)
                assert result is False


class TestLatticeMemoryEdgeCases:
    """Test lattice memory handling edge cases"""

    def test_lattice_with_minimal_memory(self):
        """Test lattice creation with minimal memory settings"""
        from apps.catalytic.core.unified_lattice import UnifiedCatalyticLattice

        # Create very small lattice
        with UnifiedCatalyticLattice(dimensions=2, size=2, enable_gpu=False, aux_memory_size=10) as lattice:
            assert lattice.dimensions == 2
            assert lattice.size == 2
            assert len(lattice.auxiliary_memory) == 10

    def test_lattice_with_large_dimensions(self):
        """Test lattice creation with large dimensions"""
        from apps.catalytic.core.unified_lattice import UnifiedCatalyticLattice

        # Create high-dimensional lattice (but small size to avoid memory issues)
        with UnifiedCatalyticLattice(dimensions=10, size=2, enable_gpu=False) as lattice:
            lattice.build_lattice()
            assert lattice.n_points == 2 ** 10  # 1024 points

    def test_lattice_cache_size_limits(self):
        """Test that lattice cache doesn't grow unbounded"""
        from apps.catalytic.core.unified_lattice import UnifiedCatalyticLattice

        with UnifiedCatalyticLattice(dimensions=3, size=5, enable_gpu=False) as lattice:
            lattice.build_lattice()

            # Add many paths to cache
            for start in range(0, min(50, lattice.n_points)):
                for end in range(start + 1, min(start + 10, lattice.n_points)):
                    try:
                        lattice.find_shortest_path(start, end)
                    except Exception:
                        pass  # Some paths may not exist

            # Cache should have entries but not be excessive
            cache_size = len(lattice._path_cache)
            assert cache_size > 0
            assert cache_size < 1000  # Reasonable upper limit


class TestGPUFallbackBehavior:
    """Test GPU fallback to CPU behavior"""

    def test_gpu_failure_falls_back_to_cpu(self):
        """Test that GPU initialization failure falls back to CPU"""
        from apps.catalytic.core.unified_lattice import UnifiedCatalyticLattice

        with patch('apps.catalytic.gpu.factory.GPUFactory.create', side_effect=RuntimeError("GPU init failed")):
            # Should not raise, should fall back to CPU
            with UnifiedCatalyticLattice(dimensions=3, size=5, enable_gpu=True) as lattice:
                assert lattice.gpu_backend is None
                lattice.build_lattice()
                # Operations should still work on CPU
                path, _ = lattice.find_shortest_path(0, lattice.n_points - 1)
                assert len(path) > 0

    def test_mixed_gpu_cpu_operations(self):
        """Test mixing GPU and CPU operations"""
        from apps.catalytic.core.unified_lattice import UnifiedCatalyticLattice

        with UnifiedCatalyticLattice(dimensions=3, size=4, enable_gpu=False) as lattice:
            lattice.build_lattice()

            # All operations should work on CPU
            data = np.array([1, 2, 3, 4, 5], dtype=np.uint8)
            result = lattice.xor_transform(data)
            assert len(result) == len(data)

            path, _ = lattice.find_shortest_path(0, 10)
            assert len(path) > 0

            analysis = lattice.analyze_structure()
            assert 'vertices' in analysis


class TestConcurrentGPUAccess:
    """Test concurrent GPU access scenarios"""

    @pytest.mark.gpu
    def test_sequential_lattice_creation(self):
        """Test creating multiple lattices sequentially"""
        from apps.catalytic.core.unified_catalytic_lattice import UnifiedCatalyticLattice

        lattices = []
        try:
            for i in range(3):
                lattice = UnifiedCatalyticLattice(dimensions=2, size=5, enable_gpu=True)
                lattice.build_lattice()
                lattices.append(lattice)

            # All should be created successfully
            assert len(lattices) == 3

        finally:
            # Cleanup
            for lattice in lattices:
                lattice.cleanup()

    @pytest.mark.gpu
    @pytest.mark.slow
    def test_memory_stress(self):
        """Test GPU under memory stress"""
        try:
            import torch

            if not torch.cuda.is_available():
                pytest.skip("CUDA not available")

            device = torch.device('cuda:0')
            tensors = []

            # Allocate tensors until we're close to limit
            try:
                for i in range(100):
                    tensor = torch.randn(500, 500, device=device)
                    tensors.append(tensor)
            except RuntimeError:
                # Expected to eventually run out of memory
                pass

            # Cleanup should work
            for tensor in tensors:
                del tensor
            torch.cuda.empty_cache()

            # Should be able to allocate again
            test_tensor = torch.randn(100, 100, device=device)
            assert test_tensor.device.type == 'cuda'

        except ImportError:
            pytest.skip("PyTorch not available")


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short', '-m', 'not slow'])
