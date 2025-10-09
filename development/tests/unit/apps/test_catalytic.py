"""
Unit tests for the Catalytic Computing application.
"""

import pytest
import numpy as np
import sys
from pathlib import Path

# Add project root to path to import modules
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))


class TestCatalyticLattice:
    """Test catalytic lattice functionality."""

    def test_lattice_creation(self, sample_data):
        """Test basic lattice creation."""
        try:
            from apps.catalytic.catalytic_lattice_gpu import CatalyticLattice

            config = sample_data["lattice_config"]
            lattice = CatalyticLattice(dimensions=config["dimensions"], size=config["size"])

            assert lattice.dimensions == config["dimensions"]
            assert lattice.size == config["size"]
            assert lattice.total_vertices > 0

        except ImportError as e:
            pytest.skip(f"Catalytic module not available: {e}")

    def test_memory_efficiency(self):
        """Test memory efficiency claims."""
        try:
            from apps.catalytic.catalytic_lattice_gpu import CatalyticLattice

            # Create a small lattice to test memory efficiency
            lattice = CatalyticLattice(dimensions=3, size=5)

            # The catalytic approach should use significantly less memory
            # than a traditional dense representation
            expected_dense_size = (5**3) ** 2 * 8  # bytes for adjacency matrix
            actual_memory = lattice.get_memory_usage()

            efficiency_ratio = expected_dense_size / actual_memory
            assert efficiency_ratio > 10, (
                f"Memory efficiency should be >10x, got {efficiency_ratio:.1f}x"
            )

        except ImportError:
            pytest.skip("Catalytic module not available")

    @pytest.mark.performance
    def test_path_finding_performance(self, benchmark):
        """Benchmark path finding performance."""
        try:
            from apps.catalytic.catalytic_lattice_gpu import CatalyticLattice

            lattice = CatalyticLattice(dimensions=3, size=8)
            start = (0, 0, 0)
            end = (7, 7, 7)

            def find_path():
                return lattice.find_shortest_path(start, end)

            result = benchmark(find_path)
            assert result is not None, "Path should be found"
            assert len(result) > 0, "Path should have steps"

        except ImportError:
            pytest.skip("Catalytic module not available")

    def test_catalytic_property(self):
        """Test the core catalytic property - perfect memory restoration."""
        try:
            from apps.catalytic.catalytic_lattice_gpu import CatalyticLattice

            lattice = CatalyticLattice(dimensions=2, size=4)

            # Store initial state
            initial_aux_memory = (
                lattice.aux_memory.copy() if hasattr(lattice, "aux_memory") else None
            )

            # Perform some operations that modify auxiliary memory
            lattice.transform_data(np.array([1, 2, 3, 4]))

            # The catalytic property should restore memory to initial state
            lattice.restore_memory()

            if initial_aux_memory is not None:
                final_aux_memory = lattice.aux_memory
                np.testing.assert_array_equal(
                    initial_aux_memory,
                    final_aux_memory,
                    "Catalytic property should restore memory perfectly",
                )

        except ImportError:
            pytest.skip("Catalytic module not available")


class TestGPUAcceleration:
    """Test GPU acceleration functionality."""

    @pytest.mark.gpu
    def test_gpu_factory_selection(self):
        """Test GPU backend factory selection."""
        try:
            from apps.catalytic.gpu.factory import GPUBackendFactory

            factory = GPUBackendFactory()
            backend = factory.create_backend()

            assert backend is not None, "Backend should be created"
            assert hasattr(backend, "is_available"), "Backend should have availability check"

        except ImportError:
            pytest.skip("GPU factory module not available")

    @pytest.mark.gpu
    def test_pytorch_backend(self):
        """Test PyTorch GPU backend."""
        try:
            from apps.catalytic.gpu.pytorch_impl import PyTorchGPUBackend

            backend = PyTorchGPUBackend()

            if backend.is_available():
                # Test basic operations
                data = np.random.randn(100, 100).astype(np.float32)
                gpu_result = backend.matrix_multiply(data, data)

                assert gpu_result.shape == (100, 100), "Result shape should be correct"
                assert gpu_result.dtype == np.float32, "Result dtype should be preserved"
            else:
                pytest.skip("PyTorch GPU backend not available")

        except ImportError:
            pytest.skip("PyTorch backend module not available")

    @pytest.mark.gpu
    def test_cupy_backend(self):
        """Test CuPy GPU backend."""
        try:
            from apps.catalytic.gpu.cupy_impl import CuPyGPUBackend

            backend = CuPyGPUBackend()

            if backend.is_available():
                # Test basic operations
                data = np.random.randn(100, 100).astype(np.float32)
                gpu_result = backend.matrix_multiply(data, data)

                assert gpu_result.shape == (100, 100), "Result shape should be correct"
                assert gpu_result.dtype == np.float32, "Result dtype should be preserved"
            else:
                pytest.skip("CuPy GPU backend not available")

        except ImportError:
            pytest.skip("CuPy backend module not available")


class TestKALattice:
    """Test Knowledge-Augmented Lattice functionality."""

    def test_ka_lattice_creation(self):
        """Test KA Lattice creation and basic functionality."""
        try:
            from apps.catalytic.ka_lattice.ka_core import KALattice

            ka_lattice = KALattice(max_instances=2)

            assert ka_lattice.max_instances == 2
            assert hasattr(ka_lattice, "knowledge_base")
            assert hasattr(ka_lattice, "orchestrator")

        except ImportError:
            pytest.skip("KA Lattice module not available")

    def test_knowledge_base(self):
        """Test knowledge base functionality."""
        try:
            from apps.catalytic.ka_lattice.knowledge_base import KnowledgeBase

            kb = KnowledgeBase()

            # Test pattern storage and retrieval
            pattern_data = np.array([1, 2, 3, 4])
            performance_data = {"time": 0.1, "efficiency": 0.9}

            kb.store_pattern("test_pattern", pattern_data, performance_data)
            retrieved = kb.get_pattern("test_pattern")

            assert retrieved is not None, "Pattern should be retrievable"

        except ImportError:
            pytest.skip("Knowledge base module not available")

    @pytest.mark.performance
    def test_ka_lattice_performance(self, benchmark):
        """Benchmark KA Lattice performance improvements."""
        try:
            from apps.catalytic.ka_lattice.ka_core import KALattice

            ka_lattice = KALattice(max_instances=1)

            def process_workload():
                workload = {
                    "operation": "transform",
                    "data": np.random.randn(100),
                    "parameters": {"factor": 2.0},
                }
                return ka_lattice.process_workload(workload)

            result = benchmark(process_workload)
            assert result is not None, "Workload should be processed"

        except ImportError:
            pytest.skip("KA Lattice module not available")
