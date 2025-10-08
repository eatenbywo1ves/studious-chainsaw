"""
Performance benchmark tests for the development environment.
"""

import pytest
import time
from pathlib import Path
import sys

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))


class TestGPUPerformanceBenchmarks:
    """Performance benchmarks for GPU operations."""

    @pytest.mark.performance
    @pytest.mark.gpu
    def test_pytorch_matrix_performance(self, benchmark):
        """Benchmark PyTorch matrix operations."""
        torch = pytest.importorskip("torch")

        if not torch.cuda.is_available():
            pytest.skip("GPU not available")

        device = torch.device('cuda:0')

        def matrix_operations():
            a = torch.randn(2048, 2048, device=device)
            b = torch.randn(2048, 2048, device=device)
            c = torch.mm(a, b)
            torch.cuda.synchronize()
            return c

        result = benchmark(matrix_operations)

        # Performance assertions
        assert result.shape == (2048, 2048)
        # Benchmark should complete in reasonable time (handled by benchmark fixture)

    @pytest.mark.performance
    @pytest.mark.gpu
    def test_cupy_matrix_performance(self, benchmark):
        """Benchmark CuPy matrix operations."""
        cupy = pytest.importorskip("cupy")

        if not cupy.cuda.is_available():
            pytest.skip("GPU not available")

        def matrix_operations():
            a = cupy.random.randn(2048, 2048, dtype=cupy.float32)
            b = cupy.random.randn(2048, 2048, dtype=cupy.float32)
            c = cupy.matmul(a, b)
            cupy.cuda.Stream.null.synchronize()
            return c

        result = benchmark(matrix_operations)

        assert result.shape == (2048, 2048)

    @pytest.mark.performance
    @pytest.mark.gpu
    def test_memory_transfer_performance(self, benchmark):
        """Benchmark CPU-GPU memory transfer performance."""
        torch = pytest.importorskip("torch")

        if not torch.cuda.is_available():
            pytest.skip("GPU not available")

        device = torch.device('cuda:0')
        cpu_data = torch.randn(1000, 1000)

        def memory_transfer():
            gpu_data = cpu_data.to(device)
            cpu_result = gpu_data.cpu()
            return cpu_result

        result = benchmark(memory_transfer)
        assert result.shape == (1000, 1000)


class TestCatalyticPerformanceBenchmarks:
    """Performance benchmarks for Catalytic Computing."""

    @pytest.mark.performance
    def test_lattice_creation_performance(self, benchmark):
        """Benchmark lattice creation performance."""
        try:
            from apps.catalytic.catalytic_lattice_gpu import CatalyticLattice

            def create_lattice():
                return CatalyticLattice(dimensions=3, size=10)

            result = benchmark(create_lattice)
            assert result.total_vertices > 0

        except ImportError:
            pytest.skip("Catalytic module not available")

    @pytest.mark.performance
    def test_path_finding_performance(self, benchmark):
        """Benchmark path finding performance."""
        try:
            from apps.catalytic.catalytic_lattice_gpu import CatalyticLattice

            lattice = CatalyticLattice(dimensions=3, size=10)
            start = (0, 0, 0)
            end = (9, 9, 9)

            def find_path():
                return lattice.find_shortest_path(start, end)

            result = benchmark(find_path)
            assert result is not None
            assert len(result) > 0

        except ImportError:
            pytest.skip("Catalytic module not available")

    @pytest.mark.performance
    def test_memory_efficiency_benchmark(self, benchmark):
        """Benchmark memory efficiency of catalytic approach."""
        try:
            from apps.catalytic.catalytic_lattice_gpu import CatalyticLattice

            def measure_memory_efficiency():
                lattice = CatalyticLattice(dimensions=4, size=5)
                return lattice.get_memory_efficiency_ratio()

            efficiency_ratio = benchmark(measure_memory_efficiency)

            # Should achieve significant memory reduction
            assert efficiency_ratio > 100, f"Memory efficiency should be >100x, got {efficiency_ratio:.1f}x"

        except ImportError:
            pytest.skip("Catalytic module not available")


class TestScalabilityBenchmarks:
    """Scalability benchmarks for different problem sizes."""

    @pytest.mark.performance
    @pytest.mark.slow
    def test_lattice_scalability(self, benchmark):
        """Test how performance scales with lattice size."""
        try:
            from apps.catalytic.catalytic_lattice_gpu import CatalyticLattice

            sizes = [5, 10, 15, 20]
            times = []

            for size in sizes:
                def create_and_process():
                    lattice = CatalyticLattice(dimensions=3, size=size)
                    start = (0, 0, 0)
                    end = (size-1, size-1, size-1)
                    return lattice.find_shortest_path(start, end)

                # Time the operation
                start_time = time.time()
                result = create_and_process()
                end_time = time.time()

                times.append(end_time - start_time)
                assert result is not None

            # Check that scaling is reasonable (not exponential)
            # Time should not increase exponentially with size
            for i in range(1, len(times)):
                scaling_factor = times[i] / times[i-1]
                assert scaling_factor < 10, f"Scaling factor {scaling_factor:.2f} too high between sizes {sizes[i-1]} and {sizes[i]}"

        except ImportError:
            pytest.skip("Catalytic module not available")

    @pytest.mark.performance
    @pytest.mark.gpu
    @pytest.mark.slow
    def test_gpu_memory_scalability(self, benchmark):
        """Test GPU memory usage scalability."""
        torch = pytest.importorskip("torch")

        if not torch.cuda.is_available():
            pytest.skip("GPU not available")

        device = torch.device('cuda:0')

        def test_large_matrices():
            # Test progressively larger matrices
            sizes = [1024, 2048, 4096]
            max_size = 0

            for size in sizes:
                try:
                    a = torch.randn(size, size, device=device)
                    b = torch.randn(size, size, device=device)
                    c = torch.mm(a, b)
                    max_size = size

                    # Clean up
                    del a, b, c
                    torch.cuda.empty_cache()

                except RuntimeError:  # Out of memory
                    break

            return max_size

        max_size = benchmark(test_large_matrices)

        # Should handle at least 1024x1024 matrices
        assert max_size >= 1024, f"Should handle at least 1024x1024 matrices, max was {max_size}x{max_size}"


class TestComparisonBenchmarks:
    """Comparative performance benchmarks."""

    @pytest.mark.performance
    def test_cpu_vs_gpu_comparison(self, benchmark):
        """Compare CPU vs GPU performance for same operations."""
        torch = pytest.importorskip("torch")

        size = 1024
        a_cpu = torch.randn(size, size)
        b_cpu = torch.randn(size, size)

        def cpu_operation():
            return torch.mm(a_cpu, b_cpu)

        # Benchmark CPU operation
        cpu_result = benchmark(cpu_operation)
        cpu_time = benchmark.stats.get('mean', 0)

        if torch.cuda.is_available():
            device = torch.device('cuda:0')
            a_gpu = a_cpu.to(device)
            b_gpu = b_cpu.to(device)

            def gpu_operation():
                result = torch.mm(a_gpu, b_gpu)
                torch.cuda.synchronize()
                return result

            # Time GPU operation manually since we can't use benchmark twice
            start_time = time.time()
            gpu_operation()
            torch.cuda.synchronize()
            gpu_time = time.time() - start_time

            # GPU should be significantly faster
            speedup = cpu_time / gpu_time
            assert speedup > 5, f"GPU should be >5x faster than CPU, got {speedup:.2f}x"

        assert cpu_result.shape == (size, size)

    @pytest.mark.performance
    def test_catalytic_vs_traditional(self, benchmark):
        """Compare catalytic approach vs traditional methods."""
        try:
            from apps.catalytic.catalytic_lattice_gpu import CatalyticLattice

            # Catalytic approach
            def catalytic_approach():
                lattice = CatalyticLattice(dimensions=3, size=8)
                start = (0, 0, 0)
                end = (7, 7, 7)
                return lattice.find_shortest_path(start, end)

            catalytic_result = benchmark(catalytic_approach)
            catalytic_time = benchmark.stats.get('mean', 0)

            # Compare with traditional approach (if available)
            try:
                import networkx as nx

                def traditional_approach():
                    # Create traditional graph representation
                    G = nx.grid_graph([8, 8, 8])
                    start_node = (0, 0, 0)
                    end_node = (7, 7, 7)
                    return nx.shortest_path(G, start_node, end_node)

                # Time traditional approach manually
                start_time = time.time()
                traditional_approach()
                traditional_time = time.time() - start_time

                # Catalytic should be competitive or faster
                if traditional_time > 0:
                    speedup = traditional_time / catalytic_time
                    # Note: For small problems, speedup might not be dramatic
                    assert speedup > 0.1, f"Catalytic approach should be competitive, got {speedup:.2f}x"

            except ImportError:
                pass  # NetworkX not available for comparison

            assert catalytic_result is not None
            assert len(catalytic_result) > 0

        except ImportError:
            pytest.skip("Catalytic module not available")
