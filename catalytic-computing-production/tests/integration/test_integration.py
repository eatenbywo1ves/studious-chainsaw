"""
Integration tests for Catalytic Computing system
"""

import pytest
import asyncio
import numpy as np
from unittest.mock import Mock, patch
import time

from catalytic_computing.core.lattice_core import CatalyticLatticeComputing
from catalytic_computing.algorithms.quantum_lattice import QuantumCatalyticLattice
from catalytic_computing.utils.monitoring import metrics_collector


class TestCatalyticIntegration:
    """Integration tests for the complete catalytic computing pipeline"""

    @pytest.fixture
    def catalyst_system(self):
        """Create a configured catalyst system"""
        return CatalyticLatticeComputing(dimensions=100)

    @pytest.fixture
    def quantum_system(self):
        """Create a quantum catalyst system"""
        return QuantumCatalyticLattice(qubits=8)

    def test_end_to_end_catalytic_operation(self, catalyst_system):
        """Test complete catalytic operation from start to finish"""
        # Setup
        initial_state = np.random.randn(100, 100)
        catalyst = np.random.randn(50, 50)

        # Perform catalytic operation
        result = catalyst_system.catalytic_transform(
            initial_state,
            catalyst,
            operation='lattice_navigation'
        )

        # Verify catalyst restoration
        assert catalyst_system.verify_catalyst_integrity(catalyst)

        # Verify result validity
        assert result.shape == initial_state.shape
        assert not np.array_equal(result, initial_state)

    def test_memory_efficiency(self, catalyst_system):
        """Test memory efficiency improvements"""
        # Measure baseline memory
        import psutil
        process = psutil.Process()
        baseline_memory = process.memory_info().rss

        # Perform large-scale operation
        large_matrix = np.random.randn(1000, 1000)
        catalyst = np.random.randn(100, 100)

        result = catalyst_system.catalytic_transform(
            large_matrix,
            catalyst,
            operation='memory_efficient'
        )

        # Check memory usage didn't explode
        peak_memory = process.memory_info().rss
        memory_increase = (peak_memory - baseline_memory) / baseline_memory

        assert memory_increase < 0.5  # Less than 50% increase

    @pytest.mark.asyncio
    async def test_concurrent_operations(self, catalyst_system):
        """Test concurrent catalytic operations"""
        tasks = []
        for i in range(10):
            matrix = np.random.randn(100, 100)
            catalyst = np.random.randn(50, 50)
            task = asyncio.create_task(
                catalyst_system.async_catalytic_transform(
                    matrix, catalyst
                )
            )
            tasks.append(task)

        results = await asyncio.gather(*tasks)

        # Verify all operations completed successfully
        assert len(results) == 10
        for result in results:
            assert result is not None

    def test_gpu_acceleration(self, catalyst_system):
        """Test GPU acceleration when available"""
        try:
            import cupy as cp
            gpu_available = True
        except ImportError:
            gpu_available = False
            pytest.skip("GPU not available")

        if gpu_available:
            # Compare CPU vs GPU performance
            matrix = np.random.randn(500, 500)
            catalyst = np.random.randn(100, 100)

            # CPU timing
            start = time.time()
            cpu_result = catalyst_system.catalytic_transform(
                matrix, catalyst, use_gpu=False
            )
            cpu_time = time.time() - start

            # GPU timing
            start = time.time()
            gpu_result = catalyst_system.catalytic_transform(
                matrix, catalyst, use_gpu=True
            )
            gpu_time = time.time() - start

            # GPU should be faster for large operations
            assert gpu_time < cpu_time * 0.5  # At least 2x speedup

    def test_quantum_catalytic_integration(self, quantum_system):
        """Test quantum-catalytic hybrid operations"""
        # Create quantum state
        quantum_state = quantum_system.create_bell_state()

        # Apply catalytic transformation
        catalyst = np.random.randn(4, 4)
        result = quantum_system.catalytic_quantum_operation(
            quantum_state, catalyst
        )

        # Verify quantum properties preserved
        assert quantum_system.verify_unitarity(result)
        assert quantum_system.verify_normalization(result)

    def test_error_recovery(self, catalyst_system):
        """Test system recovery from errors"""
        # Simulate corrupted catalyst
        catalyst = np.random.randn(50, 50)
        corrupted_catalyst = catalyst.copy()
        corrupted_catalyst[0, 0] = np.nan

        with pytest.raises(ValueError):
            catalyst_system.catalytic_transform(
                np.random.randn(100, 100),
                corrupted_catalyst
            )

        # System should still be functional after error
        result = catalyst_system.catalytic_transform(
            np.random.randn(100, 100),
            catalyst  # Use good catalyst
        )
        assert result is not None

    @pytest.mark.benchmark
    def test_performance_benchmark(self, benchmark, catalyst_system):
        """Benchmark catalytic operations"""
        matrix = np.random.randn(200, 200)
        catalyst = np.random.randn(50, 50)

        result = benchmark(
            catalyst_system.catalytic_transform,
            matrix, catalyst
        )

        assert result is not None

    def test_monitoring_integration(self, catalyst_system):
        """Test monitoring and metrics collection"""
        with patch.object(metrics_collector, 'track_operation') as mock_track:
            matrix = np.random.randn(100, 100)
            catalyst = np.random.randn(50, 50)

            result = catalyst_system.catalytic_transform(
                matrix, catalyst
            )

            # Verify metrics were collected
            mock_track.assert_called()

    @pytest.mark.asyncio
    async def test_health_check_integration(self):
        """Test health check endpoints"""
        health_status = await metrics_collector.health_check()

        assert health_status['status'] in ['healthy', 'degraded', 'unhealthy']
        assert 'checks' in health_status
        assert 'timestamp' in health_status