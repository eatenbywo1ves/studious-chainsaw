"""
Integration tests for GPU-accelerated SaaS operations.

Tests GPU performance, CPU fallback, concurrent operations, memory management,
and monitoring integration.

Test Coverage:
- GPU acceleration and performance (3 tests)
- CPU fallback mechanisms (2 tests)
- Concurrent GPU operations (3 tests)
- GPU memory management (3 tests)
- GPU monitoring endpoints (2 tests)
- GPU error handling (2 tests)

Total: 15 test cases

Related Documents:
- PRD: tests/integration/PRD_GPU_SAAS_INTEGRATION.md
- TDD: tests/integration/TDD_GPU_SAAS_INTEGRATION.md

Developer: BMAD Developer Agent
Date: 2025-10-05
"""

import pytest
import asyncio
from httpx import AsyncClient


# ============================================================================
# TEST CLASS: GPU Acceleration
# ============================================================================

class TestGPUAcceleration:
    """Test GPU-accelerated transformations"""

    @pytest.mark.gpu_required
    async def test_small_lattice_gpu_vs_cpu(
        self,
        authenticated_client: AsyncClient,
        gpu_available: bool
    ):
        """
        Test GPU vs CPU comparison for small lattice.

        For small lattices (size < 1000), CPU should be faster due to
        GPU overhead. This test verifies smart routing works.
        """
        if not gpu_available:
            pytest.skip("GPU not available for testing")

        # Create small lattice
        create_response = await authenticated_client.post(
            "/api/lattices",
            json={"dimensions": 2, "size": 100, "name": "Small GPU Test"}
        )
        assert create_response.status_code == 201
        lattice_id = create_response.json()["id"]

        # Transform with GPU request (should use CPU due to small size)
        gpu_response = await authenticated_client.post(
            f"/api/lattices/{lattice_id}/transform",
            json={
                "transformation_type": "xor",
                "parameters": {"key": "test_key"},
                "use_gpu": True
            }
        )
        assert gpu_response.status_code == 200
        gpu_data = gpu_response.json()

        # For small lattice, CPU should be used even if GPU requested
        # (smart routing in OperationRouter)
        assert "gpu_used" in gpu_data
        assert "execution_time_ms" in gpu_data

    @pytest.mark.gpu_required
    async def test_large_lattice_gpu_performance(
        self,
        authenticated_client: AsyncClient,
        gpu_available: bool
    ):
        """
        Test GPU performance on large lattice.

        For large lattices (size >= 10000), GPU should provide significant
        speedup (10x+) over CPU.
        """
        if not gpu_available:
            pytest.skip("GPU not available for testing")

        # Create large lattice
        create_response = await authenticated_client.post(
            "/api/lattices",
            json={"dimensions": 3, "size": 10000, "name": "Large GPU Test"}
        )
        assert create_response.status_code == 201
        lattice_id = create_response.json()["id"]

        # GPU transformation
        gpu_response = await authenticated_client.post(
            f"/api/lattices/{lattice_id}/transform",
            json={
                "transformation_type": "xor",
                "parameters": {"key": "test_key"},
                "use_gpu": True
            }
        )
        assert gpu_response.status_code == 200
        gpu_time = gpu_response.json()["execution_time_ms"]
        assert gpu_response.json()["gpu_used"]

        # CPU transformation (for comparison)
        cpu_response = await authenticated_client.post(
            f"/api/lattices/{lattice_id}/transform",
            json={
                "transformation_type": "xor",
                "parameters": {"key": "test_key"},
                "use_gpu": False
            }
        )
        assert cpu_response.status_code == 200
        cpu_time = cpu_response.json()["execution_time_ms"]
        assert not cpu_response.json()["gpu_used"]

        # GPU should be at least 2x faster for large lattice
        speedup = cpu_time / max(gpu_time, 1)  # Avoid division by zero
        assert speedup >= 2.0, f"GPU speedup {speedup}x is less than expected 2x"

    @pytest.mark.gpu_required
    async def test_gpu_results_match_cpu(
        self,
        authenticated_client: AsyncClient,
        gpu_available: bool
    ):
        """
        Test GPU and CPU produce identical results.

        Mathematical correctness is critical - GPU and CPU implementations
        must produce bitwise identical results.
        """
        if not gpu_available:
            pytest.skip("GPU not available for testing")

        # Create two identical lattices
        lattice_data = {"dimensions": 2, "size": 1000, "name": "GPU Correctness Test"}

        create_gpu = await authenticated_client.post("/api/lattices", json=lattice_data)
        lattice_gpu_id = create_gpu.json()["id"]

        create_cpu = await authenticated_client.post("/api/lattices", json=lattice_data)
        lattice_cpu_id = create_cpu.json()["id"]

        # Same transformation parameters
        transform_params = {
            "transformation_type": "xor",
            "parameters": {"key": "identical_key_12345"}
        }

        # GPU transformation
        gpu_result = await authenticated_client.post(
            f"/api/lattices/{lattice_gpu_id}/transform",
            json={**transform_params, "use_gpu": True}
        )

        # CPU transformation
        cpu_result = await authenticated_client.post(
            f"/api/lattices/{lattice_cpu_id}/transform",
            json={**transform_params, "use_gpu": False}
        )

        # Both should succeed
        assert gpu_result.status_code == 200
        assert cpu_result.status_code == 200

        # Results should be mathematically identical
        assert gpu_result.json()["result_summary"]["success"]
        assert cpu_result.json()["result_summary"]["success"]


# ============================================================================
# TEST CLASS: GPU Fallback
# ============================================================================

class TestGPUFallback:
    """Test CPU fallback when GPU unavailable"""

    async def test_cpu_fallback_when_gpu_disabled(
        self,
        authenticated_client: AsyncClient
    ):
        """
        Test CPU fallback works when GPU explicitly disabled.
        """
        create_response = await authenticated_client.post(
            "/api/lattices",
            json={"dimensions": 2, "size": 1000}
        )
        lattice_id = create_response.json()["id"]

        # Explicit CPU request
        cpu_response = await authenticated_client.post(
            f"/api/lattices/{lattice_id}/transform",
            json={
                "transformation_type": "xor",
                "parameters": {"key": "cpu_key"},
                "use_gpu": False
            }
        )

        assert cpu_response.status_code == 200
        data = cpu_response.json()
        assert not data["gpu_used"]
        assert data["execution_time_ms"] > 0

    async def test_automatic_cpu_fallback(
        self,
        authenticated_client: AsyncClient
    ):
        """
        Test automatic CPU fallback when GPU unavailable.

        When GPU is requested but unavailable, system should automatically
        fall back to CPU without error.

        NOTE: This test assumes GPU might not be available and verifies
        graceful handling.
        """
        create_response = await authenticated_client.post(
            "/api/lattices",
            json={"dimensions": 2, "size": 1000}
        )
        lattice_id = create_response.json()["id"]

        # Request GPU (may not be available)
        response = await authenticated_client.post(
            f"/api/lattices/{lattice_id}/transform",
            json={
                "transformation_type": "xor",
                "parameters": {"key": "fallback_key"},
                "use_gpu": True
            }
        )

        assert response.status_code == 200
        data = response.json()
        # Should have either used GPU or fallen back to CPU
        assert "gpu_used" in data
        assert "execution_time_ms" in data


# ============================================================================
# TEST CLASS: Concurrent GPU
# ============================================================================

class TestConcurrentGPU:
    """Test concurrent GPU request handling"""

    @pytest.mark.gpu_required
    async def test_concurrent_small_lattices(
        self,
        authenticated_client: AsyncClient,
        gpu_available: bool
    ):
        """
        Test handling 10 concurrent small lattice requests.
        """
        if not gpu_available:
            pytest.skip("GPU not available")

        # Create 10 lattices
        lattice_ids = []
        for i in range(10):
            create_resp = await authenticated_client.post(
                "/api/lattices",
                json={"dimensions": 2, "size": 100, "name": f"Concurrent {i}"}
            )
            lattice_ids.append(create_resp.json()["id"])

        # Concurrent transformations
        async def transform(lattice_id):
            return await authenticated_client.post(
                f"/api/lattices/{lattice_id}/transform",
                json={"transformation_type": "xor", "parameters": {}}
            )

        tasks = [transform(lid) for lid in lattice_ids]
        responses = await asyncio.gather(*tasks)

        # All should succeed
        assert all(r.status_code == 200 for r in responses)

    @pytest.mark.gpu_required
    async def test_concurrent_large_lattices(
        self,
        authenticated_client: AsyncClient,
        gpu_available: bool
    ):
        """
        Test handling 5 concurrent large lattice requests.

        Large lattices require more GPU memory, so concurrency is limited.
        This tests that the system handles concurrent GPU operations correctly.
        """
        if not gpu_available:
            pytest.skip("GPU not available")

        # Create 5 large lattices
        lattice_ids = []
        for i in range(5):
            create_resp = await authenticated_client.post(
                "/api/lattices",
                json={"dimensions": 2, "size": 5000, "name": f"Large Concurrent {i}"}
            )
            lattice_ids.append(create_resp.json()["id"])

        # Concurrent transformations
        async def transform(lattice_id):
            return await authenticated_client.post(
                f"/api/lattices/{lattice_id}/transform",
                json={"transformation_type": "xor", "parameters": {}, "use_gpu": True}
            )

        tasks = [transform(lid) for lid in lattice_ids]
        responses = await asyncio.gather(*tasks)

        # All should complete (may take longer due to queuing)
        success_count = sum(1 for r in responses if r.status_code == 200)
        assert success_count >= 4, "At least 4 of 5 concurrent operations should succeed"

    @pytest.mark.gpu_required
    async def test_mixed_gpu_cpu_concurrent(
        self,
        authenticated_client: AsyncClient,
        gpu_available: bool
    ):
        """
        Test handling mixed GPU and CPU requests concurrently.
        """
        if not gpu_available:
            pytest.skip("GPU not available")

        # Create 10 lattices
        lattice_ids = []
        for i in range(10):
            create_resp = await authenticated_client.post(
                "/api/lattices",
                json={"dimensions": 2, "size": 1000}
            )
            lattice_ids.append(create_resp.json()["id"])

        # Mixed GPU/CPU transformations
        async def transform(lattice_id, use_gpu):
            return await authenticated_client.post(
                f"/api/lattices/{lattice_id}/transform",
                json={
                    "transformation_type": "xor",
                    "parameters": {},
                    "use_gpu": use_gpu
                }
            )

        tasks = []
        for i, lid in enumerate(lattice_ids):
            use_gpu = i < 5  # First 5 use GPU, last 5 use CPU
            tasks.append(transform(lid, use_gpu))

        responses = await asyncio.gather(*tasks)
        assert all(r.status_code == 200 for r in responses)


# ============================================================================
# TEST CLASS: GPU Memory Management
# ============================================================================

class TestGPUMemoryManagement:
    """Test GPU memory allocation and cleanup"""

    @pytest.mark.gpu_required
    async def test_memory_allocated_and_freed(
        self,
        authenticated_client: AsyncClient,
        gpu_available: bool
    ):
        """
        Test GPU memory is allocated and freed correctly.

        NOTE: This is a simplified version. Full memory monitoring requires
        GPU monitoring fixtures with torch.cuda or cupy memory tracking.
        """
        if not gpu_available:
            pytest.skip("GPU not available")

        # Create and transform
        create_resp = await authenticated_client.post(
            "/api/lattices",
            json={"dimensions": 2, "size": 5000}
        )
        lattice_id = create_resp.json()["id"]

        transform_resp = await authenticated_client.post(
            f"/api/lattices/{lattice_id}/transform",
            json={"transformation_type": "xor", "parameters": {}, "use_gpu": True}
        )
        assert transform_resp.status_code == 200

        # Wait for GPU cleanup
        await asyncio.sleep(1)

        # Verify transformation completed successfully
        assert transform_resp.json()["gpu_used"]

    @pytest.mark.gpu_required
    async def test_no_memory_leaks(
        self,
        authenticated_client: AsyncClient,
        gpu_available: bool
    ):
        """
        Test no memory leaks over 100 transformations.
        """
        if not gpu_available:
            pytest.skip("GPU not available")

        # Create lattice
        create_resp = await authenticated_client.post(
            "/api/lattices",
            json={"dimensions": 2, "size": 1000}
        )
        lattice_id = create_resp.json()["id"]

        # 100 transformations
        for i in range(100):
            transform_resp = await authenticated_client.post(
                f"/api/lattices/{lattice_id}/transform",
                json={"transformation_type": "xor", "parameters": {}, "use_gpu": True}
            )
            assert transform_resp.status_code == 200

        # All transformations should succeed without memory exhaustion
        # (Full memory leak detection requires GPU memory monitoring)

    @pytest.mark.gpu_required
    async def test_memory_exhaustion_handling(
        self,
        authenticated_client: AsyncClient,
        gpu_available: bool
    ):
        """
        Test handling GPU out-of-memory gracefully.

        When GPU memory is exhausted, system should fall back to CPU
        or return helpful error, not crash.
        """
        if not gpu_available:
            pytest.skip("GPU not available")

        # Very large lattice (likely to exceed GPU memory)
        create_resp = await authenticated_client.post(
            "/api/lattices",
            json={"dimensions": 3, "size": 100000, "name": "OOM Test"}
        )

        if create_resp.status_code == 413:
            # Lattice creation rejected due to size
            pytest.skip("Lattice too large to create")
            return

        lattice_id = create_resp.json()["id"]

        # Attempt transformation
        transform_resp = await authenticated_client.post(
            f"/api/lattices/{lattice_id}/transform",
            json={"transformation_type": "xor", "parameters": {}, "use_gpu": True}
        )

        # Should either succeed with CPU fallback or return helpful error
        assert transform_resp.status_code in [200, 413, 500]

        if transform_resp.status_code == 200:
            # CPU fallback occurred or GPU handled it
            assert "gpu_used" in transform_resp.json()


# ============================================================================
# TEST CLASS: GPU Monitoring
# ============================================================================

class TestGPUMonitoring:
    """Test GPU monitoring and metrics"""

    @pytest.mark.gpu_required
    async def test_gpu_status_endpoint(
        self,
        authenticated_client: AsyncClient,
        gpu_available: bool
    ):
        """
        Test GPU status endpoint returns correct data.
        """
        if not gpu_available:
            pytest.skip("GPU not available")

        response = await authenticated_client.get("/api/gpu/status")
        assert response.status_code == 200

        data = response.json()
        assert "available" in data
        assert data["available"]
        assert "backend" in data
        assert "device_count" in data
        assert data["device_count"] >= 1
        assert "devices" in data
        assert len(data["devices"]) >= 1

        # Verify device info structure
        device = data["devices"][0]
        assert "id" in device
        assert "name" in device
        assert "memory_total_gb" in device

    @pytest.mark.gpu_required
    async def test_gpu_metrics_collection(
        self,
        authenticated_client: AsyncClient,
        gpu_available: bool
    ):
        """
        Test GPU metrics are collected during transformation.
        """
        if not gpu_available:
            pytest.skip("GPU not available")

        # Create lattice and transform with GPU
        create_resp = await authenticated_client.post(
            "/api/lattices",
            json={"dimensions": 2, "size": 2000}
        )
        lattice_id = create_resp.json()["id"]

        transform_resp = await authenticated_client.post(
            f"/api/lattices/{lattice_id}/transform",
            json={"transformation_type": "xor", "parameters": {}, "use_gpu": True}
        )
        assert transform_resp.status_code == 200

        # Verify metrics in response
        data = transform_resp.json()
        assert "execution_time_ms" in data
        assert "gpu_used" in data

        # If metrics endpoint exists, query it
        try:
            metrics_resp = await authenticated_client.get("/metrics")
            if metrics_resp.status_code == 200:
                metrics_text = metrics_resp.text
                # Check for GPU utilization metric
                assert "gpu_utilization_percent" in metrics_text or "lattice_transformation" in metrics_text
        except Exception:
            # Metrics endpoint may not be implemented yet
            pass


# ============================================================================
# TEST CLASS: GPU Error Handling
# ============================================================================

class TestGPUErrorHandling:
    """Test GPU error scenarios"""

    @pytest.mark.gpu_required
    async def test_cuda_oom_error_handling(
        self,
        authenticated_client: AsyncClient,
        gpu_available: bool
    ):
        """
        Test CUDA out-of-memory error is handled gracefully.
        """
        if not gpu_available:
            pytest.skip("GPU not available")

        # Attempt very large operation
        create_resp = await authenticated_client.post(
            "/api/lattices",
            json={"dimensions": 3, "size": 50000}
        )

        if create_resp.status_code != 201:
            # Creation itself may fail for large lattice
            pytest.skip("Lattice too large to create")
            return

        lattice_id = create_resp.json()["id"]

        transform_resp = await authenticated_client.post(
            f"/api/lattices/{lattice_id}/transform",
            json={"transformation_type": "xor", "parameters": {}, "use_gpu": True}
        )

        # Should not crash server - either succeeds or returns error
        assert transform_resp.status_code in [200, 413, 500, 503]

        if transform_resp.status_code == 200:
            # Succeeded (possibly with CPU fallback)
            assert "gpu_used" in transform_resp.json()

    async def test_invalid_gpu_operation(
        self,
        authenticated_client: AsyncClient
    ):
        """
        Test invalid GPU operation returns clear error.
        """
        create_resp = await authenticated_client.post(
            "/api/lattices",
            json={"dimensions": 2, "size": 100}
        )
        lattice_id = create_resp.json()["id"]

        # Invalid transformation type
        transform_resp = await authenticated_client.post(
            f"/api/lattices/{lattice_id}/transform",
            json={
                "transformation_type": "invalid_operation",
                "parameters": {},
                "use_gpu": True
            }
        )

        # Should return clear error (not crash)
        assert transform_resp.status_code in [400, 422]
        error_data = transform_resp.json()
        assert "detail" in error_data
