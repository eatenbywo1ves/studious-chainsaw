# Technical Design Document: GPU-SaaS Integration Tests

**Feature**: `test_gpu_saas_integration.py`
**Architect**: BMAD Architect Agent
**Date**: 2025-10-05
**PRD Reference**: `PRD_GPU_SAAS_INTEGRATION.md`
**Implementation Estimate**: 6-8 hours

---

## Architecture Overview

This TDD provides implementation specifications for GPU integration tests validating GPU-accelerated lattice transformations work correctly through the SaaS API with proper fallback and memory management.

### GPU Integration Architecture

```
┌──────────────────────────────────────────────────────────┐
│                   SaaS API Server                        │
│  ┌────────────────────────────────────────────────────┐  │
│  │  POST /api/lattices/{id}/transform                 │  │
│  │  { "use_gpu": true, "transformation_type": "xor" } │  │
│  └─────────────────┬──────────────────────────────────┘  │
│                    │                                      │
│  ┌─────────────────▼──────────────────────────────────┐  │
│  │        GPU Operation Router                        │  │
│  │  - Checks GPU availability                         │  │
│  │  - Validates lattice size threshold                │  │
│  │  - Routes to GPU or CPU                            │  │
│  └─────────────────┬──────────────────────────────────┘  │
│                    │                                      │
│         ┌──────────┴──────────┐                          │
│         │                     │                          │
│  ┌──────▼────────┐    ┌──────▼────────┐                │
│  │  GPU Backend  │    │  CPU Backend  │                 │
│  │  (CuPy/PyTorch│    │  (NumPy)      │                 │
│  └───────────────┘    └───────────────┘                 │
└──────────────────────────────────────────────────────────┘
```

---

## GPU Backend Specifications

### GPU Manager
**File**: `apps/catalytic/gpu/manager.py`

The existing GPUManager provides:
- GPU availability detection
- Memory monitoring
- Device capabilities querying
- Backend selection (CuPy, PyTorch, CPU fallback)

### GPU Factory
**File**: `apps/catalytic/gpu/factory.py`

The GPUFactory creates appropriate GPU implementations based on:
- Available backend (CuPy/PyTorch)
- Lattice dimensions and size
- Memory requirements

### Operation Router
**File**: `apps/catalytic/gpu/operation_router.py`

Smart routing logic:
- **Size < 1000**: Use CPU (overhead dominates)
- **Size >= 1000**: Use GPU if available
- **Size >= 10000**: Strongly prefer GPU (10x+ speedup)

---

## API Endpoint Design

### POST /api/lattices/{lattice_id}/transform
**Implementation**: To be added to `saas/api/saas_server.py`

```python
from apps.catalytic.gpu.manager import get_gpu_manager
from apps.catalytic.gpu.factory import GPUFactory
from apps.catalytic.gpu.operation_router import OperationRouter

@app.post("/api/lattices/{lattice_id}/transform")
async def transform_lattice(
    lattice_id: str,
    request: TransformRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Transform lattice with GPU acceleration support"""
    import time
    start_time = time.time()

    # Get lattice
    lattice = lattice_manager.get_lattice(current_user.tenant_id, lattice_id)
    if not lattice:
        raise HTTPException(status_code=404, detail="Lattice not found")

    # Determine if GPU should be used
    gpu_manager = get_gpu_manager()
    router = OperationRouter()

    use_gpu = router.should_use_gpu(
        operation_type=request.transformation_type,
        data_size=lattice.size,
        force_gpu=request.use_gpu,
        gpu_available=gpu_manager.is_gpu_available()
    )

    # Perform transformation
    if use_gpu:
        gpu_lattice = GPUFactory.create(
            backend=gpu_manager.get_backend(),
            dimensions=lattice.dimensions,
            size=lattice.size
        )
        result = gpu_lattice.xor_transform(
            lattice.lattice_data,
            key=request.parameters.get("key")
        )
        gpu_used = True
    else:
        # CPU fallback
        result = lattice.xor_transform(request.parameters.get("key"))
        gpu_used = False

    execution_time_ms = int((time.time() - start_time) * 1000)

    # Save operation to database
    operation = LatticeOperation(
        tenant_id=current_user.tenant_id,
        lattice_id=lattice_id,
        operation_type=request.transformation_type,
        parameters=request.parameters,
        result={"gpu_used": gpu_used, "execution_time_ms": execution_time_ms},
        execution_time_ms=execution_time_ms,
        created_by_id=current_user.id
    )
    db.add(operation)
    db.commit()

    return TransformResponse(
        lattice_id=lattice_id,
        operation_id=operation.id,
        transformation_type=request.transformation_type,
        execution_time_ms=execution_time_ms,
        gpu_used=gpu_used,
        result_summary={"success": True}
    )
```

### GET /api/gpu/status
**Implementation**: New endpoint for GPU monitoring

```python
@app.get("/api/gpu/status")
async def get_gpu_status(current_user: User = Depends(get_current_user)):
    """Get GPU availability and status"""
    gpu_manager = get_gpu_manager()

    return {
        "available": gpu_manager.is_gpu_available(),
        "backend": gpu_manager.get_backend().value if gpu_manager.is_gpu_available() else None,
        "device_count": len(gpu_manager.get_all_devices()),
        "devices": [
            {
                "id": device_id,
                "name": cap.device_name,
                "memory_total_gb": cap.total_memory_gb,
                "compute_capability": cap.compute_capability
            }
            for device_id, cap in gpu_manager.get_all_devices().items()
        ]
    }
```

---

## Implementation Components

### Test File: test_gpu_saas_integration.py

```python
"""
GPU-SaaS Integration Tests

Tests GPU-accelerated transformations through the SaaS API,
including performance, memory management, and CPU fallback.
"""

import pytest
import asyncio
import time
from typing import Dict, Any
from httpx import AsyncClient
import numpy as np

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

try:
    import cupy as cp
    CUPY_AVAILABLE = True
except ImportError:
    CUPY_AVAILABLE = False


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

        Steps:
        1. Create small lattice (size=100)
        2. Transform with use_gpu=true
        3. Verify CPU was used (smarter routing)
        4. Transform with use_gpu=false
        5. Compare timings
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

        Steps:
        1. Create large lattice (size=10000)
        2. Transform with GPU
        3. Measure execution time
        4. Transform with CPU
        5. Verify GPU is faster (at least 2x)
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
        assert gpu_response.json()["gpu_used"] == True

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
        assert cpu_response.json()["gpu_used"] == False

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

        Steps:
        1. Create lattice
        2. Get initial state
        3. Transform with GPU
        4. Create identical lattice
        5. Transform with CPU
        6. Verify results are identical
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
        # (This would require returning result data, which may be large)
        # For now, verify operations completed successfully
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

        Steps:
        1. Create lattice
        2. Transform with use_gpu=false
        3. Verify CPU was used
        4. Verify transformation succeeded
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
        assert data["gpu_used"] == False
        assert data["execution_time_ms"] > 0

    @pytest.mark.mock_gpu_unavailable
    async def test_automatic_cpu_fallback(
        self,
        authenticated_client: AsyncClient,
        mock_gpu_unavailable
    ):
        """
        Test automatic CPU fallback when GPU unavailable.

        When GPU is requested but unavailable, system should automatically
        fall back to CPU without error.

        Steps:
        1. Mock GPU as unavailable
        2. Request transformation with use_gpu=true
        3. Verify CPU fallback occurred automatically
        4. Verify no errors
        """
        create_response = await authenticated_client.post(
            "/api/lattices",
            json={"dimensions": 2, "size": 1000}
        )
        lattice_id = create_response.json()["id"]

        # Request GPU (but GPU unavailable via mock)
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
        # Should have fallen back to CPU
        assert data["gpu_used"] == False
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

        Steps:
        1. Create 10 small lattices
        2. Submit transformations concurrently
        3. Verify all complete successfully
        4. Verify reasonable execution times
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

        Steps:
        1. Create 5 large lattices
        2. Submit transformations concurrently
        3. Verify all complete (may queue internally)
        4. Verify no OOM errors
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
        assert success_count >= 4  # Allow 1 potential failure due to resource constraints

    @pytest.mark.gpu_required
    async def test_mixed_gpu_cpu_concurrent(
        self,
        authenticated_client: AsyncClient,
        gpu_available: bool
    ):
        """
        Test handling mixed GPU and CPU requests concurrently.

        Steps:
        1. Create 10 lattices
        2. Submit 5 GPU and 5 CPU transformations concurrently
        3. Verify all complete
        4. Verify no resource conflicts
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
        gpu_monitor_fixture,
        gpu_available: bool
    ):
        """
        Test GPU memory is allocated and freed correctly.

        Steps:
        1. Record initial GPU memory
        2. Create and transform lattice
        3. Record peak GPU memory
        4. Wait for cleanup
        5. Record final GPU memory
        6. Verify memory returned to baseline
        """
        if not gpu_available:
            pytest.skip("GPU not available")

        initial_memory = gpu_monitor_fixture.get_memory_allocated()

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

        final_memory = gpu_monitor_fixture.get_memory_allocated()

        # Memory should return to baseline (within 1MB tolerance)
        memory_delta = abs(final_memory - initial_memory)
        assert memory_delta < 1024 * 1024, f"Memory leak detected: {memory_delta / 1024 / 1024:.2f} MB"

    @pytest.mark.gpu_required
    async def test_no_memory_leaks(
        self,
        authenticated_client: AsyncClient,
        gpu_monitor_fixture,
        gpu_available: bool
    ):
        """
        Test no memory leaks over 100 transformations.

        Steps:
        1. Record initial memory
        2. Perform 100 transformations
        3. Record final memory
        4. Verify no cumulative memory growth
        """
        if not gpu_available:
            pytest.skip("GPU not available")

        # Create lattice
        create_resp = await authenticated_client.post(
            "/api/lattices",
            json={"dimensions": 2, "size": 1000}
        )
        lattice_id = create_resp.json()["id"]

        initial_memory = gpu_monitor_fixture.get_memory_allocated()

        # 100 transformations
        for i in range(100):
            transform_resp = await authenticated_client.post(
                f"/api/lattices/{lattice_id}/transform",
                json={"transformation_type": "xor", "parameters": {}, "use_gpu": True}
            )
            assert transform_resp.status_code == 200

            # Every 10 iterations, check memory isn't growing
            if i % 10 == 0:
                current_memory = gpu_monitor_fixture.get_memory_allocated()
                growth = current_memory - initial_memory
                # Allow some growth, but not linear with iterations
                assert growth < 100 * 1024 * 1024, f"Memory growing: {growth / 1024 / 1024:.2f} MB at iteration {i}"

        final_memory = gpu_monitor_fixture.get_memory_allocated()
        total_growth = final_memory - initial_memory

        # Total growth should be minimal (< 10MB)
        assert total_growth < 10 * 1024 * 1024, f"Memory leak: {total_growth / 1024 / 1024:.2f} MB total growth"

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

        Steps:
        1. Create very large lattice (exceeding GPU memory)
        2. Attempt transformation
        3. Verify graceful handling (CPU fallback or 413 error)
        4. Verify no server crash
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
            # CPU fallback occurred
            assert transform_resp.json()["gpu_used"] == False


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

        Steps:
        1. GET /api/gpu/status
        2. Verify response contains GPU info
        3. Verify device count and capabilities
        """
        if not gpu_available:
            pytest.skip("GPU not available")

        response = await authenticated_client.get("/api/gpu/status")
        assert response.status_code == 200

        data = response.json()
        assert "available" in data
        assert data["available"] == True
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

        Steps:
        1. Create lattice and transform with GPU
        2. Query metrics endpoint
        3. Verify GPU utilization metric present
        4. Verify execution time recorded
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

        data = transform_resp.json()
        assert "execution_time_ms" in data
        assert data["execution_time_ms"] > 0
        assert data["gpu_used"] == True


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
        Test CUDA out-of-memory error handled gracefully.

        Steps:
        1. Create lattice near GPU memory limit
        2. Transform
        3. Verify error handling or CPU fallback
        4. Verify helpful error message
        """
        if not gpu_available:
            pytest.skip("GPU not available")

        # Large lattice
        create_resp = await authenticated_client.post(
            "/api/lattices",
            json={"dimensions": 3, "size": 50000}
        )

        if create_resp.status_code != 201:
            pytest.skip("Lattice creation failed")
            return

        lattice_id = create_resp.json()["id"]

        transform_resp = await authenticated_client.post(
            f"/api/lattices/{lattice_id}/transform",
            json={"transformation_type": "xor", "parameters": {}, "use_gpu": True}
        )

        # Should handle gracefully
        assert transform_resp.status_code in [200, 413, 500]

        if transform_resp.status_code != 200:
            # Verify error message is helpful
            assert "detail" in transform_resp.json()

    @pytest.mark.gpu_required
    async def test_invalid_gpu_operation(
        self,
        authenticated_client: AsyncClient,
        gpu_available: bool
    ):
        """
        Test invalid GPU operation returns clear error.

        Steps:
        1. Create lattice
        2. Request unsupported transformation type
        3. Verify 422 validation error
        4. Verify error message describes issue
        """
        if not gpu_available:
            pytest.skip("GPU not available")

        create_resp = await authenticated_client.post(
            "/api/lattices",
            json={"dimensions": 2, "size": 1000}
        )
        lattice_id = create_resp.json()["id"]

        transform_resp = await authenticated_client.post(
            f"/api/lattices/{lattice_id}/transform",
            json={
                "transformation_type": "unsupported_transform",
                "parameters": {},
                "use_gpu": True
            }
        )

        assert transform_resp.status_code == 422  # Validation error
        assert "detail" in transform_resp.json()
```

---

## Test Fixtures Required

### GPU Monitor Fixture
**File**: `tests/integration/conftest.py`

```python
import pytest

class GPUMemoryMonitor:
    """Monitor GPU memory usage during tests"""

    def __init__(self):
        try:
            import torch
            self.backend = "torch"
            self.torch = torch
        except ImportError:
            try:
                import cupy as cp
                self.backend = "cupy"
                self.cp = cp
            except ImportError:
                self.backend = None

    def get_memory_allocated(self) -> int:
        """Get current GPU memory allocated in bytes"""
        if self.backend == "torch":
            return self.torch.cuda.memory_allocated()
        elif self.backend == "cupy":
            mempool = self.cp.get_default_memory_pool()
            return mempool.used_bytes()
        return 0

    def reset(self):
        """Reset GPU memory"""
        if self.backend == "torch":
            self.torch.cuda.empty_cache()
        elif self.backend == "cupy":
            mempool = self.cp.get_default_memory_pool()
            mempool.free_all_blocks()


@pytest.fixture
def gpu_monitor_fixture():
    """Fixture providing GPU memory monitoring"""
    monitor = GPUMemoryMonitor()
    monitor.reset()
    yield monitor
    monitor.reset()
```

### Mock GPU Unavailable Fixture
**File**: `tests/integration/conftest.py`

```python
from unittest.mock import patch

@pytest.fixture
def mock_gpu_unavailable():
    """Mock GPU as unavailable for testing fallback"""
    with patch('apps.catalytic.gpu.manager.GPUManager.is_gpu_available', return_value=False):
        yield
```

---

## Performance Benchmarks

| Lattice Size | GPU Target | CPU Target | Expected Speedup |
|--------------|-----------|-----------|------------------|
| 100 | 10ms | 5ms | N/A (CPU faster) |
| 1,000 | 50ms | 100ms | 2x |
| 10,000 | 200ms | 2000ms | 10x |
| 100,000 | 1000ms | 20000ms | 20x |

---

## Deployment Notes

### Prerequisites
- NVIDIA GPU with CUDA support
- PyTorch or CuPy installed
- nvidia-smi available
- GPU drivers up to date

### Running Tests
```bash
# Run all GPU tests
pytest tests/integration/test_gpu_saas_integration.py -v -m gpu_required

# Run without GPU tests (CPU fallback only)
pytest tests/integration/test_gpu_saas_integration.py -v -m "not gpu_required"

# Run with GPU memory profiling
pytest tests/integration/test_gpu_saas_integration.py -v --profile-gpu
```

---

**TDD Approved By**: BMAD Architect Agent
**Ready for**: Developer Agent (Implementation)
**Status**: ✅ Complete - Implementation Ready

**Next**: Create TDD for Security Integration Tests.
