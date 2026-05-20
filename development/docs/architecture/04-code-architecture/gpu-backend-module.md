# GPU Backend Module - Code Architecture

## Overview
The GPU backend module provides a unified interface for PyTorch, CuPy, and Numba backends with intelligent selection based on task characteristics.

## Class Responsibilities

### ComputeBackend (Abstract)
**Location**: `compute/backends/base.py`

```python
from abc import ABC, abstractmethod
from typing import Any, Dict
import numpy as np

class ComputeBackend(ABC):
    """Abstract base class for all compute backends."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Backend identifier."""
        pass

    @property
    @abstractmethod
    def is_available(self) -> bool:
        """Check if backend is available (GPU, drivers, etc.)."""
        pass

    @abstractmethod
    def allocate(self, size_bytes: int) -> Any:
        """Allocate GPU memory."""
        pass

    @abstractmethod
    def deallocate(self, handle: Any) -> None:
        """Release GPU memory."""
        pass

    @abstractmethod
    def to_device(self, data: np.ndarray) -> Any:
        """Transfer data to GPU."""
        pass

    @abstractmethod
    def to_host(self, data: Any) -> np.ndarray:
        """Transfer data back to CPU."""
        pass

    @abstractmethod
    def synchronize(self) -> None:
        """Wait for all GPU operations to complete."""
        pass

    @abstractmethod
    def get_memory_info(self) -> Dict[str, int]:
        """Return {'free': bytes, 'total': bytes}."""
        pass
```

### PyTorchBackend
**Location**: `compute/backends/pytorch_backend.py`

```python
import torch
import torch.nn as nn
from typing import Any, Dict, Optional
import numpy as np

class PyTorchBackend(ComputeBackend):
    """PyTorch backend for deep learning operations."""

    def __init__(self, device_id: int = 0):
        self._device = torch.device(f"cuda:{device_id}" if torch.cuda.is_available() else "cpu")
        self._device_id = device_id

    @property
    def name(self) -> str:
        return "pytorch"

    @property
    def is_available(self) -> bool:
        return torch.cuda.is_available()

    def to_device(self, data: np.ndarray) -> torch.Tensor:
        return torch.from_numpy(data).to(self._device)

    def to_host(self, data: torch.Tensor) -> np.ndarray:
        return data.cpu().numpy()

    def synchronize(self) -> None:
        if torch.cuda.is_available():
            torch.cuda.synchronize(self._device)

    def get_memory_info(self) -> Dict[str, int]:
        if not torch.cuda.is_available():
            return {"free": 0, "total": 0}
        return {
            "free": torch.cuda.mem_get_info(self._device_id)[0],
            "total": torch.cuda.mem_get_info(self._device_id)[1]
        }

    # PyTorch-specific methods
    def load_model(self, path: str) -> nn.Module:
        """Load a saved PyTorch model."""
        model = torch.load(path, map_location=self._device)
        model.eval()
        return model

    def inference(self, model: nn.Module, input_data: torch.Tensor) -> torch.Tensor:
        """Run inference with no gradient computation."""
        with torch.no_grad():
            return model(input_data)

    def matmul(self, a: torch.Tensor, b: torch.Tensor) -> torch.Tensor:
        """Matrix multiplication."""
        return torch.matmul(a, b)

    def enable_mixed_precision(self) -> None:
        """Enable automatic mixed precision for faster computation."""
        torch.set_float32_matmul_precision('high')
```

### CuPyBackend
**Location**: `compute/backends/cupy_backend.py`

```python
import cupy as cp
from typing import Any, Dict
import numpy as np

class CuPyBackend(ComputeBackend):
    """CuPy backend for NumPy-compatible GPU operations."""

    def __init__(self, device_id: int = 0):
        self._device = cp.cuda.Device(device_id)
        self._device_id = device_id

    @property
    def name(self) -> str:
        return "cupy"

    @property
    def is_available(self) -> bool:
        try:
            cp.cuda.runtime.getDeviceCount()
            return True
        except cp.cuda.runtime.CUDARuntimeError:
            return False

    def to_device(self, data: np.ndarray) -> cp.ndarray:
        with self._device:
            return cp.asarray(data)

    def to_host(self, data: cp.ndarray) -> np.ndarray:
        return cp.asnumpy(data)

    def synchronize(self) -> None:
        self._device.synchronize()

    def get_memory_info(self) -> Dict[str, int]:
        with self._device:
            free, total = cp.cuda.runtime.memGetInfo()
            return {"free": free, "total": total}

    # CuPy-specific methods
    def matmul(self, a: cp.ndarray, b: cp.ndarray) -> cp.ndarray:
        """Matrix multiplication using cuBLAS."""
        return cp.matmul(a, b)

    def fft(self, data: cp.ndarray) -> cp.ndarray:
        """FFT using cuFFT."""
        return cp.fft.fft(data)

    def fft2(self, data: cp.ndarray) -> cp.ndarray:
        """2D FFT."""
        return cp.fft.fft2(data)

    def elementwise(self, a: cp.ndarray, b: cp.ndarray, op: str) -> cp.ndarray:
        """Element-wise operations."""
        ops = {
            "add": cp.add,
            "sub": cp.subtract,
            "mul": cp.multiply,
            "div": cp.divide
        }
        return ops[op](a, b)

    def random_normal(self, shape: tuple, dtype=cp.float32) -> cp.ndarray:
        """Generate random normal data on GPU."""
        return cp.random.randn(*shape, dtype=dtype)
```

### NumbaBackend
**Location**: `compute/backends/numba_backend.py`

```python
from numba import jit, cuda, prange
from numba.cuda import cudadrv
from typing import Any, Dict, Callable
import numpy as np

class NumbaBackend(ComputeBackend):
    """Numba backend for JIT-compiled custom kernels."""

    def __init__(self, device_id: int = 0):
        self._device_id = device_id
        cuda.select_device(device_id)

    @property
    def name(self) -> str:
        return "numba"

    @property
    def is_available(self) -> bool:
        return cuda.is_available()

    def to_device(self, data: np.ndarray) -> cuda.devicearray.DeviceNDArray:
        return cuda.to_device(data)

    def to_host(self, data: cuda.devicearray.DeviceNDArray) -> np.ndarray:
        return data.copy_to_host()

    def synchronize(self) -> None:
        cuda.synchronize()

    def get_memory_info(self) -> Dict[str, int]:
        ctx = cuda.current_context()
        free, total = ctx.get_memory_info()
        return {"free": free, "total": total}

    # Numba-specific methods
    def compile_kernel(self, func: Callable, signature: str) -> cuda.dispatcher.CUDADispatcher:
        """
        Compile a CUDA kernel from Python function.

        Example:
            @cuda.jit
            def add_kernel(a, b, result):
                idx = cuda.grid(1)
                if idx < result.size:
                    result[idx] = a[idx] + b[idx]
        """
        return cuda.jit(signature)(func)

    def launch_kernel(
        self,
        kernel: cuda.dispatcher.CUDADispatcher,
        args: tuple,
        grid: tuple,
        block: tuple
    ) -> None:
        """Launch a compiled CUDA kernel."""
        kernel[grid, block](*args)

    def parallel_cpu(self, func: Callable) -> Callable:
        """JIT compile for parallel CPU execution."""
        return jit(nopython=True, parallel=True)(func)

    # Pre-compiled common kernels
    @staticmethod
    @cuda.jit
    def _add_kernel(a, b, result):
        idx = cuda.grid(1)
        if idx < result.size:
            result[idx] = a[idx] + b[idx]

    def vector_add(self, a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """Vector addition using pre-compiled kernel."""
        d_a = self.to_device(a)
        d_b = self.to_device(b)
        d_result = cuda.device_array_like(d_a)

        threads_per_block = 256
        blocks_per_grid = (a.size + threads_per_block - 1) // threads_per_block

        self._add_kernel[blocks_per_grid, threads_per_block](d_a, d_b, d_result)

        return self.to_host(d_result)
```

### BackendSelector
**Location**: `compute/backend_selector.py`

```python
from typing import Dict, Optional, Type
from dataclasses import dataclass
from enum import Enum

class TaskType(Enum):
    DEEP_LEARNING = "deep_learning"
    MATRIX_OPS = "matrix_ops"
    FFT = "fft"
    CUSTOM_KERNEL = "custom_kernel"
    SIGNAL_PROCESSING = "signal_processing"

@dataclass
class JobSpec:
    task_type: TaskType
    input_size: int  # bytes
    requires_autograd: bool = False
    requires_model: bool = False
    custom_kernel: Optional[str] = None

class BackendSelector:
    """
    Selects optimal compute backend based on job characteristics.
    """

    def __init__(self):
        self._backends: Dict[str, ComputeBackend] = {}
        self._register_backends()

    def _register_backends(self) -> None:
        """Register available backends."""
        backends = [PyTorchBackend, CuPyBackend, NumbaBackend]
        for backend_cls in backends:
            try:
                backend = backend_cls()
                if backend.is_available:
                    self._backends[backend.name] = backend
            except Exception:
                pass  # Backend not available

    def select(self, job_spec: JobSpec) -> ComputeBackend:
        """
        Select optimal backend based on task requirements.

        Selection logic:
        1. Deep learning / autograd → PyTorch
        2. NumPy-like array ops → CuPy
        3. Custom kernels → Numba
        4. FFT → CuPy (cuFFT)
        """
        if job_spec.requires_model or job_spec.requires_autograd:
            return self._get_backend("pytorch")

        if job_spec.task_type == TaskType.DEEP_LEARNING:
            return self._get_backend("pytorch")

        if job_spec.task_type in (TaskType.MATRIX_OPS, TaskType.FFT, TaskType.SIGNAL_PROCESSING):
            return self._get_backend("cupy")

        if job_spec.task_type == TaskType.CUSTOM_KERNEL:
            return self._get_backend("numba")

        # Default to CuPy for general operations
        return self._get_backend("cupy")

    def _get_backend(self, name: str) -> ComputeBackend:
        """Get backend with fallback."""
        if name in self._backends:
            return self._backends[name]

        # Fallback chain: cupy → pytorch → numba
        fallback_order = ["cupy", "pytorch", "numba"]
        for fallback in fallback_order:
            if fallback in self._backends:
                return self._backends[fallback]

        raise NoBackendAvailableError("No GPU backends available")

    def get_all_available(self) -> Dict[str, ComputeBackend]:
        """Return all available backends."""
        return self._backends.copy()

    def benchmark(self, job_spec: JobSpec) -> Dict[str, float]:
        """
        Benchmark all backends for a given job spec.
        Returns estimated time in seconds.
        """
        import time
        results = {}

        # Generate test data
        test_size = min(job_spec.input_size, 10_000_000)  # Cap at 10MB for benchmark
        test_data = np.random.randn(test_size // 8).astype(np.float64)

        for name, backend in self._backends.items():
            try:
                start = time.perf_counter()
                d_data = backend.to_device(test_data)
                # Simple operation
                if hasattr(backend, 'matmul'):
                    result = backend.to_host(d_data)
                backend.synchronize()
                end = time.perf_counter()
                results[name] = end - start
            except Exception:
                results[name] = float('inf')

        return results
```

### GPUScheduler
**Location**: `compute/gpu_scheduler.py`

```python
from dataclasses import dataclass
from typing import List, Optional, Dict
from datetime import datetime, timedelta
import threading

@dataclass
class GPUAllocation:
    gpu_id: int
    memory_reserved: int
    allocated_at: datetime
    job_id: str

class GPUScheduler:
    """
    Manages GPU resource allocation across multiple jobs.
    """

    def __init__(self, gpu_count: int = 1):
        self._gpu_count = gpu_count
        self._allocations: Dict[str, GPUAllocation] = {}
        self._lock = threading.Lock()
        self._backends = {i: CuPyBackend(i) for i in range(gpu_count)}

    def allocate(
        self,
        job_id: str,
        memory_required: int,
        preferred_gpu: Optional[int] = None
    ) -> GPUAllocation:
        """
        Allocate GPU resources for a job.

        Algorithm:
        1. Check preferred GPU if specified
        2. Otherwise find GPU with most free memory
        3. Reserve memory + 10% buffer
        """
        with self._lock:
            if preferred_gpu is not None and self._can_allocate(preferred_gpu, memory_required):
                gpu_id = preferred_gpu
            else:
                gpu_id = self._find_best_gpu(memory_required)

            if gpu_id is None:
                raise InsufficientGPUMemoryError(
                    f"Cannot allocate {memory_required} bytes on any GPU"
                )

            allocation = GPUAllocation(
                gpu_id=gpu_id,
                memory_reserved=int(memory_required * 1.1),  # 10% buffer
                allocated_at=datetime.utcnow(),
                job_id=job_id
            )
            self._allocations[job_id] = allocation
            return allocation

    def release(self, job_id: str) -> None:
        """Release GPU allocation for a job."""
        with self._lock:
            if job_id in self._allocations:
                del self._allocations[job_id]

    def get_utilization(self) -> Dict[int, float]:
        """Get utilization percentage for each GPU."""
        result = {}
        for gpu_id in range(self._gpu_count):
            info = self._backends[gpu_id].get_memory_info()
            used = info["total"] - info["free"]
            result[gpu_id] = (used / info["total"]) * 100 if info["total"] > 0 else 0
        return result

    def _can_allocate(self, gpu_id: int, memory_required: int) -> bool:
        """Check if GPU has sufficient free memory."""
        info = self._backends[gpu_id].get_memory_info()
        return info["free"] >= memory_required * 1.1

    def _find_best_gpu(self, memory_required: int) -> Optional[int]:
        """Find GPU with most free memory that can fit the job."""
        best_gpu = None
        best_free = 0

        for gpu_id in range(self._gpu_count):
            info = self._backends[gpu_id].get_memory_info()
            if info["free"] >= memory_required * 1.1 and info["free"] > best_free:
                best_gpu = gpu_id
                best_free = info["free"]

        return best_gpu

    def estimate_wait_time(self, memory_required: int) -> timedelta:
        """Estimate wait time based on current allocations."""
        # Simple heuristic: if any GPU can fit, wait time is 0
        for gpu_id in range(self._gpu_count):
            if self._can_allocate(gpu_id, memory_required):
                return timedelta(seconds=0)

        # Otherwise estimate based on oldest allocation
        if self._allocations:
            oldest = min(a.allocated_at for a in self._allocations.values())
            age = datetime.utcnow() - oldest
            # Assume jobs take ~5 minutes on average
            return max(timedelta(minutes=5) - age, timedelta(seconds=0))

        return timedelta(seconds=0)
```

## Performance Comparison

| Backend | Best For | Overhead | Speedup vs CPU |
|---------|----------|----------|----------------|
| PyTorch | Neural networks, autograd | ~500MB | 50-200x |
| CuPy | Array operations, FFT | ~200MB | 500-700x |
| Numba | Custom algorithms | ~100MB | 50-400x |

## Data Flow

```
┌─────────────┐
│  JobSpec    │
└──────┬──────┘
       │
       ▼
┌──────────────────┐
│ BackendSelector  │
└────────┬─────────┘
         │
    ┌────┴────┬────────────┐
    │         │            │
    ▼         ▼            ▼
┌───────┐ ┌───────┐ ┌──────────┐
│PyTorch│ │ CuPy  │ │  Numba   │
└───┬───┘ └───┬───┘ └────┬─────┘
    │         │          │
    └────┬────┴──────────┘
         │
         ▼
┌──────────────────┐
│  GPUScheduler    │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  GPU Hardware    │
└──────────────────┘
```

---
**Last Updated**: 2024-10-15
