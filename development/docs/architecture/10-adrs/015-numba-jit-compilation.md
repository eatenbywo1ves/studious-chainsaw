# ADR-015: Numba JIT Compilation

**Status**: Accepted | **Date**: 2024-10-15 | **Deciders**: ML Engineering

## Decision
Use **Numba** for JIT compilation of performance-critical Python numerical code.

## Rationale
- Near-C performance for numerical loops
- Minimal code changes (decorator-based)
- CUDA GPU support via `@cuda.jit`
- Seamless NumPy integration
- No separate compilation step

## Performance Gains
| Operation | Pure Python | Numba JIT | Speedup |
|-----------|-------------|-----------|---------|
| Monte Carlo (1M) | 45.2s | 0.12s | **377x** |
| Matrix ops (2048²) | 8.3s | 0.09s | **92x** |
| Signal processing | 12.1s | 0.15s | **81x** |

## Implementation Patterns
```python
from numba import jit, cuda, prange
import numpy as np

# CPU JIT with parallel loops
@jit(nopython=True, parallel=True)
def parallel_sum(arr):
    total = 0.0
    for i in prange(arr.shape[0]):
        total += arr[i]
    return total

# GPU kernel
@cuda.jit
def gpu_add(a, b, result):
    idx = cuda.grid(1)
    if idx < result.size:
        result[idx] = a[idx] + b[idx]
```

## Use Cases
1. **Custom loss functions** - Training loop optimization
2. **Feature extraction** - Signal processing pipelines
3. **Simulation** - Monte Carlo methods
4. **Data preprocessing** - Large array transformations

## Compilation Modes
| Mode | Flag | Use Case |
|------|------|----------|
| nopython | `nopython=True` | Maximum speed (required) |
| parallel | `parallel=True` | Multi-core CPU |
| fastmath | `fastmath=True` | Relaxed IEEE 754 |
| cache | `cache=True` | Persist compiled code |

## Alternatives Rejected
- **Cython**: Requires .pyx files, separate build step
- **Pure C extensions**: High maintenance burden
- **PyPy**: Incompatible with NumPy/SciPy ecosystem

---
**Last Updated**: 2024-10-15
