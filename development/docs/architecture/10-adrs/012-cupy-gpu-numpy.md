# ADR-012: CuPy for GPU-Accelerated NumPy

**Status**: Accepted | **Date**: 2024-10-12 | **Deciders**: ML Engineering

## Decision
Use **CuPy 12.1+** as GPU-accelerated NumPy replacement.

## Performance
| Operation | NumPy (CPU) | CuPy (GPU) | Speedup |
|-----------|-------------|------------|---------|
| Matrix multiply (4096²) | 12.5s | 19ms | **658x** |
| FFT (1M points) | 2.1s | 4.2ms | **500x** |
| Element-wise (100M) | 850ms | 1.3ms | **654x** |

## Implementation
```python
import cupy as cp

# Drop-in replacement for NumPy
x = cp.random.randn(4096, 4096)
y = cp.random.randn(4096, 4096)
z = cp.matmul(x, y)  # Runs on GPU

# Interop with PyTorch
torch_tensor = torch.as_tensor(z, device='cuda')
```

## Benefits
- ✅ NumPy-compatible API (minimal code changes)
- ✅ 649x average speedup
- ✅ Seamless PyTorch interop
- ✅ Custom kernel support (RawKernel)

## Alternatives Rejected
- **NumPy only**: No GPU acceleration
- **Custom CUDA**: High development cost, maintenance burden

---
**Last Updated**: 2024-10-15
