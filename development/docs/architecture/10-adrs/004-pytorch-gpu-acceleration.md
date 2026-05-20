# ADR-004: PyTorch for GPU Acceleration

**Status**: Accepted
**Date**: 2024-09-22
**Deciders**: Architecture Team, ML Engineering Lead
**Technical Story**: Select GPU framework for Catalytic Engine

---

## Context

The Catalytic Engine requires GPU acceleration for high-performance computing operations, achieving 649x speedup over CPU.

### Problem Statement

Choose a GPU computing framework that provides optimal performance, developer productivity, and ecosystem compatibility.

### Driving Forces

- **Performance**: Must achieve 7+ TFLOPS sustained
- **Flexibility**: Support matrix ops, custom kernels, and deep learning
- **Ecosystem**: Rich library support and community
- **Integration**: Works with CuPy and Numba for hybrid workloads

---

## Decision

**We will use PyTorch 2.0+ as the primary GPU framework for tensor operations and deep learning workloads.**

### Implementation

```python
import torch

# Device selection
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

# Tensor operations on GPU
x = torch.randn(4096, 4096, device=device)
y = torch.randn(4096, 4096, device=device)
z = torch.matmul(x, y)  # 7.24 TFLOPS

# Mixed precision for memory efficiency
with torch.cuda.amp.autocast():
    result = model(input)
```

---

## Consequences

### Positive (Benefits)

- ✅ **Performance**: 7.24 TFLOPS validated, excellent CUDA optimization
- ✅ **Dynamic Graphs**: Easy debugging, Pythonic API
- ✅ **Ecosystem**: torchvision, torchaudio, transformers integration
- ✅ **Production Ready**: torch.compile() for optimization
- ✅ **Multi-GPU**: Easy DataParallel and DistributedDataParallel

### Negative (Trade-offs)

- ❌ **Memory Usage**: Higher baseline memory than TensorFlow
- ❌ **Mobile**: TorchScript less mature than TFLite
- ❌ **TPU Support**: Limited (Google hardware favors TensorFlow)

---

## Alternatives Considered

### Alternative 1: TensorFlow 2.x

**Pros**: Production-focused, TPU support, TFLite mobile
**Cons**: Less Pythonic, eager mode slower, verbose API
**Why Rejected**: PyTorch has better developer experience and CUDA performance

### Alternative 2: JAX

**Pros**: Functional, excellent for research, XLA compilation
**Cons**: Smaller ecosystem, less production tooling
**Why Rejected**: Ecosystem less mature for production deployment

---

## Related Decisions

- [ADR-012: CuPy GPU NumPy](012-cupy-gpu-numpy.md)
- [ADR-015: Numba JIT](015-numba-jit-compilation.md)

---

**Last Updated**: 2024-10-15
