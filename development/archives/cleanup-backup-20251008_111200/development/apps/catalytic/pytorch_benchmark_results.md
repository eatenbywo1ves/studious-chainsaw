# PyTorch GPU Benchmark Results
*Date: 2025-09-21*
*GPU: NVIDIA GeForce GTX 1080 (8GB)*
*PyTorch Version: 2.5.1+cu121*

## Executive Summary
Successfully configured PyTorch with CUDA 12.1 support on GTX 1080!
- **Average GPU Speedup: 6.51x**
- **Maximum GPU Speedup: 20.54x** (3D lattice 128x128x128)
- GPU excels at larger problem sizes and 3D computations

## Detailed Benchmark Results

### 2D Lattice Simulations
| Size | Steps | GPU Time | CPU Time | Speedup | GPU Memory |
|------|-------|----------|----------|---------|------------|
| 128  | 100   | 0.063s   | 0.036s   | 0.58x   | 0.12 MB    |
| 256  | 100   | 0.089s   | 0.166s   | 1.88x   | 0.50 MB    |
| 512  | 50    | 0.046s   | 0.171s   | 3.72x   | 2.00 MB    |

### 3D Lattice Simulations
| Size | Steps | GPU Time | CPU Time | Speedup | GPU Memory |
|------|-------|----------|----------|---------|------------|
| 64   | 50    | 0.096s   | 0.557s   | 5.83x   | 2.00 MB    |
| 128  | 30    | 0.100s   | 2.044s   | 20.54x  | 16.00 MB   |

## Key Insights

1. **Overhead vs Throughput**: Small 2D problems (128x128) show GPU overhead dominates
2. **Scaling Advantage**: GPU speedup increases dramatically with problem size
3. **3D Superiority**: 3D computations show exceptional GPU performance (5.83x-20.54x)
4. **Memory Efficiency**: Only 16MB used for largest test (128³ lattice)

## Technical Configuration
- Python 3.12.10 (separate installation for PyTorch compatibility)
- CUDA Version: 12.1 (PyTorch build)
- Driver Version: 566.36
- Compute Capability: 6.1

## Next Steps
- [x] Install Python 3.12 for PyTorch
- [x] Install PyTorch with CUDA support
- [x] Benchmark catalytic lattice computations
- [ ] Fix CuPy for Python 3.12/CUDA compatibility
- [ ] Resolve Numba CUDA detection issues
- [ ] Optimize memory usage for larger lattices