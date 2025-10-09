#!/usr/bin/env python3
"""
GPU Acceleration Test Suite for Catalytic Computing
Tests various GPU acceleration options and benchmarks performance
"""

import sys
import time
import numpy as np
import platform
from pathlib import Path

print("=" * 70)
print("GPU ACCELERATION TEST SUITE FOR CATALYTIC COMPUTING")
print("=" * 70)

# System Information
print("\n[SYSTEM INFORMATION]")
print(f"Python Version: {sys.version}")
print(f"Platform: {platform.platform()}")
print(f"Processor: {platform.processor()}")

# Test 1: Check NVIDIA GPU Status
print("\n[1] NVIDIA GPU DETECTION")
try:
    import subprocess

    result = subprocess.run(
        ["nvidia-smi", "--query-gpu=name,memory.total,compute_cap", "--format=csv,noheader"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        gpu_info = result.stdout.strip()
        print(f"[OK] GPU Found: {gpu_info}")
    else:
        print("[X] nvidia-smi command failed")
except Exception as e:
    print(f"[X] Could not detect NVIDIA GPU: {e}")

# Test 2: NumPy Performance (CPU Baseline)
print("\n[2] NUMPY CPU BASELINE")
size = 10000
print(f"Testing matrix multiplication ({size}x{size})...")
A = np.random.randn(size, size).astype(np.float32)
B = np.random.randn(size, size).astype(np.float32)

start = time.time()
C_cpu = np.dot(A[:1000, :1000], B[:1000, :1000])  # Smaller for CPU
cpu_time = time.time() - start
print(f"[OK] NumPy CPU Time (1000x1000): {cpu_time:.4f} seconds")
print(f"  GFLOPS: {(2 * 1000**3) / (cpu_time * 1e9):.2f}")

# Test 3: Numba CUDA Support
print("\n[3] NUMBA GPU SUPPORT")
try:
    from numba import cuda

    if cuda.is_available():
        print("[OK] Numba CUDA support is available")

        # Get GPU info through Numba
        gpu = cuda.get_current_device()
        print(f"  GPU Name: {gpu.name}")
        print(f"  Compute Capability: {gpu.compute_capability}")
        print(f"  Total Memory: {gpu.total_memory / 1024**3:.2f} GB")

        # Simple Numba CUDA test
        @cuda.jit
        def add_kernel(x, y, out):
            idx = cuda.grid(1)
            if idx < x.size:
                out[idx] = x[idx] + y[idx]

        # Test kernel
        n = 1000000
        x = np.ones(n, dtype=np.float32)
        y = np.ones(n, dtype=np.float32)
        out = np.zeros(n, dtype=np.float32)

        # Transfer to GPU
        d_x = cuda.to_device(x)
        d_y = cuda.to_device(y)
        d_out = cuda.device_array_like(out)

        # Run kernel
        threads_per_block = 256
        blocks_per_grid = (n + threads_per_block - 1) // threads_per_block

        start = time.time()
        add_kernel[blocks_per_grid, threads_per_block](d_x, d_y, d_out)
        cuda.synchronize()
        gpu_time = time.time() - start

        print(f"  Kernel execution time: {gpu_time * 1000:.3f} ms")
        print("  Speedup vs CPU: N/A (different operation)")
    else:
        print("[X] Numba CUDA not available - CPU only")
        print("  To enable: pip install cudatoolkit")
except ImportError:
    print("[X] Numba is installed but CUDA support not configured")
except Exception as e:
    print(f"[X] Numba CUDA test failed: {e}")

# Test 4: PyTorch GPU Support
print("\n[4] PYTORCH GPU SUPPORT")
try:
    import torch

    print(f"[OK] PyTorch Version: {torch.__version__}")

    if torch.cuda.is_available():
        print("[OK] CUDA Available: True")
        print(f"  CUDA Version: {torch.version.cuda}")
        print(f"  GPU Count: {torch.cuda.device_count()}")
        print(f"  Current GPU: {torch.cuda.get_device_name(0)}")

        # Benchmark
        size = 5000
        A_torch = torch.randn(size, size, dtype=torch.float32)
        B_torch = torch.randn(size, size, dtype=torch.float32)

        # CPU timing
        start = time.time()
        C_cpu = torch.mm(A_torch, B_torch)
        cpu_time = time.time() - start

        # GPU timing
        A_cuda = A_torch.cuda()
        B_cuda = B_torch.cuda()
        torch.cuda.synchronize()

        start = time.time()
        C_gpu = torch.mm(A_cuda, B_cuda)
        torch.cuda.synchronize()
        gpu_time = time.time() - start

        print(f"  Matrix Multiply ({size}x{size}):")
        print(f"    CPU Time: {cpu_time:.4f}s")
        print(f"    GPU Time: {gpu_time:.4f}s")
        print(f"    Speedup: {cpu_time / gpu_time:.2f}x")
    else:
        print("[X] CUDA Not Available - CPU only version installed")
        print("  To enable: pip uninstall torch")
        print(
            "  Then: pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124"
        )
except ImportError:
    print("[X] PyTorch not installed")
    print(
        "  To install: pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124"
    )

# Test 5: CuPy (CUDA NumPy)
print("\n[5] CUPY GPU ACCELERATION")
try:
    import cupy as cp

    print(f"[OK] CuPy Version: {cp.__version__}")
    print(f"  CUDA Version: {cp.cuda.runtime.runtimeGetVersion()}")

    # Benchmark
    size = 5000
    A_cp = cp.random.randn(size, size, dtype=cp.float32)
    B_cp = cp.random.randn(size, size, dtype=cp.float32)

    # Warm-up
    _ = cp.dot(A_cp[:100, :100], B_cp[:100, :100])
    cp.cuda.Stream.null.synchronize()

    start = time.time()
    C_gpu = cp.dot(A_cp, B_cp)
    cp.cuda.Stream.null.synchronize()
    gpu_time = time.time() - start

    print(f"  Matrix Multiply ({size}x{size}): {gpu_time:.4f}s")
    print(f"  GFLOPS: {(2 * size**3) / (gpu_time * 1e9):.2f}")
except ImportError:
    print("[X] CuPy not installed")
    print("  To install: pip install cupy-cuda12x")
except Exception as e:
    print(f"[X] CuPy test failed: {e}")

# Test 6: Catalytic Computing GPU Potential
print("\n[6] CATALYTIC COMPUTING GPU OPTIMIZATION POTENTIAL")
print("Analyzing catalytic_lattice_computing.py capabilities...")

# Check if the catalytic computing file exists
catalytic_file = Path("catalytic_lattice_computing.py")
if catalytic_file.exists():
    print("[OK] Catalytic computing implementation found")

    # Analyze potential GPU optimizations
    with open(catalytic_file, "r") as f:
        content = f.read()

    optimizations = []
    if "numpy" in content or "np." in content:
        optimizations.append("  - NumPy operations -> CuPy (10-50x speedup)")
    if "for" in content and "range" in content:
        optimizations.append("  - Python loops -> CUDA kernels (100-1000x speedup)")
    if "lattice" in content.lower():
        optimizations.append("  - Lattice operations -> Parallel GPU computation")
    if "xor" in content.lower():
        optimizations.append("  - XOR operations -> GPU bitwise operations")

    print("Potential GPU Optimizations:")
    for opt in optimizations:
        print(opt)
else:
    print("[X] catalytic_lattice_computing.py not found")

# Test 7: Memory Requirements
print("\n[7] GPU MEMORY ANALYSIS FOR CATALYTIC COMPUTING")
lattice_dims = [(100, 5), (1000, 5), (10000, 5), (100000, 5), (1000000, 5)]
print("Lattice Size | Memory Required | Fits in GTX 1080 (8GB)")
print("-" * 55)
for points, dims in lattice_dims:
    memory_mb = (points * dims * 4) / (1024**2)  # float32
    fits = "[OK]" if memory_mb < 8000 else "[X]"
    print(f"{points:8d} x {dims} | {memory_mb:10.2f} MB  | {fits}")

# Recommendations
print("\n" + "=" * 70)
print("RECOMMENDATIONS FOR GPU ACCELERATION")
print("=" * 70)

recommendations = []

# Check current setup
has_cuda = False
has_gpu_torch = False
has_cupy = False

try:
    import torch

    has_gpu_torch = torch.cuda.is_available()
except:
    pass

try:
    has_cupy = True
except:
    pass

try:
    from numba import cuda

    has_cuda = cuda.is_available()
except:
    pass

if not has_gpu_torch:
    recommendations.append(
        {
            "priority": "HIGH",
            "action": "Install PyTorch with CUDA",
            "command": "pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124",
            "benefit": "10-50x speedup for tensor operations",
        }
    )

if not has_cupy:
    recommendations.append(
        {
            "priority": "HIGH",
            "action": "Install CuPy for GPU NumPy",
            "command": "pip install cupy-cuda12x",
            "benefit": "Drop-in replacement for NumPy with GPU acceleration",
        }
    )

if not has_cuda:
    recommendations.append(
        {
            "priority": "MEDIUM",
            "action": "Configure Numba CUDA",
            "command": "conda install cudatoolkit -c conda-forge",
            "benefit": "Custom CUDA kernels for maximum performance",
        }
    )

recommendations.append(
    {
        "priority": "LOW",
        "action": "Install JAX with CUDA",
        "command": 'pip install --upgrade "jax[cuda12]"',
        "benefit": "Automatic differentiation and XLA compilation",
    }
)

for rec in sorted(recommendations, key=lambda x: x["priority"]):
    print(f"\n[{rec['priority']}] {rec['action']}")
    print(f"  Command: {rec['command']}")
    print(f"  Benefit: {rec['benefit']}")

print("\n" + "=" * 70)
print("TEST COMPLETE")
print("=" * 70)
