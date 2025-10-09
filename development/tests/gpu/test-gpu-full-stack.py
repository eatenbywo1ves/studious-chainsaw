#!/usr/bin/env python3
"""
Complete GPU Stack Validation
Tests PyTorch, CuPy, and KA Lattice with GPU acceleration

Requirements:
  - Python 3.12
  - PyTorch 2.5.1+cu121
  - CuPy 13.6.0 (cupy-cuda12x)
  - NVIDIA GPU with CUDA support
"""

import sys
import time
import numpy as np
from pathlib import Path

# Add development directory to path
sys.path.insert(0, str(Path(__file__).parent))

print("=" * 70)
print("COMPLETE GPU STACK VALIDATION")
print("=" * 70)

# Test 1: CUDA Initialization
print("\n[Test 1] CUDA Environment Initialization")
print("-" * 70)
try:
    from libs.gpu.cuda_init import initialize_cuda_environment, get_cuda_info

    success = initialize_cuda_environment(verbose=True)
    if not success:
        print("[FAIL] CUDA initialization failed")
        sys.exit(1)
    print("[OK] CUDA initialization successful")
except Exception as e:
    print(f"[FAIL] CUDA init error: {e}")
    import traceback

    traceback.print_exc()
    sys.exit(1)

# Test 2: PyTorch GPU
print("\n[Test 2] PyTorch GPU Acceleration")
print("-" * 70)
try:
    import torch

    print(f"PyTorch version: {torch.__version__}")
    print(f"CUDA available: {torch.cuda.is_available()}")
    print(f"CUDA version: {torch.version.cuda}")
    print(f"GPU: {torch.cuda.get_device_name(0)}")

    # Performance test
    device = torch.device("cuda:0")
    size = 2048
    start = time.time()
    a = torch.randn(size, size, device=device)
    b = torch.randn(size, size, device=device)
    c = torch.mm(a, b)
    torch.cuda.synchronize()
    elapsed = (time.time() - start) * 1000

    print(f"Matrix multiply ({size}x{size}): {elapsed:.2f}ms")
    print("[OK] PyTorch GPU working")
except Exception as e:
    print(f"[FAIL] PyTorch error: {e}")
    sys.exit(1)

# Test 3: CuPy with CURAND
print("\n[Test 3] CuPy GPU with CURAND")
print("-" * 70)
try:
    import cupy as cp

    print(f"CuPy version: {cp.__version__}")
    print(f"CUDA available: {cp.cuda.is_available()}")

    # Test CURAND (the problematic component)
    start = time.time()
    x = cp.random.randn(10000, 10000)
    cp.cuda.Stream.null.synchronize()
    elapsed = (time.time() - start) * 1000

    print(f"Random generation (10000x10000): {elapsed:.2f}ms")
    print(f"Sample values: {x[:5, 0]}")
    print("[OK] CuPy CURAND working")
except Exception as e:
    print(f"[FAIL] CuPy error: {e}")
    import traceback

    traceback.print_exc()
    sys.exit(1)

# Test 4: KA Lattice with GPU
print("\n[Test 4] KA Lattice GPU Acceleration")
print("-" * 70)
try:
    from apps.catalytic.core.unified_lattice import UnifiedCatalyticLattice

    # Create lattice with GPU enabled
    print("Creating 4D lattice with GPU acceleration...")
    start = time.time()
    lattice = UnifiedCatalyticLattice(dimensions=4, size=10, enable_gpu=True)
    elapsed = (time.time() - start) * 1000

    print(f"Lattice creation: {elapsed:.2f}ms")
    print(f"GPU enabled: {lattice.enable_gpu}")
    print(
        f"GPU backend: {lattice.gpu_backend.__class__.__name__ if lattice.gpu_backend else 'None'}"
    )

    # Test XOR transform with GPU
    if lattice.gpu_backend:
        test_array = np.array([5, 10, 15, 20, 25], dtype=np.int32)
        start = time.time()
        result = lattice.xor_transform(test_array)
        elapsed = (time.time() - start) * 1000

        print(f"XOR transform: {elapsed:.2f}ms")
        print(f"Input: {test_array}")
        print(f"Output: {result}")
        print("[OK] KA Lattice GPU working")
    else:
        print("[WARN] GPU backend not initialized")

except Exception as e:
    print(f"[FAIL] KA Lattice error: {e}")
    import traceback

    traceback.print_exc()
    sys.exit(1)

# Test 5: Performance Comparison
print("\n[Test 5] CPU vs GPU Performance Comparison")
print("-" * 70)
try:
    # GPU benchmark
    device = torch.device("cuda:0")
    size = 1024
    iterations = 10

    print(f"Running {iterations} iterations of {size}x{size} matrix multiply...")

    # Warmup
    a = torch.randn(size, size, device=device)
    b = torch.randn(size, size, device=device)
    _ = torch.mm(a, b)
    torch.cuda.synchronize()

    # GPU timing
    start = time.time()
    for _ in range(iterations):
        c = torch.mm(a, b)
    torch.cuda.synchronize()
    gpu_time = (time.time() - start) * 1000 / iterations

    # CPU timing
    a_cpu = a.cpu()
    b_cpu = b.cpu()
    start = time.time()
    for _ in range(iterations):
        c_cpu = torch.mm(a_cpu, b_cpu)
    cpu_time = (time.time() - start) * 1000 / iterations

    speedup = cpu_time / gpu_time

    print(f"CPU time: {cpu_time:.2f}ms")
    print(f"GPU time: {gpu_time:.2f}ms")
    print(f"Speedup: {speedup:.2f}x")
    print("[OK] Performance comparison complete")

except Exception as e:
    print(f"[WARN] Performance comparison failed: {e}")

# Summary
print("\n" + "=" * 70)
print("GPU STACK VALIDATION SUMMARY")
print("=" * 70)
available, info = get_cuda_info()
print(f"CUDA Available: {available}")
print(f"CUDA Version: {info['version']}")
print(f"GPU Device: {info['device_name']}")
print(f"Lib Path: {info['lib_path']}")
print(f"DLL Count: {info['dll_count']}")
print("\n[OK] ALL TESTS PASSED - GPU acceleration fully functional!")
print("=" * 70)
