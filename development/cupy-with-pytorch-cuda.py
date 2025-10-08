#!/usr/bin/env python3
"""
Configure and test CuPy using PyTorch's CUDA 12.x runtime
Pirate mode: Making CuPy sail with borrowed winds!
"""

import os
import sys
import site

print("[PIRATE] Configuring CuPy to use PyTorch's CUDA Runtime!")
print("=" * 60)

# Get PyTorch paths
torch_site = site.getsitepackages()[0]
torch_base = os.path.join(torch_site, "torch")
torch_lib = os.path.join(torch_base, "lib")
torch_bin = os.path.join(torch_base, "bin")

print("[FOUND] PyTorch installation:")
print(f"  Base: {torch_base}")
print(f"  Lib:  {torch_lib}")
print(f"  Bin:  {torch_bin}")

# Set environment BEFORE importing CuPy
os.environ['CUDA_PATH'] = torch_base  # CuPy looks for bin subdirectory
os.environ['PATH'] = f"{torch_lib};{torch_bin};{os.environ.get('PATH', '')}"

# Windows-specific: Add DLL directories
if hasattr(os, 'add_dll_directory'):
    try:
        os.add_dll_directory(torch_lib)
        os.add_dll_directory(torch_bin)
        print("\n[CONFIGURED] Added DLL directories")
    except:
        pass

print("\n[TESTING] Importing CuPy...")

try:
    import cupy as cp
    import numpy as np
    import time

    print(f"[OK] CuPy version: {cp.__version__}")
    print(f"[OK] CUDA available: {cp.cuda.is_available()}")

    if not cp.cuda.is_available():
        print("[ERROR] CUDA not available in CuPy")
        sys.exit(1)

    # Get device info
    device = cp.cuda.Device(0)
    print(f"[OK] GPU Device: {device.id}")
    mem_info = device.mem_info
    print(f"[OK] GPU Memory: {mem_info[1] / (1024**3):.1f} GB total, {mem_info[0] / (1024**3):.1f} GB free")

    print("\n[BENCHMARK] Running CuPy operations...")
    print("-" * 40)

    # Test 1: Basic array operations
    print("1. Array operations...")
    x = cp.arange(1000000)
    y = cp.ones(1000000)
    z = x + y
    print(f"   [OK] Basic arithmetic: sum = {z[0]}")

    # Test 2: Matrix multiplication
    print("2. Matrix multiplication...")
    size = 3000
    A = cp.random.random((size, size), dtype=cp.float32)
    B = cp.random.random((size, size), dtype=cp.float32)

    # Warmup
    C = cp.dot(A, B)
    cp.cuda.Stream.null.synchronize()

    # Benchmark
    start = time.perf_counter()
    C = cp.dot(A, B)
    cp.cuda.Stream.null.synchronize()
    elapsed = time.perf_counter() - start

    gflops = (2 * size**3) / (elapsed * 1e9)
    print(f"   [OK] {size}x{size} matmul: {elapsed*1000:.1f}ms ({gflops:.1f} GFLOPS)")

    # Test 3: FFT
    print("3. Fast Fourier Transform...")
    data = cp.random.random((1024, 1024), dtype=cp.complex64)
    fft_result = cp.fft.fft2(data)
    print(f"   [OK] 2D FFT shape: {fft_result.shape}")

    # Test 4: Reductions
    print("4. Reduction operations...")
    big_array = cp.random.random(10000000, dtype=cp.float32)
    mean_val = cp.mean(big_array)
    std_val = cp.std(big_array)
    print(f"   [OK] Mean: {mean_val:.4f}, Std: {std_val:.4f}")

    # Memory cleanup
    mempool = cp.get_default_memory_pool()
    used_mb = mempool.used_bytes() / (1024**2)
    mempool.free_all_blocks()

    print("\n[SUCCESS] CuPy is working with PyTorch's CUDA runtime!")
    print(f"  Peak memory used: {used_mb:.1f} MB")
    print("  All tests passed! Arrr!")

except ImportError as e:
    print(f"\n[ERROR] Failed to import CuPy: {e}")
except Exception as e:
    print(f"\n[ERROR] Test failed: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 60)
print("[INFO] To use CuPy with PyTorch's CUDA:")
print("1. Set CUDA_PATH environment variable to PyTorch directory")
print("2. Add PyTorch lib and bin to PATH")
print("3. Or run this script before your CuPy code")
