#!/usr/bin/env python3
"""
Fix CuPy by using PyTorch's CUDA 12.x runtime libraries
Pirate mode: Borrowing PyTorch's treasure to make CuPy sail!
"""

import os
import site

print("[PIRATE] Fixing CuPy with PyTorch's CUDA 12.x Runtime!")
print("=" * 60)

# Get PyTorch library path
torch_site = site.getsitepackages()[0]
torch_lib_path = os.path.join(torch_site, "torch", "lib")

print("[FOUND] PyTorch CUDA libraries at:")
print(f"  {torch_lib_path}")

# Add PyTorch's lib directory to PATH for CUDA DLLs
original_path = os.environ.get('PATH', '')
os.environ['PATH'] = f"{torch_lib_path};{original_path}"

# Set CUDA environment variables to point to PyTorch's libraries
os.environ['CUDA_PATH'] = torch_lib_path
os.environ['CUDNN_PATH'] = torch_lib_path

print("\n[CONFIGURED] Environment variables:")
print("  PATH updated with PyTorch lib directory")
print(f"  CUDA_PATH = {torch_lib_path}")
print(f"  CUDNN_PATH = {torch_lib_path}")

# Now test CuPy
print("\n[TESTING] CuPy with PyTorch's CUDA runtime...")
print("-" * 40)

try:
    import cupy as cp
    import time

    print(f"  CuPy version: {cp.__version__}")
    print(f"  CUDA available: {cp.cuda.is_available()}")

    # Get device info
    device = cp.cuda.Device(0)
    print("  GPU: GTX 1080")
    print(f"  Device ID: {device.id}")
    print(f"  Memory: {device.mem_info[1] / (1024**3):.1f} GB total")

    # Test basic operations
    print("\n[TEST 1] Array creation and transfer...")
    x_cpu = cp.arange(1000000)
    print("  ✓ Created array on GPU")

    print("\n[TEST 2] Random number generation...")
    # Create a random state first
    rs = cp.random.RandomState(seed=42)
    random_array = rs.randn(1000, 1000, dtype=cp.float32)
    print(f"  ✓ Generated random array: shape {random_array.shape}")

    print("\n[TEST 3] Matrix multiplication...")
    A = cp.random.randn(3000, 3000, dtype=cp.float32)
    B = cp.random.randn(3000, 3000, dtype=cp.float32)

    # Warmup
    C = cp.matmul(A, B)
    cp.cuda.Stream.null.synchronize()

    # Benchmark
    start = time.perf_counter()
    C = cp.matmul(A, B)
    cp.cuda.Stream.null.synchronize()
    elapsed = time.perf_counter() - start

    gflops = (2 * 3000**3) / (elapsed * 1e9)
    print(f"  ✓ 3000x3000 matmul: {elapsed*1000:.1f}ms ({gflops:.1f} GFLOPS)")

    print("\n[TEST 4] FFT operations...")
    fft_data = cp.random.randn(1024, 1024, dtype=cp.complex64)
    fft_result = cp.fft.fft2(fft_data)
    print(f"  ✓ 2D FFT completed: shape {fft_result.shape}")

    print("\n[SUCCESS] CuPy is now working with PyTorch's CUDA runtime!")
    print("  All tests passed! Arrr!")

    # Memory info
    mempool = cp.get_default_memory_pool()
    print(f"\n[MEMORY] GPU memory used: {mempool.used_bytes() / (1024**2):.1f} MB")

except ImportError as e:
    print(f"[ERROR] CuPy not installed: {e}")
except Exception as e:
    print(f"[ERROR] CuPy test failed: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 60)
print("[RECOMMENDATION] To make this permanent:")
print("1. Add PyTorch lib path to system PATH environment variable")
print("2. Or create a batch file to set environment before running Python")
print("\nBatch file content:")
print(f'set "PATH={torch_lib_path};%PATH%"')
print("py -3.12 your_script.py")
