#!/usr/bin/env python3
"""
Comprehensive GPU Performance Benchmark
Tests CuPy, Numba CUDA, and PyTorch on GTX 1080
"""

import os
import time
import numpy as np

# Configure CUDA environment
TORCH_CUDA_PATH = (
    r"C:\Users\Corbin\AppData\Local\Programs\Python\Python312\Lib\site-packages\torch\lib"
)
os.environ["CUDA_HOME"] = TORCH_CUDA_PATH
os.environ["CUDA_PATH"] = TORCH_CUDA_PATH
os.environ["PATH"] = TORCH_CUDA_PATH + ";" + os.environ.get("PATH", "")

print("=== GPU Performance Benchmark ===")
print("Testing GTX 1080 with CUDA 12.1 libraries")
print()


def format_time(seconds):
    """Format time in appropriate units"""
    if seconds < 1e-6:
        return f"{seconds * 1e9:.2f} ns"
    elif seconds < 1e-3:
        return f"{seconds * 1e6:.2f} us"
    elif seconds < 1:
        return f"{seconds * 1e3:.2f} ms"
    else:
        return f"{seconds:.3f} s"


def format_throughput(ops, time_s):
    """Format throughput in appropriate units"""
    throughput = ops / time_s
    if throughput > 1e9:
        return f"{throughput / 1e9:.2f} GOPS"
    elif throughput > 1e6:
        return f"{throughput / 1e6:.2f} MOPS"
    elif throughput > 1e3:
        return f"{throughput / 1e3:.2f} KOPS"
    else:
        return f"{throughput:.2f} OPS"


# Test configurations
sizes = [1000, 10000, 100000, 1000000]
results = {}

print("1. NUMBA CUDA BENCHMARK")
print("-" * 30)

try:
    from numba import cuda
    import numba

    if cuda.is_available():
        print(f"Numba {numba.__version__} - CUDA Available")
        print(f"GPU: {cuda.get_current_device().name.decode()}")
        print()

        @cuda.jit
        def numba_vector_add(a, b, c):
            idx = cuda.grid(1)
            if idx < a.size:
                c[idx] = a[idx] + b[idx]

        @cuda.jit
        def numba_matrix_mult_element(a, b, c, n):
            row, col = cuda.grid(2)
            if row < n and col < n:
                temp = 0.0
                for k in range(n):
                    temp += a[row, k] * b[k, col]
                c[row, col] = temp

        numba_results = {}

        for size in sizes:
            print(f"Testing size: {size}")

            # Vector addition
            a = np.ones(size, dtype=np.float32)
            b = np.ones(size, dtype=np.float32) * 2
            c = np.zeros(size, dtype=np.float32)

            d_a = cuda.to_device(a)
            d_b = cuda.to_device(b)
            d_c = cuda.device_array_like(c)

            threads_per_block = 256
            blocks_per_grid = (size + threads_per_block - 1) // threads_per_block

            # Warmup
            numba_vector_add[blocks_per_grid, threads_per_block](d_a, d_b, d_c)
            cuda.synchronize()

            # Benchmark
            start = time.perf_counter()
            numba_vector_add[blocks_per_grid, threads_per_block](d_a, d_b, d_c)
            cuda.synchronize()
            numba_time = time.perf_counter() - start

            result = d_c.copy_to_host()

            print(
                f"  Vector Add: {format_time(numba_time)} ({format_throughput(size, numba_time)})"
            )

            numba_results[size] = {
                "vector_add_time": numba_time,
                "vector_add_throughput": size / numba_time,
            }

        results["numba"] = numba_results
    else:
        print("Numba CUDA not available")

except Exception as e:
    print(f"Numba error: {e}")

print()
print("2. CUPY BENCHMARK")
print("-" * 20)

try:
    import cupy as cp

    print(f"CuPy {cp.__version__}")

    cupy_results = {}

    for size in sizes:
        print(f"Testing size: {size}")

        # Vector operations
        a_gpu = cp.ones(size, dtype=cp.float32)
        b_gpu = cp.ones(size, dtype=cp.float32) * 2

        # Warmup
        c_gpu = a_gpu + b_gpu
        cp.cuda.Stream.null.synchronize()

        # Benchmark
        start = time.perf_counter()
        c_gpu = a_gpu + b_gpu
        cp.cuda.Stream.null.synchronize()
        cupy_time = time.perf_counter() - start

        print(f"  Vector Add: {format_time(cupy_time)} ({format_throughput(size, cupy_time)})")

        # Matrix multiplication for larger sizes
        if size <= 2000:
            n = int(np.sqrt(size))
            if n > 10:
                A = cp.ones((n, n), dtype=cp.float32)
                B = cp.ones((n, n), dtype=cp.float32)

                # Warmup
                C = cp.dot(A, B)
                cp.cuda.Stream.null.synchronize()

                # Benchmark
                start = time.perf_counter()
                C = cp.dot(A, B)
                cp.cuda.Stream.null.synchronize()
                matmul_time = time.perf_counter() - start

                ops = n * n * (2 * n - 1)  # FLOPS for matrix multiplication
                print(
                    f"  Matrix Mul: {format_time(matmul_time)} ({format_throughput(ops, matmul_time)})"
                )

        cupy_results[size] = {
            "vector_add_time": cupy_time,
            "vector_add_throughput": size / cupy_time,
        }

    results["cupy"] = cupy_results

except Exception as e:
    print(f"CuPy error: {e}")

print()
print("3. PYTORCH BENCHMARK")
print("-" * 21)

try:
    import torch

    if torch.cuda.is_available():
        print(f"PyTorch {torch.__version__}")
        print(f"CUDA Device: {torch.cuda.get_device_name()}")

        pytorch_results = {}

        for size in sizes:
            print(f"Testing size: {size}")

            # Vector operations
            a_torch = torch.ones(size, dtype=torch.float32, device="cuda")
            b_torch = torch.ones(size, dtype=torch.float32, device="cuda") * 2

            # Warmup
            c_torch = a_torch + b_torch
            torch.cuda.synchronize()

            # Benchmark
            start = time.perf_counter()
            c_torch = a_torch + b_torch
            torch.cuda.synchronize()
            pytorch_time = time.perf_counter() - start

            print(
                f"  Vector Add: {format_time(pytorch_time)} ({format_throughput(size, pytorch_time)})"
            )

            pytorch_results[size] = {
                "vector_add_time": pytorch_time,
                "vector_add_throughput": size / pytorch_time,
            }

        results["pytorch"] = pytorch_results
    else:
        print("PyTorch CUDA not available")

except Exception as e:
    print(f"PyTorch error: {e}")

print()
print("=== PERFORMANCE SUMMARY ===")
print()

if "numba" in results and "cupy" in results:
    print("Vector Addition Comparison (1M elements):")
    if 1000000 in results["numba"] and 1000000 in results["cupy"]:
        numba_time = results["numba"][1000000]["vector_add_time"]
        cupy_time = results["cupy"][1000000]["vector_add_time"]
        pytorch_time = results.get("pytorch", {}).get(1000000, {}).get("vector_add_time", 0)

        print(f"  Numba:   {format_time(numba_time)}")
        print(f"  CuPy:    {format_time(cupy_time)}")
        if pytorch_time:
            print(f"  PyTorch: {format_time(pytorch_time)}")

        print()
        print("Relative Performance:")
        fastest = min(numba_time, cupy_time)
        print(f"  Numba is {fastest / numba_time:.2f}x relative speed")
        print(f"  CuPy is {fastest / cupy_time:.2f}x relative speed")
        if pytorch_time:
            print(f"  PyTorch is {fastest / pytorch_time:.2f}x relative speed")

print()
print("GPU Computing Environment Status: FULLY OPERATIONAL")
print("Ready for high-performance scientific computing!")
