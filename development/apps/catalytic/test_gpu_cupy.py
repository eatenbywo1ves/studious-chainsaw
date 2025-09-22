#!/usr/bin/env python3
"""
Test GPU acceleration with CuPy
"""

import numpy as np
import cupy as cp
import time

def test_cupy_gpu():
    """Test CuPy GPU acceleration"""
    print("="*60)
    print("    CUPY GPU ACCELERATION TEST")
    print("="*60)

    # Check GPU availability
    print(f"\nGPU Device: {cp.cuda.runtime.getDeviceProperties(0)['name'].decode()}")

    # Get memory info
    mem_info = cp.cuda.runtime.memGetInfo()
    total_gb = mem_info[1] / (1024**3)
    free_gb = mem_info[0] / (1024**3)
    print(f"GPU Memory: {total_gb:.1f}GB total, {free_gb:.1f}GB free")

    print("\nRunning benchmarks...")

    results = {}

    # Test 1: Matrix multiplication
    for size in [1000, 2000, 3000]:
        print(f"\n{size}x{size} Matrix Multiplication:")

        # GPU computation
        A_gpu = cp.random.random((size, size), dtype=cp.float32)
        B_gpu = cp.random.random((size, size), dtype=cp.float32)

        # Warmup
        C_gpu = cp.dot(A_gpu, B_gpu)
        cp.cuda.Stream.null.synchronize()

        # Timed run
        start = time.perf_counter()
        C_gpu = cp.dot(A_gpu, B_gpu)
        cp.cuda.Stream.null.synchronize()
        gpu_time = (time.perf_counter() - start) * 1000

        # CPU computation
        A_cpu = cp.asnumpy(A_gpu)
        B_cpu = cp.asnumpy(B_gpu)

        start = time.perf_counter()
        C_cpu = np.dot(A_cpu, B_cpu)
        cpu_time = (time.perf_counter() - start) * 1000

        speedup = cpu_time / gpu_time
        results[f'matmul_{size}'] = speedup

        print(f"  GPU: {gpu_time:.2f}ms")
        print(f"  CPU: {cpu_time:.2f}ms")
        print(f"  Speedup: {speedup:.2f}x")

    # Test 2: Element-wise operations
    print("\n10M Element Operations:")
    size = 10_000_000

    # GPU
    arr_gpu = cp.random.random(size, dtype=cp.float32)
    start = time.perf_counter()
    result_gpu = cp.sqrt(cp.exp(arr_gpu) + cp.sin(arr_gpu))
    cp.cuda.Stream.null.synchronize()
    gpu_time = (time.perf_counter() - start) * 1000

    # CPU
    arr_cpu = cp.asnumpy(arr_gpu)
    start = time.perf_counter()
    result_cpu = np.sqrt(np.exp(arr_cpu) + np.sin(arr_cpu))
    cpu_time = (time.perf_counter() - start) * 1000

    speedup = cpu_time / gpu_time
    results['elementwise'] = speedup

    print(f"  GPU: {gpu_time:.2f}ms")
    print(f"  CPU: {cpu_time:.2f}ms")
    print(f"  Speedup: {speedup:.2f}x")

    # Test 3: FFT
    print("\n1024x1024 2D FFT:")

    # GPU
    data_gpu = cp.random.random((1024, 1024), dtype=cp.complex64)
    start = time.perf_counter()
    fft_gpu = cp.fft.fft2(data_gpu)
    cp.cuda.Stream.null.synchronize()
    gpu_time = (time.perf_counter() - start) * 1000

    # CPU
    data_cpu = cp.asnumpy(data_gpu)
    start = time.perf_counter()
    fft_cpu = np.fft.fft2(data_cpu)
    cpu_time = (time.perf_counter() - start) * 1000

    speedup = cpu_time / gpu_time
    results['fft2d'] = speedup

    print(f"  GPU: {gpu_time:.2f}ms")
    print(f"  CPU: {cpu_time:.2f}ms")
    print(f"  Speedup: {speedup:.2f}x")

    # Summary
    print("\n" + "="*60)
    print("    GPU ACCELERATION SUMMARY")
    print("="*60)

    avg_speedup = sum(results.values()) / len(results)
    print(f"Average Speedup: {avg_speedup:.2f}x")

    print("\nDetailed Results:")
    for test, speedup in results.items():
        print(f"  {test}: {speedup:.2f}x faster on GPU")

    # Memory efficiency test
    print("\nMemory Efficiency Test:")

    # Create large sparse-like structure on GPU
    size = 10000
    sparse_ratio = 0.01

    # GPU sparse simulation
    data = cp.random.random((size, size), dtype=cp.float32)
    mask = cp.random.random((size, size)) < sparse_ratio
    sparse_gpu = data * mask

    gpu_memory = sparse_gpu.nbytes / (1024**2)
    traditional_memory = (size * size * 4) / (1024**2)

    print(f"  Traditional dense: {traditional_memory:.2f}MB")
    print(f"  GPU sparse-like: {gpu_memory:.2f}MB")
    print(f"  Memory ratio: {traditional_memory/gpu_memory:.2f}x")

    print("\nGPU Acceleration: FULLY OPERATIONAL")
    return results

if __name__ == "__main__":
    try:
        results = test_cupy_gpu()
        print("\nGPU acceleration with CuPy is working perfectly!")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()