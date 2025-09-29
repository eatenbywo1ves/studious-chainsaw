#!/usr/bin/env python3
"""
Matrix Optimization Benchmark for GTX 1080
Finds optimal matrix sizes for different algorithms
"""
import os
import time
import numpy as np
import math

# Configure CUDA environment
TORCH_CUDA_PATH = r'C:\Users\Corbin\AppData\Local\Programs\Python\Python312\Lib\site-packages\torch\lib'
os.environ['CUDA_HOME'] = TORCH_CUDA_PATH
os.environ['CUDA_PATH'] = TORCH_CUDA_PATH
os.environ['PATH'] = TORCH_CUDA_PATH + ';' + os.environ.get('PATH', '')

print("=== Matrix Optimization Analysis for GTX 1080 ===")
print("Finding optimal matrix sizes for maximum performance")
print()

def benchmark_matrix_operation(framework, operation, sizes, warmup_runs=3, test_runs=5):
    """Benchmark matrix operations across different sizes"""
    results = {}

    for size in sizes:
        times = []
        memory_usage = 0

        try:
            for run in range(warmup_runs + test_runs):
                if framework == 'numba':
                    from numba import cuda

                    @cuda.jit
                    def matrix_multiply_numba(A, B, C):
                        row, col = cuda.grid(2)
                        if row < C.shape[0] and col < C.shape[1]:
                            temp = 0.0
                            for k in range(A.shape[1]):
                                temp += A[row, k] * B[k, col]
                            C[row, col] = temp

                    # Create matrices
                    A = np.random.random((size, size)).astype(np.float32)
                    B = np.random.random((size, size)).astype(np.float32)
                    C = np.zeros((size, size), dtype=np.float32)

                    # Transfer to GPU
                    d_A = cuda.to_device(A)
                    d_B = cuda.to_device(B)
                    d_C = cuda.to_device(C)

                    # Configure grid
                    threads_per_block = (16, 16)
                    blocks_per_grid_x = math.ceil(size / threads_per_block[0])
                    blocks_per_grid_y = math.ceil(size / threads_per_block[1])
                    blocks_per_grid = (blocks_per_grid_x, blocks_per_grid_y)

                    if run >= warmup_runs:
                        start = time.perf_counter()

                    matrix_multiply_numba[blocks_per_grid, threads_per_block](d_A, d_B, d_C)
                    cuda.synchronize()

                    if run >= warmup_runs:
                        end = time.perf_counter()
                        times.append(end - start)

                    memory_usage = A.nbytes * 3  # A, B, C matrices

                elif framework == 'cupy':
                    import cupy as cp

                    A = cp.random.random((size, size), dtype=cp.float32)
                    B = cp.random.random((size, size), dtype=cp.float32)

                    if run >= warmup_runs:
                        start = time.perf_counter()

                    C = cp.dot(A, B)
                    cp.cuda.Stream.null.synchronize()

                    if run >= warmup_runs:
                        end = time.perf_counter()
                        times.append(end - start)

                    memory_usage = A.nbytes * 3

                elif framework == 'pytorch':
                    import torch

                    A = torch.randn(size, size, dtype=torch.float32, device='cuda')
                    B = torch.randn(size, size, dtype=torch.float32, device='cuda')

                    if run >= warmup_runs:
                        start = time.perf_counter()

                    C = torch.mm(A, B)
                    torch.cuda.synchronize()

                    if run >= warmup_runs:
                        end = time.perf_counter()
                        times.append(end - start)

                    memory_usage = A.numel() * 4 * 3  # float32 = 4 bytes

            # Calculate statistics
            avg_time = np.mean(times)
            std_time = np.std(times)
            min_time = np.min(times)

            # Calculate FLOPS (2*n^3 operations for matrix multiplication)
            flops = 2 * size**3
            gflops = flops / (avg_time * 1e9)

            # Calculate memory bandwidth utilization
            memory_gb = memory_usage / 1e9
            bandwidth_gbps = memory_gb / avg_time

            results[size] = {
                'avg_time': avg_time,
                'min_time': min_time,
                'std_time': std_time,
                'gflops': gflops,
                'bandwidth_gbps': bandwidth_gbps,
                'memory_gb': memory_gb
            }

            print(f"  {size:4d}x{size:<4d}: {avg_time*1000:6.2f}ms | {gflops:6.1f} GFLOPS | {bandwidth_gbps:5.1f} GB/s")

        except Exception as e:
            print(f"  {size:4d}x{size:<4d}: ERROR - {str(e)[:50]}...")
            results[size] = None

    return results

# GTX 1080 specifications
GTX_1080_SPECS = {
    'cuda_cores': 2560,
    'base_clock_mhz': 1607,
    'boost_clock_mhz': 1733,
    'memory_gb': 8,
    'memory_bandwidth_gbps': 320,
    'theoretical_fp32_gflops': 2560 * 1733e6 * 2 / 1e9,  # Approximate
    'l2_cache_mb': 2,
    'shared_memory_kb_per_sm': 96,
    'multiprocessors': 20
}

print(f"GTX 1080 Theoretical Peak: {GTX_1080_SPECS['theoretical_fp32_gflops']:.1f} GFLOPS")
print(f"Memory Bandwidth: {GTX_1080_SPECS['memory_bandwidth_gbps']} GB/s")
print()

# Test matrix sizes - focusing on powers of 2 and multiples of 32 for optimal memory coalescing
matrix_sizes = [32, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096]

print("1. NUMBA CUDA Matrix Multiplication")
print("=" * 50)
print("  Size     | Time    | GFLOPS | Bandwidth")
numba_results = benchmark_matrix_operation('numba', 'matmul', matrix_sizes)

print()
print("2. CUPY Matrix Multiplication (cuBLAS)")
print("=" * 50)
print("  Size     | Time    | GFLOPS | Bandwidth")
cupy_results = benchmark_matrix_operation('cupy', 'matmul', matrix_sizes)

print()
print("3. PYTORCH Matrix Multiplication (cuBLAS)")
print("=" * 50)
print("  Size     | Time    | GFLOPS | Bandwidth")
pytorch_results = benchmark_matrix_operation('pytorch', 'matmul', matrix_sizes)

print()
print("=== OPTIMIZATION ANALYSIS ===")
print()

def find_optimal_size(results, metric='gflops'):
    """Find the matrix size with optimal performance"""
    if not results:
        return None, 0

    valid_results = {k: v for k, v in results.items() if v is not None}
    if not valid_results:
        return None, 0

    optimal_size = max(valid_results.keys(), key=lambda k: valid_results[k][metric])
    optimal_value = valid_results[optimal_size][metric]

    return optimal_size, optimal_value

# Find optimal sizes for each framework
frameworks = [
    ('Numba CUDA', numba_results),
    ('CuPy (cuBLAS)', cupy_results),
    ('PyTorch (cuBLAS)', pytorch_results)
]

best_overall = {'framework': '', 'size': 0, 'gflops': 0}

for name, results in frameworks:
    if results:
        optimal_size, optimal_gflops = find_optimal_size(results, 'gflops')
        if optimal_size:
            print(f"{name}:")
            print(f"  Optimal size: {optimal_size}x{optimal_size}")
            print(f"  Peak performance: {optimal_gflops:.1f} GFLOPS")
            print(f"  Efficiency: {optimal_gflops/GTX_1080_SPECS['theoretical_fp32_gflops']*100:.1f}% of theoretical peak")

            if optimal_gflops > best_overall['gflops']:
                best_overall = {'framework': name, 'size': optimal_size, 'gflops': optimal_gflops}
            print()

print("OVERALL WINNER:")
print(f"  Framework: {best_overall['framework']}")
print(f"  Optimal matrix size: {best_overall['size']}x{best_overall['size']}")
print(f"  Peak performance: {best_overall['gflops']:.1f} GFLOPS")

print()
print("=== MEMORY CONSIDERATIONS ===")

# Memory usage analysis
for size in [1024, 2048, 4096]:
    memory_per_matrix = size * size * 4 / 1e9  # float32 = 4 bytes
    total_memory = memory_per_matrix * 3  # A, B, C matrices
    memory_percent = total_memory / GTX_1080_SPECS['memory_gb'] * 100

    print(f"{size}x{size} matrices:")
    print(f"  Memory usage: {total_memory:.2f} GB ({memory_percent:.1f}% of 8GB)")
    print(f"  Memory per matrix: {memory_per_matrix:.2f} GB")

print()
print("=== RECOMMENDATIONS ===")
print()
print("For GTX 1080 optimal performance:")
print(f"1. Best overall: {best_overall['size']}x{best_overall['size']} with {best_overall['framework']}")
print("2. Memory-constrained scenarios: Use 2048x2048 max (12GB memory usage)")
print("3. Real-time applications: 512x512 to 1024x1024 for <10ms latency")
print("4. Batch processing: Use largest size that fits in memory")
print("5. Custom kernels: Multiple of 32 for memory coalescing")

print()
print("Framework-specific recommendations:")
print("- Numba: Best for custom algorithms, use 16x16 thread blocks")
print("- CuPy: Best for NumPy-like operations, leverage cuBLAS")
print("- PyTorch: Best for ML workloads, automatic optimization")