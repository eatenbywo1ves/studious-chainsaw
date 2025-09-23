import numba
import numpy as np
from time import time

# Test JIT compilation
@numba.jit
def compute_lattice_sum(n):
    """Example: compute sum of squared indices in a lattice"""
    return np.sum(np.arange(n)**2)

# Test without JIT
def compute_lattice_sum_regular(n):
    return np.sum(np.arange(n)**2)

n = 10_000_000

# Warm up JIT
compute_lattice_sum(100)

# Test JIT version
t1 = time()
result_jit = compute_lattice_sum(n)
t2 = time()
jit_time = (t2 - t1) * 1000

# Test regular version
t1 = time()
result_regular = compute_lattice_sum_regular(n)
t2 = time()
regular_time = (t2 - t1) * 1000

print(f"[SUCCESS] Numba {numba.__version__} installed successfully!")
print(f"\nPerformance test with {n:,} lattice points:")
print(f"  Regular NumPy: {regular_time:.2f}ms")
print(f"  Numba JIT:     {jit_time:.2f}ms")
print(f"  Speedup:       {regular_time/jit_time:.1f}x faster")

# Test parallel processing
@numba.jit(parallel=True)
def compute_lattice_distances(points):
    """Compute pairwise distances in parallel"""
    n = len(points)
    distances = np.zeros((n, n))
    for i in numba.prange(n):
        for j in range(n):
            distances[i, j] = np.sqrt(np.sum((points[i] - points[j])**2))
    return distances

# Create sample high-dimensional lattice points
dims = 10
lattice_size = 100
points = np.random.randn(lattice_size, dims)

t1 = time()
distances = compute_lattice_distances(points)
t2 = time()

print(f"\nParallel processing test:")
print(f"  Computed {lattice_size}x{lattice_size} distance matrix")
print(f"  in {dims}D space: {(t2-t1)*1000:.2f}ms")
print(f"  Using {numba.config.NUMBA_NUM_THREADS} CPU threads")