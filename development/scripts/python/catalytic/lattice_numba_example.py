import numpy as np
import numba
from time import time


@numba.jit(nopython=True)
def create_hypercube_lattice(dim, size):
    """Create a high-dimensional hypercube lattice with Numba acceleration"""
    n_points = size**dim
    points = np.zeros((n_points, dim))

    for idx in range(n_points):
        temp = idx
        for d in range(dim):
            points[idx, d] = temp % size
            temp //= size

    return points


@numba.jit(nopython=True)
def compute_lattice_neighbors(points, max_distance=1.5):
    """Find neighbors in lattice within given distance"""
    n = len(points)
    neighbors = []

    for i in range(n):
        for j in range(i + 1, n):
            dist = np.sqrt(np.sum((points[i] - points[j]) ** 2))
            if dist <= max_distance:
                neighbors.append((i, j, dist))

    return neighbors


# Test on high-dimensional lattice
dim = 5  # 5-dimensional
size = 10  # 10x10x10x10x10 lattice

print(f"Creating {dim}D hypercube lattice ({size}^{dim} = {size**dim:,} points)...")
t1 = time()
lattice = create_hypercube_lattice(dim, size)
t2 = time()
print(f"Created in {(t2 - t1) * 1000:.2f}ms")

print("\nFinding nearest neighbors...")
t1 = time()
# For demo, use small subset to avoid memory issues
sample = lattice[:1000]
neighbors = compute_lattice_neighbors(sample)
t2 = time()
print(f"Found {len(neighbors)} neighbor pairs in {(t2 - t1) * 1000:.2f}ms")

print(f"\nLattice shape: {lattice.shape}")
print(f"Memory usage: {lattice.nbytes / 1024**2:.2f} MB")
