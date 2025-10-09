"""
CPU fallback implementation for lattice operations
Provides compatibility when no GPU is available
"""

import time
import logging
from typing import Tuple, List, Optional
import numpy as np
from scipy.sparse import csr_matrix
from scipy.sparse.csgraph import shortest_path
import multiprocessing as mp

from .base import BaseLatticeGPU, GPUCapabilities

logger = logging.getLogger(__name__)


class CPULattice(BaseLatticeGPU):
    """CPU-based implementation for lattice operations"""

    def __init__(self, dimensions: int, size: int, device_id: int = 0):
        """Initialize CPU lattice"""
        super().__init__(dimensions, size, device_id)
        self.n_cores = mp.cpu_count()
        self.adjacency_matrix = None

    def initialize_device(self) -> bool:
        """Initialize CPU 'device'"""
        try:
            # Get system info
            import psutil

            self.total_memory_mb = psutil.virtual_memory().total / (1024**2)
            self.available_memory_mb = psutil.virtual_memory().available / (1024**2)

            self._capabilities = GPUCapabilities(
                device_name=f"CPU ({self.n_cores} cores)",
                device_id=0,
                total_memory_mb=self.total_memory_mb,
                available_memory_mb=self.available_memory_mb,
                max_threads_per_block=self.n_cores,
                backend_name="cpu",
            )

            # Allocate auxiliary memory
            aux_size_mb = self.config.lattice.default_aux_memory_mb
            if not self.allocate_memory(aux_size_mb):
                return False

            logger.info(f"Initialized CPU backend with {self.n_cores} cores")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize CPU backend: {e}")
            return False

    def get_device_capabilities(self) -> GPUCapabilities:
        """Get CPU capabilities"""
        return self._capabilities

    def allocate_memory(self, size_mb: float) -> bool:
        """Allocate memory"""
        try:
            size_elements = int(size_mb * 1024 * 1024 / 4)  # float32 elements
            self.auxiliary_memory = np.zeros(size_elements, dtype=np.float32)
            logger.debug(f"Allocated {size_mb:.2f} MB auxiliary memory")
            return True
        except MemoryError:
            logger.error(f"Failed to allocate {size_mb:.2f} MB")
            return False

    def free_memory(self):
        """Free memory"""
        if self.adjacency_matrix is not None:
            del self.adjacency_matrix
            self.adjacency_matrix = None

        if self.auxiliary_memory is not None:
            del self.auxiliary_memory
            self.auxiliary_memory = None

    def transfer_to_device(self, data: np.ndarray) -> np.ndarray:
        """No-op for CPU (data already on CPU)"""
        return data.copy()

    def transfer_from_device(self, data: np.ndarray) -> np.ndarray:
        """No-op for CPU (data already on CPU)"""
        return data.copy()

    def build_lattice(self) -> csr_matrix:
        """Build lattice structure as sparse matrix"""
        start_time = time.perf_counter()

        rows = []
        cols = []
        data = []

        # Generate edges for hypercube lattice
        for i in range(self.n_points):
            coords = self.index_to_coords(i)

            for dim in range(self.dimensions):
                for delta in [-1, 1]:
                    neighbor_coords = coords.copy()
                    neighbor_coords[dim] += delta

                    if 0 <= neighbor_coords[dim] < self.size:
                        j = self.coords_to_index(neighbor_coords)
                        rows.append(i)
                        cols.append(j)
                        data.append(1.0)

        # Create sparse adjacency matrix
        self.adjacency_matrix = csr_matrix(
            (data, (rows, cols)), shape=(self.n_points, self.n_points), dtype=np.float32
        )

        self.adjacency_data = (np.array(rows), np.array(cols), np.array(data))

        build_time = (time.perf_counter() - start_time) * 1000
        logger.info(
            f"Built lattice on CPU: {self.n_points} vertices, {len(rows)} edges in {build_time:.2f}ms"
        )

        return self.adjacency_matrix

    def xor_transform(self, data: np.ndarray, key: Optional[np.ndarray] = None) -> np.ndarray:
        """Apply XOR transformation using NumPy"""
        data_uint = data.astype(np.uint8)

        if key is None:
            key = np.random.randint(0, 256, size=len(data), dtype=np.uint8)
        else:
            key = key.astype(np.uint8)

        # Vectorized XOR operation
        result = np.bitwise_xor(data_uint, key)
        return result

    def find_shortest_path(self, start: int, end: int) -> Tuple[List[int], float]:
        """Find shortest path using scipy's shortest_path"""
        if self.adjacency_matrix is None:
            self.build_lattice()

        start_time = time.perf_counter()

        # Use scipy for shortest path
        dist_matrix, predecessors = shortest_path(
            self.adjacency_matrix, indices=start, return_predecessors=True, directed=False
        )

        # Reconstruct path
        path = []
        current = end
        while current != start and current != -9999:
            path.append(current)
            current = predecessors[current]
        path.append(start)
        path.reverse()

        exec_time = (time.perf_counter() - start_time) * 1000

        return path, exec_time

    def matrix_multiply(self, A: np.ndarray, B: np.ndarray) -> np.ndarray:
        """CPU matrix multiplication using NumPy"""
        # Use optimized BLAS through NumPy
        return np.matmul(A.astype(np.float32), B.astype(np.float32))

    def parallel_reduce(self, data: np.ndarray, operation: str = "sum") -> float:
        """Parallel reduction using NumPy"""
        if operation == "sum":
            return float(np.sum(data))
        elif operation == "max":
            return float(np.max(data))
        elif operation == "min":
            return float(np.min(data))
        else:
            raise ValueError(f"Unsupported operation: {operation}")

    def _parallel_worker(self, func, data_chunk):
        """Worker function for parallel processing"""
        return func(data_chunk)

    def parallel_map(self, func, data: np.ndarray, n_chunks: Optional[int] = None) -> np.ndarray:
        """
        Parallel map operation using multiprocessing

        Args:
            func: Function to apply
            data: Input data
            n_chunks: Number of chunks (defaults to n_cores)

        Returns:
            Processed data
        """
        if n_chunks is None:
            n_chunks = self.n_cores

        # Split data into chunks
        chunks = np.array_split(data, n_chunks)

        # Process in parallel
        with mp.Pool(processes=self.n_cores) as pool:
            results = pool.map(func, chunks)

        # Combine results
        return np.concatenate(results)
