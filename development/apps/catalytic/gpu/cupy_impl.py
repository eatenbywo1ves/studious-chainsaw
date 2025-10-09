"""
CuPy implementation of GPU-accelerated lattice operations
"""

import time
import logging
from typing import Tuple, List, Optional
import numpy as np

try:
    import cupy as cp

    CUPY_AVAILABLE = True
except ImportError:
    CUPY_AVAILABLE = False
    cp = None

from .base import BaseLatticeGPU, GPUCapabilities
from libs.utils.exceptions import GPUNotAvailableError, GPUMemoryError

logger = logging.getLogger(__name__)


class CuPyLatticeGPU(BaseLatticeGPU):
    """CuPy-based GPU implementation for lattice operations"""

    def __init__(self, dimensions: int, size: int, device_id: int = 0):
        """Initialize CuPy lattice GPU"""
        if not CUPY_AVAILABLE:
            raise GPUNotAvailableError("CuPy is not installed")

        super().__init__(dimensions, size, device_id)
        self.device = None
        self.stream = None

    def initialize_device(self) -> bool:
        """Initialize CuPy device"""
        try:
            # Check if device exists
            device_count = cp.cuda.runtime.getDeviceCount()
            if self.device_id >= device_count:
                raise GPUNotAvailableError(
                    f"Device {self.device_id} not found (only {device_count} devices available)"
                )

            # Set device
            self.device = cp.cuda.Device(self.device_id)
            self.device.use()

            # Create stream for async operations
            self.stream = cp.cuda.Stream()

            # Get device capabilities
            self._capabilities = self.get_device_capabilities()

            # Allocate auxiliary memory
            aux_size_mb = self.config.lattice.default_aux_memory_mb
            if not self.allocate_memory(aux_size_mb):
                raise GPUMemoryError(aux_size_mb, self._capabilities.available_memory_mb)

            logger.info(
                f"Initialized CuPy device {self.device_id}: {self._capabilities.device_name}"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to initialize CuPy device: {e}")
            return False

    def get_device_capabilities(self) -> GPUCapabilities:
        """Get CuPy device capabilities"""
        with self.device:
            props = cp.cuda.runtime.getDeviceProperties(self.device_id)
            mem_info = cp.cuda.runtime.memGetInfo()

            name = props["name"]
            if isinstance(name, bytes):
                name = name.decode("utf-8")

            return GPUCapabilities(
                device_name=name,
                device_id=self.device_id,
                total_memory_mb=mem_info[1] / (1024**2),
                available_memory_mb=mem_info[0] / (1024**2),
                compute_capability=(props["major"], props["minor"]),
                max_threads_per_block=props["maxThreadsPerBlock"],
                max_blocks=props["multiProcessorCount"],
                warp_size=props["warpSize"],
                backend_name="cupy",
            )

    def allocate_memory(self, size_mb: float) -> bool:
        """Allocate GPU memory"""
        try:
            with self.device:
                # Allocate auxiliary memory
                size_elements = int(size_mb * 1024 * 1024 / 4)  # float32 elements
                self.auxiliary_memory = cp.zeros(size_elements, dtype=cp.float32)
                logger.debug(f"Allocated {size_mb:.2f} MB auxiliary memory")
                return True
        except cp.cuda.memory.OutOfMemoryError:
            logger.error(f"Failed to allocate {size_mb:.2f} MB on GPU")
            return False

    def free_memory(self):
        """Free GPU memory"""
        try:
            if self.adjacency_data is not None:
                del self.adjacency_data
                self.adjacency_data = None

            if self.auxiliary_memory is not None:
                del self.auxiliary_memory
                self.auxiliary_memory = None

            # Force garbage collection
            cp.get_default_memory_pool().free_all_blocks()
            logger.debug("Freed GPU memory")
        except Exception as e:
            logger.warning(f"Error freeing GPU memory: {e}")

    def transfer_to_device(self, data: np.ndarray) -> cp.ndarray:
        """Transfer data to GPU"""
        with self.device:
            return cp.asarray(data)

    def transfer_from_device(self, gpu_data: cp.ndarray) -> np.ndarray:
        """Transfer data from GPU to CPU"""
        with self.device:
            return cp.asnumpy(gpu_data)

    def build_lattice(self) -> Tuple[cp.ndarray, cp.ndarray, cp.ndarray]:
        """Build lattice structure on GPU"""
        start_time = time.perf_counter()

        with self.device:
            edges = []

            # Generate edges for hypercube lattice
            for i in range(self.n_points):
                coords = self.index_to_coords(i)

                for dim in range(self.dimensions):
                    for delta in [-1, 1]:
                        neighbor_coords = coords.copy()
                        neighbor_coords[dim] += delta

                        if 0 <= neighbor_coords[dim] < self.size:
                            j = self.coords_to_index(neighbor_coords)
                            if i < j:  # Avoid duplicates
                                edges.append((i, j))

            # Convert to GPU arrays
            edges_array = np.array(edges, dtype=np.int32)
            edges_gpu = cp.asarray(edges_array)

            # Create sparse matrix representation
            row = edges_gpu[:, 0]
            col = edges_gpu[:, 1]
            data = cp.ones(len(edges), dtype=cp.float32)

            self.adjacency_data = (row, col, data)

            build_time = (time.perf_counter() - start_time) * 1000
            logger.info(
                f"Built lattice on GPU: {self.n_points} vertices, {len(edges)} edges in {build_time:.2f}ms"
            )

            return self.adjacency_data

    def xor_transform(self, data: np.ndarray, key: Optional[np.ndarray] = None) -> np.ndarray:
        """Apply XOR transformation using CuPy"""
        with self.device:
            # Transfer to GPU
            data_gpu = cp.asarray(data, dtype=cp.uint8)

            # Generate or use key
            if key is None:
                key_gpu = cp.random.randint(0, 256, size=len(data), dtype=cp.uint8)
            else:
                key_gpu = cp.asarray(key, dtype=cp.uint8)

            # Perform XOR on GPU
            with self.stream:
                result_gpu = cp.bitwise_xor(data_gpu, key_gpu)
                self.stream.synchronize()

            # Transfer back to CPU
            return cp.asnumpy(result_gpu)

    def find_shortest_path(self, start: int, end: int) -> Tuple[List[int], float]:
        """Find shortest path using GPU-accelerated BFS"""
        if self.adjacency_data is None:
            self.build_lattice()

        start_time = time.perf_counter()

        with self.device:
            row, col, _ = self.adjacency_data

            # Initialize arrays on GPU
            distances = cp.full(self.n_points, cp.inf, dtype=cp.float32)
            distances[start] = 0
            parents = cp.full(self.n_points, -1, dtype=cp.int32)
            visited = cp.zeros(self.n_points, dtype=cp.bool_)

            # BFS implementation
            queue = cp.array([start], dtype=cp.int32)
            visited[start] = True

            while len(queue) > 0:
                current = int(queue[0])
                queue = queue[1:]

                if current == end:
                    break

                # Find neighbors in parallel
                mask1 = row == current
                mask2 = col == current
                neighbors = cp.concatenate([col[mask1], row[mask2]])

                # Update unvisited neighbors
                for neighbor in neighbors:
                    neighbor_idx = int(neighbor)
                    if not visited[neighbor_idx]:
                        visited[neighbor_idx] = True
                        distances[neighbor_idx] = distances[current] + 1
                        parents[neighbor_idx] = current
                        queue = cp.append(queue, neighbor_idx)

            # Reconstruct path
            path = []
            current = end
            while current != -1:
                path.append(int(current))
                current = int(parents[current])
            path.reverse()

            exec_time = (time.perf_counter() - start_time) * 1000
            return path, exec_time

    def matrix_multiply(self, A: np.ndarray, B: np.ndarray) -> np.ndarray:
        """GPU-accelerated matrix multiplication"""
        with self.device:
            A_gpu = cp.asarray(A, dtype=cp.float32)
            B_gpu = cp.asarray(B, dtype=cp.float32)

            with self.stream:
                C_gpu = cp.matmul(A_gpu, B_gpu)
                self.stream.synchronize()

            return cp.asnumpy(C_gpu)

    def parallel_reduce(self, data: np.ndarray, operation: str = "sum") -> float:
        """Parallel reduction using CuPy"""
        with self.device:
            data_gpu = cp.asarray(data, dtype=cp.float32)

            with self.stream:
                if operation == "sum":
                    result = cp.sum(data_gpu)
                elif operation == "max":
                    result = cp.max(data_gpu)
                elif operation == "min":
                    result = cp.min(data_gpu)
                else:
                    raise ValueError(f"Unsupported operation: {operation}")

                self.stream.synchronize()

            return float(result)
