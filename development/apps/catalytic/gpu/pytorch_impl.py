"""
PyTorch implementation of GPU-accelerated lattice operations
"""

import time
import logging
from typing import Tuple, List, Optional
import numpy as np

try:
    import torch
    PYTORCH_AVAILABLE = True
except ImportError:
    PYTORCH_AVAILABLE = False
    torch = None

from .base import BaseLatticeGPU, GPUCapabilities
from libs.utils.exceptions import GPUNotAvailableError, GPUMemoryError

logger = logging.getLogger(__name__)


class PyTorchLatticeGPU(BaseLatticeGPU):
    """PyTorch-based GPU implementation for lattice operations"""

    def __init__(self, dimensions: int, size: int, device_id: int = 0):
        """Initialize PyTorch lattice GPU"""
        if not PYTORCH_AVAILABLE:
            raise GPUNotAvailableError("PyTorch is not installed")

        super().__init__(dimensions, size, device_id)
        self.device = None

    def initialize_device(self) -> bool:
        """Initialize PyTorch device"""
        try:
            if not torch.cuda.is_available():
                raise GPUNotAvailableError("CUDA not available in PyTorch")

            # Check if device exists
            device_count = torch.cuda.device_count()
            if self.device_id >= device_count:
                raise GPUNotAvailableError(f"Device {self.device_id} not found")

            # Set device
            self.device = torch.device(f'cuda:{self.device_id}')
            torch.cuda.set_device(self.device)

            # Get capabilities
            self._capabilities = self.get_device_capabilities()

            # Allocate auxiliary memory
            aux_size_mb = self.config.lattice.default_aux_memory_mb
            if not self.allocate_memory(aux_size_mb):
                raise GPUMemoryError(aux_size_mb, self._capabilities.available_memory_mb)

            logger.info(f"Initialized PyTorch device {self.device_id}: {self._capabilities.device_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize PyTorch device: {e}")
            return False

    def get_device_capabilities(self) -> GPUCapabilities:
        """Get PyTorch device capabilities"""
        props = torch.cuda.get_device_properties(self.device_id)
        mem_info = torch.cuda.mem_get_info(self.device_id)

        return GPUCapabilities(
            device_name=props.name,
            device_id=self.device_id,
            total_memory_mb=props.total_memory / (1024 ** 2),
            available_memory_mb=mem_info[0] / (1024 ** 2),
            compute_capability=(props.major, props.minor),
            max_threads_per_block=props.max_threads_per_block,
            max_blocks=props.max_threads_per_multiprocessor,
            warp_size=props.warp_size,
            supports_double_precision=True,
            supports_tensor_cores=props.major >= 7,
            backend_name="pytorch"
        )

    def allocate_memory(self, size_mb: float) -> bool:
        """Allocate GPU memory"""
        try:
            size_elements = int(size_mb * 1024 * 1024 / 4)  # float32 elements
            self.auxiliary_memory = torch.zeros(
                size_elements,
                dtype=torch.float32,
                device=self.device
            )
            logger.debug(f"Allocated {size_mb:.2f} MB auxiliary memory")
            return True
        except torch.cuda.OutOfMemoryError:
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

            # Clear cache
            torch.cuda.empty_cache()
            logger.debug("Freed GPU memory")
        except Exception as e:
            logger.warning(f"Error freeing GPU memory: {e}")

    def transfer_to_device(self, data: np.ndarray) -> torch.Tensor:
        """Transfer data to GPU"""
        return torch.from_numpy(data).to(self.device)

    def transfer_from_device(self, gpu_data: torch.Tensor) -> np.ndarray:
        """Transfer data from GPU to CPU"""
        return gpu_data.cpu().numpy()

    def build_lattice(self) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """Build lattice structure on GPU"""
        start_time = time.perf_counter()

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

        # Convert to PyTorch tensors on GPU
        edges_array = np.array(edges, dtype=np.int32)
        edges_tensor = torch.from_numpy(edges_array).to(self.device)

        # Create sparse tensor representation
        row = edges_tensor[:, 0]
        col = edges_tensor[:, 1]
        data = torch.ones(len(edges), dtype=torch.float32, device=self.device)

        self.adjacency_data = (row, col, data)

        build_time = (time.perf_counter() - start_time) * 1000
        logger.info(f"Built lattice on GPU: {self.n_points} vertices, {len(edges)} edges in {build_time:.2f}ms")

        return self.adjacency_data

    def xor_transform(self, data: np.ndarray, key: Optional[np.ndarray] = None) -> np.ndarray:
        """Apply XOR transformation using PyTorch"""
        # Convert to uint8 tensors
        data_tensor = torch.from_numpy(data.astype(np.uint8)).to(self.device)

        if key is None:
            key_tensor = torch.randint(0, 256, data_tensor.shape, dtype=torch.uint8, device=self.device)
        else:
            key_tensor = torch.from_numpy(key.astype(np.uint8)).to(self.device)

        # Perform XOR on GPU
        result_tensor = torch.bitwise_xor(data_tensor, key_tensor)

        # Transfer back to CPU
        return result_tensor.cpu().numpy()

    def find_shortest_path(self, start: int, end: int) -> Tuple[List[int], float]:
        """Find shortest path using GPU-accelerated BFS"""
        if self.adjacency_data is None:
            self.build_lattice()

        start_time = time.perf_counter()

        row, col, _ = self.adjacency_data

        # Initialize tensors on GPU
        distances = torch.full((self.n_points,), float('inf'), dtype=torch.float32, device=self.device)
        distances[start] = 0
        parents = torch.full((self.n_points,), -1, dtype=torch.int32, device=self.device)
        visited = torch.zeros(self.n_points, dtype=torch.bool, device=self.device)

        # BFS implementation
        queue = [start]
        visited[start] = True

        while queue:
            current = queue.pop(0)

            if current == end:
                break

            # Find neighbors
            mask1 = row == current
            mask2 = col == current
            neighbors = torch.cat([col[mask1], row[mask2]])

            # Update unvisited neighbors
            for neighbor in neighbors:
                neighbor_idx = int(neighbor)
                if not visited[neighbor_idx]:
                    visited[neighbor_idx] = True
                    distances[neighbor_idx] = distances[current] + 1
                    parents[neighbor_idx] = current
                    queue.append(neighbor_idx)

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
        A_tensor = torch.from_numpy(A.astype(np.float32)).to(self.device)
        B_tensor = torch.from_numpy(B.astype(np.float32)).to(self.device)

        C_tensor = torch.matmul(A_tensor, B_tensor)

        return C_tensor.cpu().numpy()

    def parallel_reduce(self, data: np.ndarray, operation: str = "sum") -> float:
        """Parallel reduction using PyTorch"""
        data_tensor = torch.from_numpy(data.astype(np.float32)).to(self.device)

        if operation == "sum":
            result = torch.sum(data_tensor)
        elif operation == "max":
            result = torch.max(data_tensor)
        elif operation == "min":
            result = torch.min(data_tensor)
        else:
            raise ValueError(f"Unsupported operation: {operation}")

        return float(result.cpu())
