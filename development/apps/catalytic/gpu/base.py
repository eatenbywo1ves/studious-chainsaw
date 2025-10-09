"""
Base GPU abstraction for Catalytic Lattice Computing
Defines the interface that all GPU implementations must follow
"""

from abc import ABC, abstractmethod
from typing import Tuple, List, Optional, Dict, Any
from dataclasses import dataclass
import numpy as np

from libs.config import get_settings


@dataclass
class GPUCapabilities:
    """GPU device capabilities"""

    device_name: str
    device_id: int
    total_memory_mb: float
    available_memory_mb: float
    compute_capability: Optional[Tuple[int, int]] = None
    max_threads_per_block: int = 1024
    max_blocks: int = 65535
    warp_size: int = 32
    supports_double_precision: bool = True
    supports_tensor_cores: bool = False
    driver_version: Optional[str] = None
    backend_name: str = "unknown"


class BaseLatticeGPU(ABC):
    """
    Abstract base class for GPU-accelerated lattice operations
    All GPU implementations must inherit from this class
    """

    def __init__(self, dimensions: int, size: int, device_id: int = 0):
        """
        Initialize GPU lattice

        Args:
            dimensions: Number of dimensions for the lattice
            size: Size in each dimension
            device_id: GPU device ID to use
        """
        self.dimensions = dimensions
        self.size = size
        self.device_id = device_id
        self.n_points = size**dimensions

        # Get configuration
        self.config = get_settings()

        # Validate parameters
        self._validate_parameters()

        # Device capabilities (to be set by implementation)
        self._capabilities: Optional[GPUCapabilities] = None

        # Lattice data structures
        self.adjacency_data = None
        self.auxiliary_memory = None

    def _validate_parameters(self):
        """Validate initialization parameters"""
        if self.dimensions < self.config.lattice.min_dimensions:
            raise ValueError(f"Dimensions must be >= {self.config.lattice.min_dimensions}")
        if self.dimensions > self.config.lattice.max_dimensions:
            raise ValueError(f"Dimensions must be <= {self.config.lattice.max_dimensions}")
        if self.size < self.config.lattice.min_lattice_size:
            raise ValueError(f"Size must be >= {self.config.lattice.min_lattice_size}")
        if self.size > self.config.lattice.max_lattice_size:
            raise ValueError(f"Size must be <= {self.config.lattice.max_lattice_size}")

    @abstractmethod
    def initialize_device(self) -> bool:
        """
        Initialize GPU device and check availability

        Returns:
            bool: True if initialization successful
        """
        pass

    @abstractmethod
    def get_device_capabilities(self) -> GPUCapabilities:
        """
        Get device capabilities

        Returns:
            GPUCapabilities: Device information and limits
        """
        pass

    @abstractmethod
    def build_lattice(self) -> Any:
        """
        Build the lattice structure on GPU

        Returns:
            Lattice adjacency structure (implementation specific)
        """
        pass

    @abstractmethod
    def allocate_memory(self, size_mb: float) -> bool:
        """
        Allocate GPU memory

        Args:
            size_mb: Size in megabytes to allocate

        Returns:
            bool: True if allocation successful
        """
        pass

    @abstractmethod
    def free_memory(self):
        """Free allocated GPU memory"""
        pass

    @abstractmethod
    def transfer_to_device(self, data: np.ndarray) -> Any:
        """
        Transfer data to GPU

        Args:
            data: NumPy array to transfer

        Returns:
            GPU array (implementation specific)
        """
        pass

    @abstractmethod
    def transfer_from_device(self, gpu_data: Any) -> np.ndarray:
        """
        Transfer data from GPU to CPU

        Args:
            gpu_data: GPU array to transfer

        Returns:
            NumPy array
        """
        pass

    @abstractmethod
    def xor_transform(self, data: np.ndarray, key: Optional[np.ndarray] = None) -> np.ndarray:
        """
        Apply XOR transformation using GPU

        Args:
            data: Input data
            key: XOR key (generated if None)

        Returns:
            Transformed data
        """
        pass

    @abstractmethod
    def find_shortest_path(self, start: int, end: int) -> Tuple[List[int], float]:
        """
        Find shortest path using GPU acceleration

        Args:
            start: Start vertex index
            end: End vertex index

        Returns:
            Tuple of (path, execution_time_ms)
        """
        pass

    @abstractmethod
    def matrix_multiply(self, A: np.ndarray, B: np.ndarray) -> np.ndarray:
        """
        GPU-accelerated matrix multiplication

        Args:
            A: First matrix
            B: Second matrix

        Returns:
            Result matrix
        """
        pass

    @abstractmethod
    def parallel_reduce(self, data: np.ndarray, operation: str = "sum") -> float:
        """
        Parallel reduction operation

        Args:
            data: Input data
            operation: Reduction operation (sum, max, min)

        Returns:
            Reduced value
        """
        pass

    def index_to_coords(self, index: int) -> np.ndarray:
        """
        Convert linear index to multidimensional coordinates

        Args:
            index: Linear index

        Returns:
            Coordinate array
        """
        coords = np.zeros(self.dimensions, dtype=int)
        for i in range(self.dimensions - 1, -1, -1):
            coords[i] = index % self.size
            index //= self.size
        return coords

    def coords_to_index(self, coords: np.ndarray) -> int:
        """
        Convert multidimensional coordinates to linear index

        Args:
            coords: Coordinate array

        Returns:
            Linear index
        """
        index = 0
        for i in range(self.dimensions):
            index = index * self.size + coords[i]
        return index

    def get_neighbors(self, index: int) -> List[int]:
        """
        Get neighbor indices for a given vertex

        Args:
            index: Vertex index

        Returns:
            List of neighbor indices
        """
        coords = self.index_to_coords(index)
        neighbors = []

        for dim in range(self.dimensions):
            for delta in [-1, 1]:
                neighbor_coords = coords.copy()
                neighbor_coords[dim] += delta

                # Check bounds
                if 0 <= neighbor_coords[dim] < self.size:
                    neighbor_idx = self.coords_to_index(neighbor_coords)
                    neighbors.append(neighbor_idx)

        return neighbors

    def estimate_memory_usage(self) -> Dict[str, float]:
        """
        Estimate memory usage for the lattice

        Returns:
            Dictionary with memory usage details in MB
        """
        # Adjacency matrix (sparse)
        num_edges = self.n_points * self.dimensions * 2  # Approximate
        adjacency_mb = (num_edges * 8 * 2) / (1024 * 1024)  # row, col indices

        # Auxiliary memory
        aux_mb = self.config.lattice.default_aux_memory_mb

        # Working memory (for algorithms)
        working_mb = (self.n_points * 8 * 3) / (1024 * 1024)  # distances, parents, visited

        return {
            "adjacency_mb": round(adjacency_mb, 2),
            "auxiliary_mb": round(aux_mb, 2),
            "working_mb": round(working_mb, 2),
            "total_mb": round(adjacency_mb + aux_mb + working_mb, 2),
        }

    def benchmark(self) -> Dict[str, Any]:
        """
        Run benchmark tests on the GPU implementation

        Returns:
            Dictionary with benchmark results
        """
        results = {}

        # Test matrix multiplication
        try:
            size = min(1000, self.n_points)
            A = np.random.randn(size, size).astype(np.float32)
            B = np.random.randn(size, size).astype(np.float32)

            import time

            start = time.perf_counter()
            _ = self.matrix_multiply(A, B)
            gpu_time = (time.perf_counter() - start) * 1000

            start = time.perf_counter()
            _ = np.dot(A, B)
            cpu_time = (time.perf_counter() - start) * 1000

            results["matrix_multiply"] = {
                "gpu_ms": round(gpu_time, 2),
                "cpu_ms": round(cpu_time, 2),
                "speedup": round(cpu_time / gpu_time, 2),
            }
        except Exception as e:
            results["matrix_multiply"] = {"error": str(e)}

        # Test XOR transform
        try:
            data = np.random.randint(0, 256, 100000, dtype=np.uint8)

            import time

            start = time.perf_counter()
            _ = self.xor_transform(data)
            gpu_time = (time.perf_counter() - start) * 1000

            results["xor_transform"] = {"gpu_ms": round(gpu_time, 2), "data_size": len(data)}
        except Exception as e:
            results["xor_transform"] = {"error": str(e)}

        return results

    def __enter__(self):
        """Context manager entry"""
        self.initialize_device()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup resources"""
        self.free_memory()

    def __repr__(self) -> str:
        """String representation"""
        return f"{self.__class__.__name__}(dimensions={self.dimensions}, size={self.size}, device={self.device_id})"
