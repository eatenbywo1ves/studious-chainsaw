"""
Common interfaces for Catalytic Lattice Computing
Defines protocols that all implementations must follow
"""

from typing import Protocol, Tuple, List, Optional, Dict, Any, Union
from dataclasses import dataclass
import numpy as np
from abc import ABC, abstractmethod


@dataclass
class LatticeMetrics:
    """Metrics for lattice performance and structure"""
    vertices: int
    edges: int
    dimensions: int
    size: int
    memory_usage_mb: float
    memory_reduction_factor: float
    avg_degree: float
    diameter: Optional[int] = None
    clustering_coefficient: Optional[float] = None
    is_connected: bool = True


class ILatticeComputer(Protocol):
    """
    Protocol for lattice computing implementations
    All lattice implementations should follow this interface
    """

    dimensions: int
    size: int
    n_points: int

    def build_lattice(self) -> Any:
        """Build the lattice structure"""
        ...

    def get_metrics(self) -> LatticeMetrics:
        """Get lattice metrics and statistics"""
        ...

    def estimate_memory_usage(self) -> Dict[str, float]:
        """Estimate memory usage"""
        ...

    def cleanup(self) -> None:
        """Cleanup resources"""
        ...


class IPathFinder(Protocol):
    """Protocol for path finding operations"""

    def find_shortest_path(self, start: int, end: int) -> Tuple[List[int], float]:
        """
        Find shortest path between two vertices

        Args:
            start: Start vertex index
            end: End vertex index

        Returns:
            Tuple of (path, execution_time_ms)
        """
        ...

    def find_all_paths(
        self,
        start: int,
        end: int,
        max_length: Optional[int] = None
    ) -> List[List[int]]:
        """
        Find all paths between two vertices

        Args:
            start: Start vertex index
            end: End vertex index
            max_length: Maximum path length to consider

        Returns:
            List of paths
        """
        ...

    def find_path_catalytic(
        self,
        start: int,
        end: int,
        auxiliary_memory: Optional[np.ndarray] = None
    ) -> Tuple[List[int], float]:
        """
        Find path using catalytic algorithm

        Args:
            start: Start vertex index
            end: End vertex index
            auxiliary_memory: Auxiliary memory for catalytic computation

        Returns:
            Tuple of (path, distance)
        """
        ...


class ITransformer(Protocol):
    """Protocol for data transformation operations"""

    def xor_transform(
        self,
        data: np.ndarray,
        key: Optional[np.ndarray] = None
    ) -> np.ndarray:
        """
        Apply XOR transformation

        Args:
            data: Input data
            key: XOR key (generated if None)

        Returns:
            Transformed data
        """
        ...

    def apply_transformation(
        self,
        data: np.ndarray,
        transformation: str,
        **kwargs
    ) -> np.ndarray:
        """
        Apply a named transformation

        Args:
            data: Input data
            transformation: Transformation name
            **kwargs: Transformation parameters

        Returns:
            Transformed data
        """
        ...


class IAnalyzer(Protocol):
    """Protocol for lattice analysis operations"""

    def analyze_structure(self) -> Dict[str, Any]:
        """
        Analyze lattice structure

        Returns:
            Dictionary with structural properties
        """
        ...

    def find_communities(self, method: str = "modularity") -> List[List[int]]:
        """
        Find communities in the lattice

        Args:
            method: Community detection method

        Returns:
            List of communities (each community is a list of vertex indices)
        """
        ...

    def calculate_centrality(
        self,
        method: str = "betweenness"
    ) -> np.ndarray:
        """
        Calculate vertex centrality

        Args:
            method: Centrality measure (betweenness, closeness, degree)

        Returns:
            Array of centrality values
        """
        ...

    def get_adjacency_matrix(self, dense: bool = False) -> Any:
        """
        Get adjacency matrix

        Args:
            dense: Return dense matrix if True, sparse otherwise

        Returns:
            Adjacency matrix
        """
        ...


class BaseLatticeComputer(ABC):
    """
    Abstract base class implementing common lattice operations
    Provides shared functionality for all lattice implementations
    """

    def __init__(self, dimensions: int, size: int):
        """
        Initialize base lattice computer

        Args:
            dimensions: Number of dimensions
            size: Size in each dimension
        """
        self.dimensions = dimensions
        self.size = size
        self.n_points = size ** dimensions
        self._metrics: Optional[LatticeMetrics] = None

    @abstractmethod
    def build_lattice(self) -> Any:
        """Build the lattice structure"""
        pass

    def index_to_coords(self, index: int) -> np.ndarray:
        """Convert linear index to multidimensional coordinates"""
        coords = np.zeros(self.dimensions, dtype=int)
        for i in range(self.dimensions - 1, -1, -1):
            coords[i] = index % self.size
            index //= self.size
        return coords

    def coords_to_index(self, coords: Union[np.ndarray, List[int]]) -> int:
        """Convert multidimensional coordinates to linear index"""
        index = 0
        for i in range(self.dimensions):
            index = index * self.size + coords[i]
        return index

    def validate_coords(self, coords: Union[np.ndarray, List[int]]) -> bool:
        """Validate coordinates are within bounds"""
        coords_array = np.asarray(coords)
        return (
            len(coords_array) == self.dimensions and
            np.all(coords_array >= 0) and
            np.all(coords_array < self.size)
        )

    def get_neighbors(self, index: int) -> List[int]:
        """Get neighbor indices for a vertex"""
        coords = self.index_to_coords(index)
        neighbors = []

        for dim in range(self.dimensions):
            for delta in [-1, 1]:
                neighbor_coords = coords.copy()
                neighbor_coords[dim] += delta

                if 0 <= neighbor_coords[dim] < self.size:
                    neighbor_idx = self.coords_to_index(neighbor_coords)
                    neighbors.append(neighbor_idx)

        return neighbors

    def calculate_memory_reduction(self, traditional_memory_mb: float) -> float:
        """
        Calculate memory reduction factor

        Args:
            traditional_memory_mb: Memory used by traditional approach

        Returns:
            Reduction factor
        """
        current_memory = self.estimate_memory_usage()
        current_total = current_memory.get('total_mb', 1.0)

        if current_total > 0:
            return traditional_memory_mb / current_total
        return 1.0

    @abstractmethod
    def get_metrics(self) -> LatticeMetrics:
        """Get lattice metrics"""
        pass

    @abstractmethod
    def estimate_memory_usage(self) -> Dict[str, float]:
        """Estimate memory usage"""
        pass

    def cleanup(self) -> None:
        """Default cleanup (can be overridden)"""
        self._metrics = None

    def __repr__(self) -> str:
        """String representation"""
        return f"{self.__class__.__name__}(dimensions={self.dimensions}, size={self.size}, vertices={self.n_points})"

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.cleanup()
