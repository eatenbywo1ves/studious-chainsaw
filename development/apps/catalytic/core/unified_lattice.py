"""
Unified Catalytic Lattice implementation
Combines GPU acceleration with graph algorithms
"""

import time
import logging
from typing import Tuple, List, Optional, Dict, Any, Union
import numpy as np

try:
    import igraph as ig
    IGRAPH_AVAILABLE = True
except ImportError:
    IGRAPH_AVAILABLE = False
    ig = None

from .interface import BaseLatticeComputer, LatticeMetrics, IPathFinder, ITransformer, IAnalyzer
from ..gpu.factory import GPUFactory
from ..gpu.base import BaseLatticeGPU
from libs.config import get_settings, GPUBackend
from libs.utils.exceptions import LatticeException, PathNotFoundException

logger = logging.getLogger(__name__)


class UnifiedCatalyticLattice(BaseLatticeComputer, IPathFinder, ITransformer, IAnalyzer):
    """
    Unified implementation that combines GPU acceleration with graph algorithms
    Automatically selects the best backend based on availability
    """

    def __init__(
        self,
        dimensions: int,
        size: int,
        backend: Optional[GPUBackend] = None,
        aux_memory_size: int = 1000,
        enable_gpu: bool = True
    ):
        """
        Initialize unified catalytic lattice

        Args:
            dimensions: Number of dimensions
            size: Size in each dimension
            backend: Specific GPU backend to use
            aux_memory_size: Size of auxiliary memory
            enable_gpu: Enable GPU acceleration
        """
        super().__init__(dimensions, size)

        self.config = get_settings()
        self.aux_memory_size = aux_memory_size
        self.enable_gpu = enable_gpu

        # Initialize GPU backend if enabled
        self.gpu_backend: Optional[BaseLatticeGPU] = None
        if enable_gpu:
            try:
                self.gpu_backend = GPUFactory.create(
                    dimensions=dimensions,
                    size=size,
                    backend=backend
                )
                logger.info(f"Using GPU backend: {self.gpu_backend.__class__.__name__}")
            except Exception as e:
                logger.warning(f"GPU initialization failed: {e}, using CPU fallback")
                self.gpu_backend = None

        # Initialize graph structure (for advanced algorithms)
        self.graph: Optional[ig.Graph] = None if IGRAPH_AVAILABLE else None
        self.auxiliary_memory = np.zeros(aux_memory_size, dtype=np.float32)

        # Cache for computed results
        self._path_cache: Dict[Tuple[int, int], Tuple[List[int], float]] = {}
        self._metrics_cache: Optional[LatticeMetrics] = None

    def build_lattice(self) -> Union[ig.Graph, Dict]:
        """Build the lattice structure"""
        start_time = time.perf_counter()

        # Build on GPU if available
        if self.gpu_backend:
            self.gpu_backend.build_lattice()

        # Build graph structure for advanced operations
        if IGRAPH_AVAILABLE:
            self.graph = ig.Graph()
            self.graph.add_vertices(self.n_points)

            edges = []
            for i in range(self.n_points):
                neighbors = self.get_neighbors(i)
                for j in neighbors:
                    if i < j:  # Avoid duplicates
                        edges.append((i, j))

            self.graph.add_edges(edges)

            # Add vertex attributes
            for i in range(self.n_points):
                coords = self.index_to_coords(i)
                self.graph.vs[i]["coords"] = coords.tolist()

            build_time = (time.perf_counter() - start_time) * 1000
            logger.info(f"Built unified lattice: {self.n_points} vertices, {len(edges)} edges in {build_time:.2f}ms")

            return self.graph
        else:
            # Fallback to dictionary representation
            adjacency = {}
            for i in range(self.n_points):
                adjacency[i] = self.get_neighbors(i)

            build_time = (time.perf_counter() - start_time) * 1000
            logger.info(f"Built lattice (dict): {self.n_points} vertices in {build_time:.2f}ms")

            return adjacency

    def find_shortest_path(self, start: int, end: int) -> Tuple[List[int], float]:
        """Find shortest path using best available method"""
        # Check cache
        cache_key = (start, end)
        if cache_key in self._path_cache:
            return self._path_cache[cache_key]

        start_time = time.perf_counter()

        # Use GPU if available
        if self.gpu_backend:
            path, exec_time = self.gpu_backend.find_shortest_path(start, end)
        # Use igraph if available
        elif self.graph:
            paths = self.graph.get_shortest_paths(start, to=end, mode='all')
            path = paths[0] if paths else []
            exec_time = (time.perf_counter() - start_time) * 1000
        else:
            # Fallback to basic BFS
            path = self._bfs_path(start, end)
            exec_time = (time.perf_counter() - start_time) * 1000

        if not path:
            raise PathNotFoundException(start, end)

        result = (path, exec_time)
        self._path_cache[cache_key] = result
        return result

    def find_all_paths(
        self,
        start: int,
        end: int,
        max_length: Optional[int] = None
    ) -> List[List[int]]:
        """Find all paths between two vertices"""
        if not self.graph:
            raise LatticeException("Graph structure not available for all paths search")

        if max_length is None:
            max_length = self.n_points

        all_paths = []
        for length in range(1, min(max_length + 1, self.n_points)):
            paths = self.graph.get_all_simple_paths(start, to=end, cutoff=length)
            all_paths.extend(paths)

        return all_paths

    def find_path_catalytic(
        self,
        start: int,
        end: int,
        auxiliary_memory: Optional[np.ndarray] = None
    ) -> Tuple[List[int], float]:
        """Catalytic path finding with auxiliary memory"""
        if auxiliary_memory is None:
            auxiliary_memory = self.auxiliary_memory

        # Use auxiliary memory to guide search
        # This is a simplified version of catalytic computing
        start_coords = self.index_to_coords(start)
        end_coords = self.index_to_coords(end)

        # Calculate heuristic distance
        heuristic = np.linalg.norm(end_coords - start_coords)

        # Store heuristic in auxiliary memory
        aux_index = hash((start, end)) % len(auxiliary_memory)
        auxiliary_memory[aux_index] = heuristic

        # Find path with heuristic guidance
        path, exec_time = self.find_shortest_path(start, end)

        # Update auxiliary memory with result
        auxiliary_memory[aux_index] = len(path)

        return path, exec_time

    def xor_transform(
        self,
        data: np.ndarray,
        key: Optional[np.ndarray] = None
    ) -> np.ndarray:
        """Apply XOR transformation"""
        if self.gpu_backend:
            return self.gpu_backend.xor_transform(data, key)

        # CPU fallback
        data_uint = data.astype(np.uint8)
        if key is None:
            key = np.random.randint(0, 256, size=len(data), dtype=np.uint8)
        else:
            key = key.astype(np.uint8)

        return np.bitwise_xor(data_uint, key)

    def apply_transformation(
        self,
        data: np.ndarray,
        transformation: str,
        **kwargs
    ) -> np.ndarray:
        """Apply named transformation"""
        if transformation == "xor":
            return self.xor_transform(data, kwargs.get('key'))
        elif transformation == "normalize":
            return (data - np.mean(data)) / (np.std(data) + 1e-8)
        elif transformation == "scale":
            factor = kwargs.get('factor', 1.0)
            return data * factor
        else:
            raise ValueError(f"Unknown transformation: {transformation}")

    def analyze_structure(self) -> Dict[str, Any]:
        """Analyze lattice structure"""
        if not self.graph:
            return {
                'vertices': self.n_points,
                'dimensions': self.dimensions,
                'size': self.size
            }

        return {
            'vertices': self.graph.vcount(),
            'edges': self.graph.ecount(),
            'dimensions': self.dimensions,
            'size': self.size,
            'is_connected': self.graph.is_connected(),
            'diameter': self.graph.diameter() if self.graph.is_connected() else -1,
            'avg_degree': np.mean(self.graph.degree()),
            'clustering_coefficient': self.graph.transitivity_avglocal_undirected(),
            'density': self.graph.density()
        }

    def find_communities(self, method: str = "modularity") -> List[List[int]]:
        """Find communities in the lattice"""
        if not self.graph:
            raise LatticeException("Graph structure required for community detection")

        if method == "modularity":
            communities = self.graph.community_multilevel()
        elif method == "edge_betweenness":
            communities = self.graph.community_edge_betweenness()
        elif method == "label_propagation":
            communities = self.graph.community_label_propagation()
        else:
            raise ValueError(f"Unknown community detection method: {method}")

        # Convert to list of lists
        community_list = [[] for _ in range(max(communities.membership) + 1)]
        for vertex, comm_id in enumerate(communities.membership):
            community_list[comm_id].append(vertex)

        return community_list

    def calculate_centrality(self, method: str = "betweenness") -> np.ndarray:
        """Calculate vertex centrality"""
        if not self.graph:
            # Simple degree-based centrality for non-graph
            centrality = np.zeros(self.n_points)
            for i in range(self.n_points):
                centrality[i] = len(self.get_neighbors(i))
            return centrality / np.max(centrality)

        if method == "betweenness":
            centrality = self.graph.betweenness()
        elif method == "closeness":
            centrality = self.graph.closeness()
        elif method == "degree":
            centrality = self.graph.degree()
        elif method == "eigenvector":
            centrality = self.graph.eigenvector_centrality()
        else:
            raise ValueError(f"Unknown centrality method: {method}")

        return np.array(centrality)

    def get_adjacency_matrix(self, dense: bool = False) -> Any:
        """Get adjacency matrix"""
        if self.graph:
            matrix = self.graph.get_adjacency_sparse() if not dense else self.graph.get_adjacency()
            return matrix
        else:
            # Build sparse representation
            from scipy.sparse import lil_matrix
            matrix = lil_matrix((self.n_points, self.n_points))

            for i in range(self.n_points):
                for j in self.get_neighbors(i):
                    matrix[i, j] = 1

            return matrix.tocsr() if not dense else matrix.toarray()

    def get_metrics(self) -> LatticeMetrics:
        """Get comprehensive lattice metrics"""
        if self._metrics_cache:
            return self._metrics_cache

        analysis = self.analyze_structure()
        memory_usage = self.estimate_memory_usage()

        # Calculate traditional memory for comparison
        traditional_memory = (self.n_points * self.n_points * 8) / (1024 ** 2)

        metrics = LatticeMetrics(
            vertices=self.n_points,
            edges=analysis.get('edges', self.n_points * self.dimensions),
            dimensions=self.dimensions,
            size=self.size,
            memory_usage_mb=memory_usage['total_mb'],
            memory_reduction_factor=self.calculate_memory_reduction(traditional_memory),
            avg_degree=analysis.get('avg_degree', 2 * self.dimensions),
            diameter=analysis.get('diameter'),
            clustering_coefficient=analysis.get('clustering_coefficient'),
            is_connected=analysis.get('is_connected', True)
        )

        self._metrics_cache = metrics
        return metrics

    def estimate_memory_usage(self) -> Dict[str, float]:
        """Estimate memory usage"""
        memory = {}

        # GPU memory if applicable
        if self.gpu_backend:
            gpu_memory = self.gpu_backend.estimate_memory_usage()
            memory.update({f"gpu_{k}": v for k, v in gpu_memory.items()})

        # Graph memory
        if self.graph:
            # Rough estimate: edges * 2 * 4 bytes + vertices * 4 bytes
            graph_mb = (self.graph.ecount() * 8 + self.graph.vcount() * 4) / (1024 ** 2)
            memory['graph_mb'] = round(graph_mb, 2)

        # Auxiliary memory
        memory['auxiliary_mb'] = (self.auxiliary_memory.nbytes) / (1024 ** 2)

        # Cache memory
        cache_entries = len(self._path_cache)
        memory['cache_mb'] = round(cache_entries * 0.001, 2)  # Rough estimate

        memory['total_mb'] = round(sum(v for k, v in memory.items() if 'total' not in k), 2)

        return memory

    def _bfs_path(self, start: int, end: int) -> List[int]:
        """Basic BFS implementation for fallback"""
        if start == end:
            return [start]

        visited = set()
        queue = [(start, [start])]

        while queue:
            vertex, path = queue.pop(0)

            if vertex in visited:
                continue

            visited.add(vertex)

            for neighbor in self.get_neighbors(vertex):
                if neighbor == end:
                    return path + [neighbor]

                if neighbor not in visited:
                    queue.append((neighbor, path + [neighbor]))

        return []  # No path found

    def cleanup(self):
        """Clean up resources"""
        if self.gpu_backend:
            self.gpu_backend.free_memory()

        self._path_cache.clear()
        self._metrics_cache = None
        self.graph = None
        self.auxiliary_memory = None

        super().cleanup()