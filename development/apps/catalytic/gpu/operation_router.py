"""
Smart Operation Router for GPU/CPU Selection
Automatically routes operations based on size, type, and performance characteristics
"""

import logging
from typing import Optional, Dict, Any
from enum import Enum
from dataclasses import dataclass
import numpy as np

from libs.config import get_settings

logger = logging.getLogger(__name__)


class OperationType(Enum):
    """Classification of operation types"""

    MATRIX_MULTIPLY = "matrix_multiply"
    MATRIX_ADD = "matrix_add"
    ELEMENT_WISE = "element_wise"
    REDUCTION = "reduction"
    TRANSFORM = "transform"
    GRAPH_ALGORITHM = "graph_algorithm"
    RANDOM_GENERATION = "random_generation"
    LATTICE_CREATION = "lattice_creation"
    PATH_FINDING = "path_finding"
    UNKNOWN = "unknown"


class DevicePreference(Enum):
    """Device routing decision"""

    GPU_OPTIMAL = "gpu_optimal"  # GPU is clearly better
    GPU_ACCEPTABLE = "gpu_acceptable"  # GPU is okay
    CPU_OPTIMAL = "cpu_optimal"  # CPU is clearly better
    CPU_ACCEPTABLE = "cpu_acceptable"  # CPU is okay
    NO_PREFERENCE = "no_preference"  # Either works


@dataclass
class OperationCharacteristics:
    """Characteristics of an operation for routing decisions"""

    operation_type: OperationType
    element_count: int
    is_parallelizable: bool
    has_dependencies: bool
    memory_estimate_mb: float
    is_io_bound: bool = False
    custom_preference: Optional[DevicePreference] = None


class OperationAnalyzer:
    """
    Analyzes operations and determines optimal execution device (GPU/CPU)
    """

    # Default thresholds (can be overridden via config)
    DEFAULT_GPU_THRESHOLD = 1000  # Elements below this prefer CPU
    DEFAULT_GPU_OPTIMAL_THRESHOLD = 10000  # Elements above this strongly prefer GPU

    # Operation-specific routing rules based on benchmarks
    OPERATION_RULES = {
        # GPU excels (from benchmarks)
        OperationType.MATRIX_MULTIPLY: {
            "gpu_threshold": 1024,  # 1024x1024+ matrices
            "gpu_speedup": 21.22,
            "overhead_ms": 10,
        },
        OperationType.RANDOM_GENERATION: {
            "gpu_threshold": 10000,
            "gpu_speedup": 21.88,
            "overhead_ms": 5,
        },
        OperationType.ELEMENT_WISE: {"gpu_threshold": 5000, "gpu_speedup": 15.0, "overhead_ms": 5},
        OperationType.REDUCTION: {"gpu_threshold": 10000, "gpu_speedup": 10.0, "overhead_ms": 8},
        # CPU better (from benchmarks)
        OperationType.GRAPH_ALGORITHM: {
            "gpu_threshold": float("inf"),  # Never use GPU
            "gpu_speedup": 0.01,  # 100x slower on GPU!
            "overhead_ms": 0,
        },
        OperationType.PATH_FINDING: {
            "gpu_threshold": float("inf"),  # Never use GPU
            "gpu_speedup": 0.01,
            "overhead_ms": 0,
        },
        # Mixed results
        OperationType.TRANSFORM: {
            "gpu_threshold": 1000,
            "gpu_speedup": 0.01,  # XOR transform was slow on GPU for small data
            "overhead_ms": 35,
        },
        OperationType.LATTICE_CREATION: {
            "gpu_threshold": 10000,
            "gpu_speedup": 1.19,  # Marginal benefit
            "overhead_ms": 2,
        },
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize operation analyzer

        Args:
            config: Optional configuration overrides
        """
        self.config = config or {}
        self.settings = get_settings()

        # Get thresholds from settings.gpu config, then manual config, then defaults
        self.gpu_threshold = self.config.get(
            "gpu_threshold",
            self.settings.gpu.gpu_threshold_elements
            if hasattr(self.settings, "gpu")
            else self.DEFAULT_GPU_THRESHOLD,
        )
        self.gpu_optimal_threshold = self.config.get(
            "gpu_optimal_threshold",
            self.settings.gpu.gpu_optimal_threshold
            if hasattr(self.settings, "gpu")
            else self.DEFAULT_GPU_OPTIMAL_THRESHOLD,
        )

        # Runtime statistics for adaptive routing
        self._operation_stats: Dict[OperationType, Dict] = {}

        logger.info(
            f"OperationAnalyzer initialized: gpu_threshold={self.gpu_threshold}, "
            f"gpu_optimal_threshold={self.gpu_optimal_threshold}"
        )

    def analyze_operation(
        self,
        operation_type: OperationType,
        element_count: Optional[int] = None,
        data: Optional[np.ndarray] = None,
        **kwargs,
    ) -> OperationCharacteristics:
        """
        Analyze an operation and return its characteristics

        Args:
            operation_type: Type of operation
            element_count: Number of elements (if known)
            data: Input data array (for size estimation)
            **kwargs: Additional operation-specific parameters

        Returns:
            OperationCharacteristics with analysis results
        """
        # Determine element count
        if element_count is None and data is not None:
            element_count = data.size if hasattr(data, "size") else len(data)
        elif element_count is None:
            element_count = 0

        # Estimate memory requirements (rough estimate: 8 bytes per float64)
        memory_estimate_mb = (element_count * 8) / (1024**2) if element_count > 0 else 0

        # Determine parallelizability
        is_parallelizable = operation_type not in [
            OperationType.GRAPH_ALGORITHM,
            OperationType.PATH_FINDING,
        ]

        # Determine if operation has data dependencies
        has_dependencies = operation_type in [
            OperationType.GRAPH_ALGORITHM,
            OperationType.PATH_FINDING,
        ]

        # Check for custom preference
        custom_preference = kwargs.get("device_preference")

        return OperationCharacteristics(
            operation_type=operation_type,
            element_count=element_count,
            is_parallelizable=is_parallelizable,
            has_dependencies=has_dependencies,
            memory_estimate_mb=memory_estimate_mb,
            is_io_bound=False,
            custom_preference=custom_preference,
        )

    def should_use_gpu(
        self,
        characteristics: OperationCharacteristics,
        gpu_available: bool = True,
        available_gpu_memory_mb: Optional[float] = None,
    ) -> tuple[bool, DevicePreference, str]:
        """
        Determine if operation should use GPU

        Args:
            characteristics: Operation characteristics from analyze_operation()
            gpu_available: Whether GPU is available
            available_gpu_memory_mb: Available GPU memory (for OOM prevention)

        Returns:
            Tuple of (use_gpu: bool, preference: DevicePreference, reason: str)
        """
        # Check custom preference first
        if characteristics.custom_preference:
            use_gpu = characteristics.custom_preference in [
                DevicePreference.GPU_OPTIMAL,
                DevicePreference.GPU_ACCEPTABLE,
            ]
            return use_gpu, characteristics.custom_preference, "Custom preference specified"

        # If GPU not available, use CPU
        if not gpu_available:
            return False, DevicePreference.CPU_OPTIMAL, "GPU not available"

        # Check memory constraints
        if available_gpu_memory_mb is not None:
            if characteristics.memory_estimate_mb > available_gpu_memory_mb * 0.8:
                return (
                    False,
                    DevicePreference.CPU_OPTIMAL,
                    f"Insufficient GPU memory ({characteristics.memory_estimate_mb:.1f}MB needed, "
                    f"{available_gpu_memory_mb:.1f}MB available)",
                )

        # Get operation-specific rules
        op_rules = self.OPERATION_RULES.get(characteristics.operation_type, {})
        op_threshold = op_rules.get("gpu_threshold", self.gpu_threshold)
        op_speedup = op_rules.get("gpu_speedup", 1.0)
        op_overhead = op_rules.get("overhead_ms", 0)

        # Decision logic based on operation type and size
        element_count = characteristics.element_count

        # Graph algorithms always use CPU (100x faster)
        if characteristics.operation_type in [
            OperationType.GRAPH_ALGORITHM,
            OperationType.PATH_FINDING,
        ]:
            return (
                False,
                DevicePreference.CPU_OPTIMAL,
                "Graph algorithms perform better on CPU (100x faster)",
            )

        # Very small operations: CPU optimal (GPU overhead dominates)
        if element_count < op_threshold:
            if op_overhead > 10:  # High overhead operations
                return (
                    False,
                    DevicePreference.CPU_OPTIMAL,
                    f"Small operation ({element_count} elements < {op_threshold} threshold), "
                    f"GPU overhead ({op_overhead}ms) dominates",
                )
            else:
                return (
                    False,
                    DevicePreference.CPU_ACCEPTABLE,
                    f"Small operation ({element_count} elements < {op_threshold} threshold)",
                )

        # Large operations with good speedup: GPU optimal
        if element_count >= self.gpu_optimal_threshold and op_speedup > 10:
            return (
                True,
                DevicePreference.GPU_OPTIMAL,
                f"Large operation ({element_count} elements) with {op_speedup:.1f}x speedup",
            )

        # Medium operations: analyze cost-benefit
        if op_speedup > 5:  # Good speedup
            return (
                True,
                DevicePreference.GPU_ACCEPTABLE,
                f"Medium operation with good speedup ({op_speedup:.1f}x)",
            )
        elif op_speedup > 1.5:  # Marginal speedup
            if element_count >= op_threshold * 2:
                return (
                    True,
                    DevicePreference.GPU_ACCEPTABLE,
                    f"Large enough for marginal GPU benefit ({op_speedup:.1f}x)",
                )
            else:
                return (
                    False,
                    DevicePreference.CPU_ACCEPTABLE,
                    f"Marginal speedup ({op_speedup:.1f}x) not worth GPU overhead",
                )
        else:  # Poor speedup
            return (
                False,
                DevicePreference.CPU_OPTIMAL,
                f"CPU faster for this operation type ({1 / op_speedup:.1f}x faster)",
            )

    def route_operation(
        self,
        operation_type: OperationType,
        element_count: Optional[int] = None,
        data: Optional[np.ndarray] = None,
        gpu_available: bool = True,
        available_gpu_memory_mb: Optional[float] = None,
        **kwargs,
    ) -> tuple[bool, str]:
        """
        High-level routing decision (convenience method)

        Args:
            operation_type: Type of operation
            element_count: Number of elements
            data: Input data
            gpu_available: GPU availability
            available_gpu_memory_mb: Available GPU memory
            **kwargs: Additional parameters

        Returns:
            Tuple of (use_gpu: bool, reason: str)
        """
        characteristics = self.analyze_operation(
            operation_type=operation_type, element_count=element_count, data=data, **kwargs
        )

        use_gpu, preference, reason = self.should_use_gpu(
            characteristics=characteristics,
            gpu_available=gpu_available,
            available_gpu_memory_mb=available_gpu_memory_mb,
        )

        logger.debug(
            f"Routing decision: {operation_type.value} -> "
            f"{'GPU' if use_gpu else 'CPU'} ({preference.value}): {reason}"
        )

        return use_gpu, reason

    def record_operation_result(
        self,
        operation_type: OperationType,
        element_count: int,
        used_gpu: bool,
        execution_time_ms: float,
    ):
        """
        Record operation result for adaptive routing (future enhancement)

        Args:
            operation_type: Operation type
            element_count: Element count
            used_gpu: Whether GPU was used
            execution_time_ms: Execution time in milliseconds
        """
        if operation_type not in self._operation_stats:
            self._operation_stats[operation_type] = {
                "gpu": {"count": 0, "total_time_ms": 0, "avg_time_ms": 0},
                "cpu": {"count": 0, "total_time_ms": 0, "avg_time_ms": 0},
            }

        device = "gpu" if used_gpu else "cpu"
        stats = self._operation_stats[operation_type][device]
        stats["count"] += 1
        stats["total_time_ms"] += execution_time_ms
        stats["avg_time_ms"] = stats["total_time_ms"] / stats["count"]

    def get_operation_stats(self) -> Dict[OperationType, Dict]:
        """Get recorded operation statistics"""
        return self._operation_stats.copy()


# Global instance
_global_analyzer: Optional[OperationAnalyzer] = None


def get_operation_analyzer(config: Optional[Dict[str, Any]] = None) -> OperationAnalyzer:
    """
    Get global operation analyzer instance (singleton pattern)

    Args:
        config: Optional configuration

    Returns:
        OperationAnalyzer instance
    """
    global _global_analyzer

    if _global_analyzer is None:
        _global_analyzer = OperationAnalyzer(config=config)

    return _global_analyzer
