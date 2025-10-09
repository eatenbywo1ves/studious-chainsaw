"""
Batch Processor for Parallel Lattice Operations
Enables processing multiple lattices in parallel for 3-5x speedup
"""

import logging
import time
from typing import List, Optional, Dict, Any, Callable, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import numpy as np

from ..gpu.batch_operations import GPUBatchOperations, BatchOperationError
from libs.gpu.memory_manager import get_memory_monitor

logger = logging.getLogger(__name__)


@dataclass
class BatchConfig:
    """Configuration for batch processing"""

    max_batch_size: int = 32
    min_batch_size: int = 2
    auto_optimize_batch_size: bool = True
    memory_safety_margin: float = 0.2  # Reserve 20% of memory
    timeout_seconds: float = 300.0
    enable_async: bool = True


class LatticeBatch:
    """
    Batch processor for multiple lattice operations
    Processes operations in parallel for improved throughput
    """

    def __init__(
        self,
        lattices: List[Any],
        config: Optional[BatchConfig] = None,
        device_id: int = 0,
        backend: str = "pytorch",
    ):
        """
        Initialize batch processor

        Args:
            lattices: List of UnifiedCatalyticLattice instances
            config: Batch configuration
            device_id: GPU device ID
            backend: Backend to use
        """
        self.lattices = lattices
        self.config = config or BatchConfig()
        self.device_id = device_id
        self.backend = backend

        # Initialize batch operations
        self.batch_ops = GPUBatchOperations(device_id=device_id, backend=backend)

        # Get memory monitor
        self.memory_monitor = get_memory_monitor(device_id=device_id)

        # Thread pool for async operations
        self.executor = ThreadPoolExecutor(max_workers=4) if self.config.enable_async else None

        # Statistics
        self._operation_count = 0
        self._total_time_ms = 0.0
        self._optimal_batch_size = self.config.max_batch_size

        logger.info(
            f"LatticeBatch initialized: {len(lattices)} lattices, "
            f"max_batch_size={self.config.max_batch_size}"
        )

    def execute_parallel(
        self, operations: List[Callable], operation_name: str = "custom"
    ) -> List[Any]:
        """
        Execute operations in parallel across all lattices

        Args:
            operations: List of callables (one per lattice)
            operation_name: Name for logging

        Returns:
            List of results (one per lattice)
        """
        if len(operations) != len(self.lattices):
            raise ValueError("Number of operations must match number of lattices")

        start_time = time.time()
        results = []

        try:
            # Determine optimal batch size
            batch_size = self._calculate_batch_size(len(self.lattices))

            logger.info(
                f"Executing {operation_name}: {len(operations)} operations "
                f"in batches of {batch_size}"
            )

            # Process in batches
            for i in range(0, len(operations), batch_size):
                batch_ops = operations[i : i + batch_size]
                batch_lattices = self.lattices[i : i + batch_size]

                # Execute batch
                batch_results = self._execute_batch(batch_ops, batch_lattices)
                results.extend(batch_results)

            elapsed_ms = (time.time() - start_time) * 1000
            self._record_operation(len(operations), elapsed_ms)

            logger.info(
                f"Batch execution complete: {len(results)} results in {elapsed_ms:.2f}ms "
                f"({elapsed_ms / len(results):.2f}ms per operation)"
            )

            return results

        except Exception as e:
            logger.error(f"Batch execution failed: {e}")
            raise

    def _execute_batch(self, operations: List[Callable], lattices: List[Any]) -> List[Any]:
        """Execute a single batch of operations"""
        if self.config.enable_async and self.executor:
            # Async execution
            futures = [
                self.executor.submit(op, lattice) for op, lattice in zip(operations, lattices)
            ]
            results = [f.result(timeout=self.config.timeout_seconds) for f in futures]
        else:
            # Sync execution
            results = [op(lattice) for op, lattice in zip(operations, lattices)]

        return results

    def batch_xor_transform(
        self, data_list: List[np.ndarray], key_list: Optional[List[np.ndarray]] = None
    ) -> List[np.ndarray]:
        """
        Batch XOR transformation across all lattices

        Args:
            data_list: List of data arrays (one per lattice)
            key_list: Optional list of keys

        Returns:
            List of transformed arrays
        """
        if len(data_list) != len(self.lattices):
            raise ValueError("Data list must match lattice count")

        start_time = time.time()

        try:
            # Use GPU batch operations
            results = self.batch_ops.batch_xor_transform(data_list, key_list)

            elapsed_ms = (time.time() - start_time) * 1000
            self._record_operation(len(data_list), elapsed_ms)

            logger.debug(f"Batch XOR: {len(results)} arrays in {elapsed_ms:.2f}ms")

            return results

        except BatchOperationError as e:
            logger.warning(f"GPU batch failed, falling back to sequential: {e}")
            # Fallback to sequential
            return [
                lattice.xor_transform(data, key if key_list else None)
                for lattice, data, key in zip(
                    self.lattices, data_list, key_list or [None] * len(data_list)
                )
            ]

    def batch_matrix_operations(
        self,
        a_matrices: List[np.ndarray],
        b_matrices: List[np.ndarray],
        operation: str = "multiply",
    ) -> List[np.ndarray]:
        """
        Batch matrix operations

        Args:
            a_matrices: List of left matrices
            b_matrices: List of right matrices
            operation: Operation type ("multiply", "add", etc.)

        Returns:
            List of result matrices
        """
        start_time = time.time()

        try:
            if operation == "multiply":
                results = self.batch_ops.batch_matrix_multiply(a_matrices, b_matrices)
            else:
                raise ValueError(f"Unknown matrix operation: {operation}")

            elapsed_ms = (time.time() - start_time) * 1000
            self._record_operation(len(a_matrices), elapsed_ms)

            return results

        except BatchOperationError as e:
            logger.warning(f"GPU batch failed, falling back: {e}")
            # Fallback
            if operation == "multiply":
                return [np.dot(a, b) for a, b in zip(a_matrices, b_matrices)]
            else:
                raise

    def batch_find_shortest_paths(
        self, start_vertices: List[int], end_vertices: List[int]
    ) -> List[Tuple[List[int], float]]:
        """
        Find shortest paths for multiple lattices in parallel

        Args:
            start_vertices: List of start vertices (one per lattice)
            end_vertices: List of end vertices (one per lattice)

        Returns:
            List of (path, time) tuples
        """
        if len(start_vertices) != len(self.lattices):
            raise ValueError("Start vertices must match lattice count")
        if len(end_vertices) != len(self.lattices):
            raise ValueError("End vertices must match lattice count")

        start_time = time.time()

        # Define operation for each lattice
        operations = [
            lambda lattice, s=start, e=end: lattice.find_shortest_path(s, e)
            for start, end in zip(start_vertices, end_vertices)
        ]

        results = self.execute_parallel(operations, operation_name="shortest_path")

        elapsed_ms = (time.time() - start_time) * 1000
        self._record_operation(len(start_vertices), elapsed_ms)

        return results

    def _calculate_batch_size(self, total_items: int) -> int:
        """
        Calculate optimal batch size based on memory and performance

        Args:
            total_items: Total number of items to process

        Returns:
            Optimal batch size
        """
        if not self.config.auto_optimize_batch_size:
            return min(self.config.max_batch_size, total_items)

        # Check available memory
        snapshot = self.memory_monitor.get_memory_snapshot()
        available_mb = snapshot.available_mb * (1 - self.config.memory_safety_margin)

        # Estimate memory per item (rough estimate: 10MB per lattice operation)
        estimated_mb_per_item = 10.0

        # Calculate memory-constrained batch size
        memory_batch_size = int(available_mb / estimated_mb_per_item)

        # Clamp to configured limits
        batch_size = max(
            self.config.min_batch_size,
            min(memory_batch_size, self.config.max_batch_size, total_items),
        )

        logger.debug(
            f"Calculated batch size: {batch_size} (memory: {available_mb:.1f}MB available)"
        )

        return batch_size

    def _record_operation(self, count: int, elapsed_ms: float):
        """Record operation statistics"""
        self._operation_count += count
        self._total_time_ms += elapsed_ms

    def get_stats(self) -> Dict[str, Any]:
        """Get batch processing statistics"""
        batch_ops_stats = self.batch_ops.get_stats()

        if self._operation_count > 0:
            avg_time_per_op = self._total_time_ms / self._operation_count
        else:
            avg_time_per_op = 0.0

        return {
            "total_operations": self._operation_count,
            "total_time_ms": self._total_time_ms,
            "avg_time_per_op_ms": avg_time_per_op,
            "optimal_batch_size": self._optimal_batch_size,
            "lattice_count": len(self.lattices),
            "batch_ops_stats": batch_ops_stats,
        }

    def print_stats(self):
        """Print batch processing statistics"""
        stats = self.get_stats()
        print(f"\n{'=' * 60}")
        print("BATCH PROCESSING STATISTICS")
        print(f"{'=' * 60}")
        print(f"Lattice Count: {stats['lattice_count']}")
        print(f"Total Operations: {stats['total_operations']}")
        print(f"Total Time: {stats['total_time_ms']:.2f}ms")
        print(f"Avg Time per Op: {stats['avg_time_per_op_ms']:.2f}ms")
        print(f"Optimal Batch Size: {stats['optimal_batch_size']}")

        batch_ops = stats["batch_ops_stats"]
        print("\nBatch Operations:")
        print(f"  Total Batch Ops: {batch_ops['total_batch_ops']}")
        print(f"  Items Processed: {batch_ops['total_items_processed']}")
        print(f"  Avg Batch Size: {batch_ops['avg_batch_size']:.1f}")
        print(f"  Avg Time per Batch: {batch_ops['avg_time_ms']:.2f}ms")
        print(f"{'=' * 60}\n")

    def cleanup(self):
        """Clean up resources"""
        if self.executor:
            self.executor.shutdown(wait=True)


# Convenience function for quick batch creation
def create_batch(lattices: List[Any], max_batch_size: int = 32, device_id: int = 0) -> LatticeBatch:
    """
    Create a batch processor for multiple lattices

    Args:
        lattices: List of lattices to process
        max_batch_size: Maximum batch size
        device_id: GPU device ID

    Returns:
        LatticeBatch instance
    """
    config = BatchConfig(max_batch_size=max_batch_size)
    return LatticeBatch(lattices=lattices, config=config, device_id=device_id)
