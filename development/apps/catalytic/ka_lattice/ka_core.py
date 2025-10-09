"""
KA Lattice Core - Knowledge-Augmented Lattice Implementation
Extends catalytic computing with knowledge integration and learning
"""

import numpy as np
import time
import json
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import logging

from apps.catalytic.core.unified_lattice import UnifiedCatalyticLattice
from libs.utils.exceptions import LatticeException

logger = logging.getLogger(__name__)


class LatticeState(Enum):
    """Lattice lifecycle states"""

    INITIALIZING = "initializing"
    BUILDING = "building"
    READY = "ready"
    PROCESSING = "processing"
    LEARNING = "learning"
    OPTIMIZING = "optimizing"
    SUSPENDED = "suspended"
    ERROR = "error"
    TERMINATED = "terminated"


@dataclass
class KnowledgeEntry:
    """Single knowledge entry in the lattice"""

    pattern_id: str
    input_signature: str
    output_signature: str
    performance_metrics: Dict[str, float]
    timestamp: datetime = field(default_factory=datetime.now)
    usage_count: int = 0
    success_rate: float = 1.0


@dataclass
class ComputationResult:
    """Result of a lattice computation"""

    result_data: Any
    execution_time_ms: float
    memory_used_mb: float
    knowledge_applied: List[str]
    confidence_score: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class KALatticeCore(UnifiedCatalyticLattice):
    """
    Knowledge-Augmented Lattice Core
    Extends unified lattice with knowledge integration and production features
    """

    def __init__(
        self,
        dimensions: int,
        size: int,
        knowledge_capacity: int = 10000,
        learning_enabled: bool = True,
        **kwargs,
    ):
        """
        Initialize KA Lattice

        Args:
            dimensions: Number of dimensions
            size: Size in each dimension
            knowledge_capacity: Maximum knowledge entries to store
            learning_enabled: Enable adaptive learning
            **kwargs: Additional arguments for parent class
        """
        super().__init__(dimensions, size, **kwargs)

        self.knowledge_capacity = knowledge_capacity
        self.learning_enabled = learning_enabled

        # Knowledge storage
        self.knowledge_base: Dict[str, KnowledgeEntry] = {}
        self.pattern_cache: Dict[str, Any] = {}

        # State management
        self._state = LatticeState.INITIALIZING
        self._state_history: List[Tuple[LatticeState, datetime]] = []

        # Performance tracking
        self.computation_history: List[ComputationResult] = []
        self.performance_stats = {
            "total_computations": 0,
            "successful_computations": 0,
            "average_execution_ms": 0.0,
            "knowledge_hits": 0,
            "knowledge_misses": 0,
            "learning_cycles": 0,
        }

        # Initialize
        self._transition_state(LatticeState.BUILDING)
        self.build_lattice()
        self._transition_state(LatticeState.READY)

    def _transition_state(self, new_state: LatticeState):
        """Transition to new state with validation"""
        valid_transitions = {
            LatticeState.INITIALIZING: [LatticeState.BUILDING, LatticeState.ERROR],
            LatticeState.BUILDING: [LatticeState.READY, LatticeState.ERROR],
            LatticeState.READY: [
                LatticeState.PROCESSING,
                LatticeState.LEARNING,
                LatticeState.OPTIMIZING,
                LatticeState.SUSPENDED,
                LatticeState.TERMINATED,
            ],
            LatticeState.PROCESSING: [
                LatticeState.READY,
                LatticeState.ERROR,
                LatticeState.TERMINATED,
            ],
            LatticeState.LEARNING: [LatticeState.READY, LatticeState.OPTIMIZING],
            LatticeState.OPTIMIZING: [LatticeState.READY],
            LatticeState.SUSPENDED: [LatticeState.READY, LatticeState.TERMINATED],
            LatticeState.ERROR: [LatticeState.READY, LatticeState.TERMINATED],
            LatticeState.TERMINATED: [],
        }

        if self._state != new_state:
            if new_state in valid_transitions.get(self._state, []):
                self._state_history.append((self._state, datetime.now()))
                self._state = new_state
                logger.info(
                    f"Lattice state transition: {self._state_history[-1][0]} -> {new_state}"
                )
            else:
                raise LatticeException(f"Invalid state transition: {self._state} -> {new_state}")

    @property
    def state(self) -> LatticeState:
        """Get current lattice state"""
        return self._state

    def compute_with_knowledge(
        self, operation: str, input_data: np.ndarray, parameters: Optional[Dict[str, Any]] = None
    ) -> ComputationResult:
        """
        Perform computation with knowledge augmentation

        Args:
            operation: Operation to perform
            input_data: Input data
            parameters: Operation parameters

        Returns:
            ComputationResult with knowledge integration
        """
        if self._state != LatticeState.READY:
            raise LatticeException(f"Lattice not ready for computation (state: {self._state})")

        self._transition_state(LatticeState.PROCESSING)
        start_time = time.perf_counter()
        knowledge_applied = []

        try:
            # Generate input signature
            input_signature = self._generate_signature(operation, input_data, parameters)

            # Check knowledge base for similar patterns
            if input_signature in self.knowledge_base:
                knowledge_entry = self.knowledge_base[input_signature]
                knowledge_entry.usage_count += 1
                knowledge_applied.append(knowledge_entry.pattern_id)
                self.performance_stats["knowledge_hits"] += 1

                # Use cached result if available
                if knowledge_entry.pattern_id in self.pattern_cache:
                    cached_result = self.pattern_cache[knowledge_entry.pattern_id]
                    exec_time = (time.perf_counter() - start_time) * 1000

                    result = ComputationResult(
                        result_data=cached_result,
                        execution_time_ms=exec_time,
                        memory_used_mb=0.0,  # No additional memory for cached
                        knowledge_applied=knowledge_applied,
                        confidence_score=knowledge_entry.success_rate,
                        metadata={"cached": True, "pattern_id": knowledge_entry.pattern_id},
                    )

                    self._record_computation(result, success=True)
                    return result
            else:
                self.performance_stats["knowledge_misses"] += 1

            # Perform actual computation
            result_data = self._execute_operation(operation, input_data, parameters)

            # Calculate metrics
            exec_time = (time.perf_counter() - start_time) * 1000
            memory_used = self._estimate_memory_usage(input_data, result_data)

            # Create result
            result = ComputationResult(
                result_data=result_data,
                execution_time_ms=exec_time,
                memory_used_mb=memory_used,
                knowledge_applied=knowledge_applied,
                confidence_score=self._calculate_confidence(operation, exec_time),
                metadata={"operation": operation, "input_shape": input_data.shape},
            )

            # Learn from computation if enabled
            if self.learning_enabled and result.confidence_score > 0.8:
                self._learn_pattern(operation, input_signature, result)

            self._record_computation(result, success=True)
            return result

        except Exception as e:
            logger.error(f"Computation failed: {e}")
            self._transition_state(LatticeState.ERROR)

            # Create error result
            exec_time = (time.perf_counter() - start_time) * 1000
            result = ComputationResult(
                result_data=None,
                execution_time_ms=exec_time,
                memory_used_mb=0.0,
                knowledge_applied=knowledge_applied,
                confidence_score=0.0,
                metadata={"error": str(e)},
            )

            self._record_computation(result, success=False)
            raise

        finally:
            if self._state == LatticeState.PROCESSING:
                self._transition_state(LatticeState.READY)

    def _execute_operation(
        self, operation: str, input_data: np.ndarray, parameters: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Execute the specified operation"""
        parameters = parameters or {}

        if operation == "transform":
            transform_type = parameters.get("type", "xor")
            return self.apply_transformation(input_data, transform_type, **parameters)

        elif operation == "pathfind":
            start = parameters.get("start", 0)
            end = parameters.get("end", self.n_points - 1)
            path, _ = self.find_path_catalytic(start, end)
            return path

        elif operation == "analyze":
            return self.analyze_structure()

        elif operation == "reduce":
            reduce_op = parameters.get("operation", "sum")
            if self.gpu_backend:
                return self.gpu_backend.parallel_reduce(input_data, reduce_op)
            else:
                return np.sum(input_data) if reduce_op == "sum" else np.max(input_data)

        else:
            raise ValueError(f"Unknown operation: {operation}")

    def _generate_signature(
        self, operation: str, input_data: np.ndarray, parameters: Optional[Dict[str, Any]]
    ) -> str:
        """Generate unique signature for input pattern"""
        hasher = hashlib.sha256()
        hasher.update(operation.encode())
        hasher.update(str(input_data.shape).encode())
        hasher.update(str(input_data.dtype).encode())

        # Include statistical properties
        hasher.update(str(np.mean(input_data)).encode())
        hasher.update(str(np.std(input_data)).encode())

        if parameters:
            hasher.update(json.dumps(parameters, sort_keys=True).encode())

        return hasher.hexdigest()[:16]

    def _calculate_confidence(self, operation: str, exec_time: float) -> float:
        """Calculate confidence score based on performance"""
        # Base confidence on execution time vs expected
        expected_times = {"transform": 10.0, "pathfind": 50.0, "analyze": 100.0, "reduce": 5.0}

        expected = expected_times.get(operation, 50.0)
        ratio = expected / max(exec_time, 0.1)

        # Clamp between 0 and 1
        confidence = min(max(ratio, 0.0), 1.0)

        # Adjust based on success rate
        if self.performance_stats["total_computations"] > 0:
            success_rate = (
                self.performance_stats["successful_computations"]
                / self.performance_stats["total_computations"]
            )
            confidence *= success_rate

        return confidence

    def _estimate_memory_usage(self, input_data: np.ndarray, result_data: Any) -> float:
        """Estimate memory usage in MB"""
        input_size = input_data.nbytes / (1024**2)

        if isinstance(result_data, np.ndarray):
            result_size = result_data.nbytes / (1024**2)
        elif isinstance(result_data, (list, dict)):
            result_size = len(json.dumps(result_data)) / (1024**2)
        else:
            result_size = 0.001  # Minimal for primitives

        return input_size + result_size

    def _learn_pattern(self, operation: str, input_signature: str, result: ComputationResult):
        """Learn from successful computation"""
        if len(self.knowledge_base) >= self.knowledge_capacity:
            # Evict least used entry
            least_used = min(self.knowledge_base.values(), key=lambda x: x.usage_count)
            del self.knowledge_base[least_used.pattern_id]

        # Create knowledge entry
        pattern_id = f"{operation}_{input_signature[:8]}_{int(time.time())}"

        entry = KnowledgeEntry(
            pattern_id=pattern_id,
            input_signature=input_signature,
            output_signature=hashlib.sha256(str(result.result_data).encode()).hexdigest()[:16],
            performance_metrics={
                "execution_time_ms": result.execution_time_ms,
                "memory_used_mb": result.memory_used_mb,
                "confidence": result.confidence_score,
            },
        )

        self.knowledge_base[input_signature] = entry

        # Cache result if small enough
        if result.memory_used_mb < 10.0:  # Cache results under 10MB
            self.pattern_cache[pattern_id] = result.result_data

        logger.debug(f"Learned pattern: {pattern_id}")

    def _record_computation(self, result: ComputationResult, success: bool):
        """Record computation for statistics"""
        self.computation_history.append(result)

        # Update statistics
        self.performance_stats["total_computations"] += 1
        if success:
            self.performance_stats["successful_computations"] += 1

        # Update rolling average execution time
        n = self.performance_stats["total_computations"]
        avg = self.performance_stats["average_execution_ms"]
        self.performance_stats["average_execution_ms"] = (
            avg * (n - 1) + result.execution_time_ms
        ) / n

        # Limit history size
        if len(self.computation_history) > 1000:
            self.computation_history = self.computation_history[-500:]

    def optimize_knowledge_base(self):
        """Optimize knowledge base by removing poor performers"""
        if self._state != LatticeState.READY:
            return

        self._transition_state(LatticeState.OPTIMIZING)
        removed = 0

        try:
            # Remove entries with low success rate or usage
            entries_to_remove = []
            for signature, entry in self.knowledge_base.items():
                if entry.success_rate < 0.5 or (
                    entry.usage_count < 2 and (datetime.now() - entry.timestamp).days > 1
                ):
                    entries_to_remove.append(signature)

            for signature in entries_to_remove:
                pattern_id = self.knowledge_base[signature].pattern_id
                del self.knowledge_base[signature]
                if pattern_id in self.pattern_cache:
                    del self.pattern_cache[pattern_id]
                removed += 1

            self.performance_stats["learning_cycles"] += 1
            logger.info(f"Knowledge optimization complete: removed {removed} entries")

        finally:
            self._transition_state(LatticeState.READY)

    def get_knowledge_stats(self) -> Dict[str, Any]:
        """Get knowledge base statistics"""
        if not self.knowledge_base:
            return {"total_entries": 0, "cache_size": 0, "hit_rate": 0.0}

        total_usage = sum(entry.usage_count for entry in self.knowledge_base.values())
        avg_success = np.mean([entry.success_rate for entry in self.knowledge_base.values()])

        total_ops = (
            self.performance_stats["knowledge_hits"] + self.performance_stats["knowledge_misses"]
        )
        hit_rate = (
            self.performance_stats["knowledge_hits"] / total_ops * 100 if total_ops > 0 else 0.0
        )

        return {
            "total_entries": len(self.knowledge_base),
            "cache_size": len(self.pattern_cache),
            "total_usage": total_usage,
            "average_success_rate": float(avg_success),
            "hit_rate": hit_rate,
            "learning_cycles": self.performance_stats["learning_cycles"],
        }

    def export_knowledge(self) -> Dict[str, Any]:
        """Export knowledge base for persistence"""
        return {
            "version": "1.0",
            "dimensions": self.dimensions,
            "size": self.size,
            "knowledge_base": {
                sig: {
                    "pattern_id": entry.pattern_id,
                    "input_signature": entry.input_signature,
                    "output_signature": entry.output_signature,
                    "performance_metrics": entry.performance_metrics,
                    "timestamp": entry.timestamp.isoformat(),
                    "usage_count": entry.usage_count,
                    "success_rate": entry.success_rate,
                }
                for sig, entry in self.knowledge_base.items()
            },
            "performance_stats": self.performance_stats,
            "export_time": datetime.now().isoformat(),
        }

    def import_knowledge(self, knowledge_data: Dict[str, Any]):
        """Import knowledge base from persistence"""
        if knowledge_data["version"] != "1.0":
            raise ValueError(f"Unsupported knowledge version: {knowledge_data['version']}")

        # Verify compatibility
        if knowledge_data["dimensions"] != self.dimensions or knowledge_data["size"] != self.size:
            logger.warning("Knowledge base from different lattice configuration")

        # Import entries
        for sig, entry_data in knowledge_data["knowledge_base"].items():
            entry = KnowledgeEntry(
                pattern_id=entry_data["pattern_id"],
                input_signature=entry_data["input_signature"],
                output_signature=entry_data["output_signature"],
                performance_metrics=entry_data["performance_metrics"],
                timestamp=datetime.fromisoformat(entry_data["timestamp"]),
                usage_count=entry_data["usage_count"],
                success_rate=entry_data["success_rate"],
            )
            self.knowledge_base[sig] = entry

        logger.info(f"Imported {len(self.knowledge_base)} knowledge entries")

    def shutdown(self):
        """Graceful shutdown of lattice"""
        if self._state == LatticeState.TERMINATED:
            return

        logger.info("Shutting down KA Lattice...")

        # Transition to terminated state
        if self._state in [LatticeState.READY, LatticeState.SUSPENDED, LatticeState.ERROR]:
            self._transition_state(LatticeState.TERMINATED)

        # Cleanup resources
        self.cleanup()

        # Clear knowledge base
        self.knowledge_base.clear()
        self.pattern_cache.clear()

        logger.info("KA Lattice shutdown complete")
