"""
GPU Profiler Optimizer - Automated Optimization Suggestions
Analyzes profiling data and suggests performance improvements

Now with Mernithian-inspired transformation equivalence framework
"""

import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

# Lazy import for transformation framework
_transformation_catalog = None


def _get_transformation_catalog():
    """Lazy load transformation catalog"""
    global _transformation_catalog
    if _transformation_catalog is None:
        try:
            from .profiler_transformations import get_transformation_catalog

            _transformation_catalog = get_transformation_catalog()
        except ImportError:
            logger.warning("Transformation catalog not available")
    return _transformation_catalog


class OptimizationType(Enum):
    """Type of optimization suggestion"""

    ROUTING = "routing"  # Smart routing to CPU/GPU
    BATCHING = "batching"  # Use batch processing
    MEMORY = "memory"  # Memory optimization
    CACHING = "caching"  # Add caching
    ALGORITHM = "algorithm"  # Algorithm improvement
    PARALLELIZATION = "parallelization"  # Add parallel execution


class Priority(Enum):
    """Priority level for optimization"""

    CRITICAL = "critical"  # High impact, easy to implement
    HIGH = "high"  # High impact or easy to implement
    MEDIUM = "medium"  # Moderate impact
    LOW = "low"  # Low impact or difficult to implement


@dataclass
class OptimizationSuggestion:
    """Single optimization suggestion with formal transformation proof"""

    operation: str
    type: OptimizationType
    priority: Priority
    description: str
    expected_improvement: str
    implementation_hint: str

    # Metrics
    current_time_ms: float
    estimated_time_ms: float
    potential_speedup: float

    # Transformation framework integration
    transformation_rule: Optional[str] = None  # Name of transformation rule
    formal_theorem: Optional[str] = None  # E₁ ⟷ᵀ E₂ theorem
    proof_sketch: List[str] = field(default_factory=list)  # Proof steps
    invariants: List[str] = field(default_factory=list)  # Preserved properties
    assumptions: List[str] = field(default_factory=list)  # Required conditions


class ProfilerOptimizer:
    """
    Analyze profiling data and suggest optimizations
    """

    def __init__(self, profiling_data: Dict):
        """
        Initialize optimizer

        Args:
            profiling_data: Profiling data (JSON dict from profiler export)
        """
        self.data = profiling_data
        self.suggestions: List[OptimizationSuggestion] = []
        self._analyze()

    def _analyze(self):
        """Analyze profiling data and generate suggestions"""
        summary = self.data.get("summary", {})
        entries = self.data.get("entries", [])

        for op_name, stats in summary.items():
            # Get sample entry for this operation
            op_entries = [e for e in entries if e["operation"] == op_name]
            if not op_entries:
                continue

            sample = op_entries[0]

            # Check various optimization opportunities
            self._check_routing_opportunity(op_name, stats, sample)
            self._check_batching_opportunity(op_name, stats, sample)
            self._check_memory_opportunity(op_name, stats, sample)
            self._check_small_frequent_calls(op_name, stats)
            self._check_gpu_underutilization(op_name, stats, sample)

    def _check_routing_opportunity(self, op: str, stats: Dict, sample: Dict):
        """Check if operation should be routed differently"""
        device = sample.get("device", "unknown")
        avg_time = stats["avg_time_ms"]
        catalog = _get_transformation_catalog()

        # Small GPU operations (overhead likely exceeds benefit)
        if device == "gpu" and avg_time < 1.0:
            # Get transformation rule if catalog available
            transformation_rule = None
            formal_theorem = None
            proof_sketch = []
            invariants = []
            assumptions = []

            if catalog:
                rule = catalog.get_rule("SmallGPUToCPU")
                if rule:
                    transformation_rule = rule.name
                    formal_theorem = rule.proof.theorem
                    proof_sketch = rule.proof.proof_sketch[:3]  # First 3 steps
                    invariants = rule.proof.invariants
                    assumptions = rule.proof.assumptions[:2]  # First 2 assumptions

            self.suggestions.append(
                OptimizationSuggestion(
                    operation=op,
                    type=OptimizationType.ROUTING,
                    priority=Priority.HIGH,
                    description=f"Operation runs on GPU but takes <1ms (avg {avg_time:.2f}ms)",
                    expected_improvement="5-50x speedup",
                    implementation_hint="Route to CPU using smart routing: "
                    "enable_smart_routing=True",
                    current_time_ms=stats["total_time_ms"],
                    estimated_time_ms=stats["total_time_ms"] * 0.1,  # Estimate 10x improvement
                    potential_speedup=10.0,
                    transformation_rule=transformation_rule,
                    formal_theorem=formal_theorem,
                    proof_sketch=proof_sketch,
                    invariants=invariants,
                    assumptions=assumptions,
                )
            )

        # Large CPU operations that could benefit from GPU
        elif device == "cpu" and avg_time > 10.0:
            memory_mb = sample.get("memory_allocated_mb", 0)
            if memory_mb > 1.0:  # Significant memory usage suggests compute-intensive
                # Get transformation rule if catalog available
                transformation_rule = None
                formal_theorem = None
                proof_sketch = []
                invariants = []
                assumptions = []

                if catalog:
                    rule = catalog.get_rule("LargeCPUToGPU")
                    if rule:
                        transformation_rule = rule.name
                        formal_theorem = rule.proof.theorem
                        proof_sketch = rule.proof.proof_sketch[:3]
                        invariants = rule.proof.invariants
                        assumptions = rule.proof.assumptions[:2]

                self.suggestions.append(
                    OptimizationSuggestion(
                        operation=op,
                        type=OptimizationType.ROUTING,
                        priority=Priority.MEDIUM,
                        description=f"Large operation on CPU (avg {avg_time:.2f}ms, "
                        f"{memory_mb:.1f}MB)",
                        expected_improvement="2-20x speedup",
                        implementation_hint="Consider GPU implementation for this operation",
                        current_time_ms=stats["total_time_ms"],
                        estimated_time_ms=stats["total_time_ms"] * 0.2,  # Estimate 5x improvement
                        potential_speedup=5.0,
                        transformation_rule=transformation_rule,
                        formal_theorem=formal_theorem,
                        proof_sketch=proof_sketch,
                        invariants=invariants,
                        assumptions=assumptions,
                    )
                )

    def _check_batching_opportunity(self, op: str, stats: Dict, sample: Dict):
        """Check if operation could benefit from batching"""
        call_count = stats["call_count"]
        avg_time = stats["avg_time_ms"]
        catalog = _get_transformation_catalog()

        # Multiple calls to same operation - batching opportunity
        if call_count >= 10 and avg_time < 100.0:
            # Get transformation rule if catalog available
            transformation_rule = None
            formal_theorem = None
            proof_sketch = []
            invariants = []
            assumptions = []

            if catalog:
                rule = catalog.get_rule("BatchFusion")
                if rule:
                    transformation_rule = rule.name
                    formal_theorem = rule.proof.theorem
                    proof_sketch = rule.proof.proof_sketch[:3]
                    invariants = rule.proof.invariants
                    assumptions = rule.proof.assumptions[:2]

            self.suggestions.append(
                OptimizationSuggestion(
                    operation=op,
                    type=OptimizationType.BATCHING,
                    priority=Priority.HIGH if call_count >= 20 else Priority.MEDIUM,
                    description=f"Operation called {call_count} times sequentially",
                    expected_improvement="2-5x speedup",
                    implementation_hint="Use batch processing: create_batch(lattices) "
                    "and process in parallel",
                    current_time_ms=stats["total_time_ms"],
                    estimated_time_ms=stats["total_time_ms"] * 0.4,  # Estimate 2.5x improvement
                    potential_speedup=2.5,
                    transformation_rule=transformation_rule,
                    formal_theorem=formal_theorem,
                    proof_sketch=proof_sketch,
                    invariants=invariants,
                    assumptions=assumptions,
                )
            )

    def _check_memory_opportunity(self, op: str, stats: Dict, sample: Dict):
        """Check for memory optimization opportunities"""
        avg_memory = stats.get("avg_memory_mb", 0)

        # High memory usage
        if avg_memory > 100.0:
            self.suggestions.append(
                OptimizationSuggestion(
                    operation=op,
                    type=OptimizationType.MEMORY,
                    priority=Priority.MEDIUM,
                    description=f"High memory usage (avg {avg_memory:.1f}MB)",
                    expected_improvement="Memory reduction + potential speedup",
                    implementation_hint="Consider: 1) Using smaller data types, "
                    "2) Processing in chunks, 3) Memory pooling",
                    current_time_ms=stats["total_time_ms"],
                    estimated_time_ms=stats["total_time_ms"]
                    * 0.9,  # Small speedup from better cache
                    potential_speedup=1.1,
                )
            )

    def _check_small_frequent_calls(self, op: str, stats: Dict):
        """Check for small frequent calls that should be cached"""
        call_count = stats["call_count"]
        avg_time = stats["avg_time_ms"]
        total_time = stats["total_time_ms"]

        # Many small calls - caching opportunity
        if call_count >= 100 and avg_time < 1.0:
            self.suggestions.append(
                OptimizationSuggestion(
                    operation=op,
                    type=OptimizationType.CACHING,
                    priority=Priority.CRITICAL,
                    description=f"Very frequent small calls ({call_count} calls, "
                    f"{avg_time:.2f}ms avg, {total_time:.2f}ms total)",
                    expected_improvement="10-100x speedup",
                    implementation_hint="Add caching/memoization for this operation",
                    current_time_ms=total_time,
                    estimated_time_ms=total_time * 0.1,  # Estimate 10x improvement
                    potential_speedup=10.0,
                )
            )

    def _check_gpu_underutilization(self, op: str, stats: Dict, sample: Dict):
        """Check for GPU underutilization"""
        device = sample.get("device", "unknown")
        gpu_util = sample.get("gpu_utilization", 0)

        if device == "gpu" and gpu_util < 50.0:
            self.suggestions.append(
                OptimizationSuggestion(
                    operation=op,
                    type=OptimizationType.PARALLELIZATION,
                    priority=Priority.MEDIUM,
                    description=f"Low GPU utilization ({gpu_util:.1f}%)",
                    expected_improvement="1.5-3x speedup",
                    implementation_hint="Increase batch size or parallelize multiple operations",
                    current_time_ms=stats["total_time_ms"],
                    estimated_time_ms=stats["total_time_ms"] * 0.6,  # Estimate 1.7x improvement
                    potential_speedup=1.7,
                )
            )

    def get_suggestions(
        self, priority: Optional[Priority] = None, top_n: Optional[int] = None
    ) -> List[OptimizationSuggestion]:
        """
        Get optimization suggestions

        Args:
            priority: Filter by priority level
            top_n: Return only top N suggestions by potential speedup

        Returns:
            List of optimization suggestions
        """
        suggestions = self.suggestions

        if priority:
            suggestions = [s for s in suggestions if s.priority == priority]

        # Sort by potential speedup (descending)
        suggestions.sort(key=lambda s: s.potential_speedup, reverse=True)

        return suggestions[:top_n] if top_n else suggestions

    def get_critical_suggestions(self) -> List[OptimizationSuggestion]:
        """Get critical priority suggestions"""
        return self.get_suggestions(priority=Priority.CRITICAL)

    def print_suggestions(self, top_n: int = 10, show_proofs: bool = False):
        """Print optimization suggestions"""
        suggestions = self.get_suggestions(top_n=top_n)

        if not suggestions:
            print("\nNo optimization suggestions - code is already well optimized!")
            return

        print(f"\n{'=' * 80}")
        print(f"TOP {len(suggestions)} OPTIMIZATION SUGGESTIONS")
        print(f"{'=' * 80}")

        total_potential_improvement = 0.0

        for i, sugg in enumerate(suggestions, 1):
            print(f"\n[{i}] {sugg.operation} ({sugg.priority.value.upper()})")
            print(f"  Type: {sugg.type.value}")
            print(f"  Issue: {sugg.description}")
            print(f"  Expected: {sugg.expected_improvement}")
            print(
                f"  Potential: {sugg.potential_speedup:.1f}x speedup "
                f"({sugg.current_time_ms:.2f}ms -> {sugg.estimated_time_ms:.2f}ms)"
            )
            print(f"  How to: {sugg.implementation_hint}")

            # Show transformation information if available
            if sugg.transformation_rule:
                print(f"\n  Transformation: {sugg.transformation_rule}")
                if show_proofs and sugg.formal_theorem:
                    print(f"  Theorem: {sugg.formal_theorem}")
                    if sugg.assumptions:
                        print("  Assumptions:")
                        for assumption in sugg.assumptions:
                            print(f"    - {assumption}")
                    if sugg.invariants:
                        print("  Guarantees:")
                        for invariant in sugg.invariants:
                            print(f"    ✓ {invariant}")

            total_potential_improvement += sugg.current_time_ms - sugg.estimated_time_ms

        print(f"\n{'=' * 80}")
        print(f"Total potential time savings: {total_potential_improvement:.2f}ms")
        if any(s.transformation_rule for s in suggestions):
            print("Note: Use show_proofs=True to see formal transformation proofs")
        print(f"{'=' * 80}\n")

    def print_critical_suggestions(self):
        """Print only critical suggestions"""
        critical = self.get_critical_suggestions()

        if not critical:
            print("\nNo critical optimization suggestions!")
            return

        print(f"\n{'=' * 80}")
        print("CRITICAL OPTIMIZATION SUGGESTIONS")
        print(f"{'=' * 80}")

        for i, sugg in enumerate(critical, 1):
            print(f"\n[{i}] {sugg.operation}")
            print(f"  {sugg.description}")
            print(f"  Expected: {sugg.expected_improvement}")
            print(f"  How to: {sugg.implementation_hint}")

        print(f"\n{'=' * 80}\n")

    def print_transformation_report(self, context: Dict):
        """Print detailed transformation analysis for given context"""
        catalog = _get_transformation_catalog()
        if not catalog:
            print("Transformation catalog not available")
            return

        print(catalog.generate_transformation_report(context))

    def export_suggestions(self, filepath: str):
        """Export suggestions to JSON"""
        import json

        data = {
            "total_suggestions": len(self.suggestions),
            "by_priority": {
                "critical": len([s for s in self.suggestions if s.priority == Priority.CRITICAL]),
                "high": len([s for s in self.suggestions if s.priority == Priority.HIGH]),
                "medium": len([s for s in self.suggestions if s.priority == Priority.MEDIUM]),
                "low": len([s for s in self.suggestions if s.priority == Priority.LOW]),
            },
            "suggestions": [
                {
                    "operation": s.operation,
                    "type": s.type.value,
                    "priority": s.priority.value,
                    "description": s.description,
                    "expected_improvement": s.expected_improvement,
                    "implementation_hint": s.implementation_hint,
                    "current_time_ms": s.current_time_ms,
                    "estimated_time_ms": s.estimated_time_ms,
                    "potential_speedup": s.potential_speedup,
                    "transformation_rule": s.transformation_rule,
                    "formal_theorem": s.formal_theorem,
                    "proof_sketch": s.proof_sketch,
                    "invariants": s.invariants,
                    "assumptions": s.assumptions,
                }
                for s in self.suggestions
            ],
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Exported optimization suggestions to {filepath}")
