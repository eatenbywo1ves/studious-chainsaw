"""
Profiler Complexity Tracking - Hierarchical Complexity Metrics
Inspired by Mernithian multiplicative iteration system (⊕→⊘→⊗→⊙)

Tracks algorithmic and operational complexity with 4-tier hierarchy:
- Tier 0 (Trivial): O(1), O(log n) - Base score 1
- Tier 1 (Linear): O(n), O(n log n) - Score 10
- Tier 2 (Polynomial): O(n²), O(n³) - Score 100
- Tier 3 (Exponential): O(2ⁿ), O(n!) - Score 1000
"""

import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json
import math

logger = logging.getLogger(__name__)


class ComplexityTier(Enum):
    """
    4-tier complexity hierarchy inspired by Mernithian iteration system
    Each tier represents ~10x increase in computational cost
    """
    TRIVIAL = 0      # ⊕ O(1), O(log n)
    LINEAR = 1       # ⊘ O(n), O(n log n)
    POLYNOMIAL = 2   # ⊗ O(n²), O(n³)
    EXPONENTIAL = 3  # ⊙ O(2ⁿ), O(n!)


class ComplexityClass(Enum):
    """Computational complexity classes"""
    P = "P"                    # Polynomial time
    NP = "NP"                  # Nondeterministic polynomial
    NP_COMPLETE = "NP-complete"
    NP_HARD = "NP-hard"
    PSPACE = "PSPACE"          # Polynomial space
    EXPTIME = "EXPTIME"        # Exponential time


@dataclass
class AlgorithmicComplexity:
    """
    Big-O complexity classification for an algorithm
    """
    time_complexity: str              # e.g., "O(n²)"
    space_complexity: str             # e.g., "O(n)"
    tier: ComplexityTier              # 0-3 (Trivial to Exponential)
    complexity_class: ComplexityClass

    # Parallelization properties
    is_parallelizable: bool
    parallelism_degree: int           # Max parallel units (1 = serial)

    # Algorithm characteristics
    deterministic: bool = True
    has_recursion: bool = False
    recursion_depth: int = 0

    def to_dict(self) -> Dict:
        """Export to dictionary"""
        return {
            'time_complexity': self.time_complexity,
            'space_complexity': self.space_complexity,
            'tier': self.tier.value,
            'tier_name': self.tier.name,
            'complexity_class': self.complexity_class.value,
            'is_parallelizable': self.is_parallelizable,
            'parallelism_degree': self.parallelism_degree,
            'deterministic': self.deterministic,
            'has_recursion': self.has_recursion,
            'recursion_depth': self.recursion_depth
        }


@dataclass
class OperationalComplexity:
    """
    Runtime operational characteristics
    Measured from actual execution
    """
    data_size_mb: float
    flop_count: int                   # Floating point operations
    memory_ops: int                   # Memory read/write operations
    branching_factor: int             # Conditional branches
    loop_depth: int                   # Nested loop levels
    dependency_graph_size: int        # Data dependency complexity

    # Derived metrics
    flop_per_byte: float              # Compute intensity
    memory_bandwidth_utilization: float  # % of peak bandwidth

    def to_dict(self) -> Dict:
        """Export to dictionary"""
        return {
            'data_size_mb': self.data_size_mb,
            'flop_count': self.flop_count,
            'memory_ops': self.memory_ops,
            'branching_factor': self.branching_factor,
            'loop_depth': self.loop_depth,
            'dependency_graph_size': self.dependency_graph_size,
            'flop_per_byte': self.flop_per_byte,
            'memory_bandwidth_utilization': self.memory_bandwidth_utilization
        }


@dataclass
class TransformationComplexity:
    """
    Tracks complexity evolution through transformation pipeline
    """
    original_tier: ComplexityTier
    current_tier: ComplexityTier
    transformation_chain: List[str] = field(default_factory=list)
    chain_depth: int = 0
    complexity_reduction: float = 0.0  # Ratio: (original - current) / original
    semantic_equivalence_proof: Optional[str] = None

    def to_dict(self) -> Dict:
        """Export to dictionary"""
        return {
            'original_tier': self.original_tier.value,
            'current_tier': self.current_tier.value,
            'transformation_chain': self.transformation_chain,
            'chain_depth': self.chain_depth,
            'complexity_reduction': self.complexity_reduction,
            'semantic_equivalence_proof': self.semantic_equivalence_proof
        }


@dataclass
class ComplexityScore:
    """
    Unified complexity scoring with multiplicative hierarchy
    """
    # Component scores
    algorithmic_score: float          # Based on Big-O tier
    operational_score: float          # Based on runtime metrics
    memory_score: float               # Memory complexity component
    parallelism_score: float          # Parallelization effectiveness

    # Composite metrics
    total_score: float                # Weighted combination
    normalized_score: float           # 0-1 normalized
    complexity_grade: str             # "A", "B", "C", "D", "F"

    # Context
    tier: ComplexityTier
    bottleneck: str                   # "compute", "memory", "transfer", "none"

    def to_dict(self) -> Dict:
        """Export to dictionary"""
        return {
            'algorithmic_score': self.algorithmic_score,
            'operational_score': self.operational_score,
            'memory_score': self.memory_score,
            'parallelism_score': self.parallelism_score,
            'total_score': self.total_score,
            'normalized_score': self.normalized_score,
            'complexity_grade': self.complexity_grade,
            'tier': self.tier.value,
            'tier_name': self.tier.name,
            'bottleneck': self.bottleneck
        }


class ComplexityAnalyzer:
    """
    Analyzes and classifies operation complexity
    """

    def __init__(self):
        """Initialize complexity analyzer"""
        self.operation_complexity_map = self._build_operation_map()
        self.tier_base_scores = {
            ComplexityTier.TRIVIAL: 1.0,
            ComplexityTier.LINEAR: 10.0,
            ComplexityTier.POLYNOMIAL: 100.0,
            ComplexityTier.EXPONENTIAL: 1000.0
        }

    def _build_operation_map(self) -> Dict[str, AlgorithmicComplexity]:
        """Build map of known operations to their complexities"""
        return {
            # Trivial operations - O(1), O(log n)
            'hash_lookup': AlgorithmicComplexity(
                time_complexity="O(1)",
                space_complexity="O(1)",
                tier=ComplexityTier.TRIVIAL,
                complexity_class=ComplexityClass.P,
                is_parallelizable=True,
                parallelism_degree=1000
            ),
            'array_access': AlgorithmicComplexity(
                time_complexity="O(1)",
                space_complexity="O(1)",
                tier=ComplexityTier.TRIVIAL,
                complexity_class=ComplexityClass.P,
                is_parallelizable=True,
                parallelism_degree=1000
            ),
            'xor_transform': AlgorithmicComplexity(
                time_complexity="O(n)",
                space_complexity="O(1)",
                tier=ComplexityTier.LINEAR,
                complexity_class=ComplexityClass.P,
                is_parallelizable=True,
                parallelism_degree=1000
            ),

            # Linear operations - O(n), O(n log n)
            'array_scan': AlgorithmicComplexity(
                time_complexity="O(n)",
                space_complexity="O(1)",
                tier=ComplexityTier.LINEAR,
                complexity_class=ComplexityClass.P,
                is_parallelizable=True,
                parallelism_degree=1000
            ),
            'quicksort': AlgorithmicComplexity(
                time_complexity="O(n log n)",
                space_complexity="O(log n)",
                tier=ComplexityTier.LINEAR,
                complexity_class=ComplexityClass.P,
                is_parallelizable=True,
                parallelism_degree=100,
                has_recursion=True,
                recursion_depth=10
            ),
            'merge_sort': AlgorithmicComplexity(
                time_complexity="O(n log n)",
                space_complexity="O(n)",
                tier=ComplexityTier.LINEAR,
                complexity_class=ComplexityClass.P,
                is_parallelizable=True,
                parallelism_degree=100,
                has_recursion=True,
                recursion_depth=10
            ),

            # Polynomial operations - O(n²), O(n³)
            'matrix_multiply': AlgorithmicComplexity(
                time_complexity="O(n³)",
                space_complexity="O(n²)",
                tier=ComplexityTier.POLYNOMIAL,
                complexity_class=ComplexityClass.P,
                is_parallelizable=True,
                parallelism_degree=10000
            ),
            'bubble_sort': AlgorithmicComplexity(
                time_complexity="O(n²)",
                space_complexity="O(1)",
                tier=ComplexityTier.POLYNOMIAL,
                complexity_class=ComplexityClass.P,
                is_parallelizable=False,
                parallelism_degree=1
            ),
            'nested_loop': AlgorithmicComplexity(
                time_complexity="O(n²)",
                space_complexity="O(1)",
                tier=ComplexityTier.POLYNOMIAL,
                complexity_class=ComplexityClass.P,
                is_parallelizable=True,
                parallelism_degree=100
            ),

            # Exponential operations - O(2ⁿ), O(n!)
            'graph_search': AlgorithmicComplexity(
                time_complexity="O(2ⁿ)",
                space_complexity="O(n)",
                tier=ComplexityTier.EXPONENTIAL,
                complexity_class=ComplexityClass.NP,
                is_parallelizable=True,
                parallelism_degree=1000,
                has_recursion=True,
                recursion_depth=20
            ),
            'traveling_salesman': AlgorithmicComplexity(
                time_complexity="O(n!)",
                space_complexity="O(n)",
                tier=ComplexityTier.EXPONENTIAL,
                complexity_class=ComplexityClass.NP_COMPLETE,
                is_parallelizable=True,
                parallelism_degree=1000,
                deterministic=False
            ),
            'subset_sum': AlgorithmicComplexity(
                time_complexity="O(2ⁿ)",
                space_complexity="O(n)",
                tier=ComplexityTier.EXPONENTIAL,
                complexity_class=ComplexityClass.NP_COMPLETE,
                is_parallelizable=True,
                parallelism_degree=1000
            )
        }

    def classify_algorithm(self, operation_name: str,
                          metadata: Optional[Dict] = None) -> AlgorithmicComplexity:
        """
        Classify algorithmic complexity from operation name and metadata

        Args:
            operation_name: Name of the operation
            metadata: Optional metadata with hints

        Returns:
            AlgorithmicComplexity descriptor
        """
        # Try exact match first
        if operation_name in self.operation_complexity_map:
            return self.operation_complexity_map[operation_name]

        # Try pattern matching
        operation_lower = operation_name.lower()

        # Matrix operations
        if any(keyword in operation_lower for keyword in ['matrix', 'gemm', 'matmul']):
            return AlgorithmicComplexity(
                time_complexity="O(n³)",
                space_complexity="O(n²)",
                tier=ComplexityTier.POLYNOMIAL,
                complexity_class=ComplexityClass.P,
                is_parallelizable=True,
                parallelism_degree=10000
            )

        # Sort operations
        if any(keyword in operation_lower for keyword in ['sort', 'order']):
            return AlgorithmicComplexity(
                time_complexity="O(n log n)",
                space_complexity="O(n)",
                tier=ComplexityTier.LINEAR,
                complexity_class=ComplexityClass.P,
                is_parallelizable=True,
                parallelism_degree=100
            )

        # Search operations
        if any(keyword in operation_lower for keyword in ['search', 'find', 'lookup']):
            return AlgorithmicComplexity(
                time_complexity="O(log n)",
                space_complexity="O(1)",
                tier=ComplexityTier.TRIVIAL,
                complexity_class=ComplexityClass.P,
                is_parallelizable=True,
                parallelism_degree=1000
            )

        # Graph operations
        if any(keyword in operation_lower for keyword in ['graph', 'tree', 'path']):
            return AlgorithmicComplexity(
                time_complexity="O(n²)",
                space_complexity="O(n)",
                tier=ComplexityTier.POLYNOMIAL,
                complexity_class=ComplexityClass.P,
                is_parallelizable=True,
                parallelism_degree=100
            )

        # Transform operations
        if any(keyword in operation_lower for keyword in ['transform', 'convert', 'xor']):
            return AlgorithmicComplexity(
                time_complexity="O(n)",
                space_complexity="O(1)",
                tier=ComplexityTier.LINEAR,
                complexity_class=ComplexityClass.P,
                is_parallelizable=True,
                parallelism_degree=1000
            )

        # Default: assume linear
        logger.warning(f"Unknown operation '{operation_name}', assuming O(n)")
        return AlgorithmicComplexity(
            time_complexity="O(n)",
            space_complexity="O(n)",
            tier=ComplexityTier.LINEAR,
            complexity_class=ComplexityClass.P,
            is_parallelizable=True,
            parallelism_degree=10
        )

    def compute_operational_complexity(self,
                                      duration_ms: float,
                                      memory_mb: float,
                                      device: str,
                                      metadata: Optional[Dict] = None) -> OperationalComplexity:
        """
        Compute operational complexity from runtime metrics

        Args:
            duration_ms: Execution duration
            memory_mb: Memory usage
            device: Execution device
            metadata: Optional additional metrics

        Returns:
            OperationalComplexity descriptor
        """
        metadata = metadata or {}

        # Estimate FLOP count from duration (rough heuristic)
        # Assume ~1 TFLOPS for GPU, ~10 GFLOPS for CPU
        peak_flops = 1e12 if device == 'gpu' else 1e10
        flop_count = int(peak_flops * (duration_ms / 1000.0) * 0.5)  # 50% utilization

        # Estimate memory operations
        # Assume ~500 GB/s for GPU, ~50 GB/s for CPU
        peak_bandwidth = 500e9 if device == 'gpu' else 50e9
        memory_ops = int((memory_mb * 1e6) / 8)  # Rough estimate

        # Compute FLOP/byte ratio
        flop_per_byte = flop_count / max(memory_mb * 1e6, 1.0)

        # Estimate bandwidth utilization
        actual_bandwidth = (memory_mb * 1e6) / (duration_ms / 1000.0)
        memory_bandwidth_utilization = min(actual_bandwidth / peak_bandwidth * 100, 100.0)

        # Extract or estimate other metrics
        branching_factor = metadata.get('branching_factor', 1)
        loop_depth = metadata.get('loop_depth', 1)
        dependency_graph_size = metadata.get('dependency_graph_size', 10)

        return OperationalComplexity(
            data_size_mb=memory_mb,
            flop_count=flop_count,
            memory_ops=memory_ops,
            branching_factor=branching_factor,
            loop_depth=loop_depth,
            dependency_graph_size=dependency_graph_size,
            flop_per_byte=flop_per_byte,
            memory_bandwidth_utilization=memory_bandwidth_utilization
        )

    def infer_complexity_from_metrics(self,
                                     duration_ms: float,
                                     data_size_mb: float) -> ComplexityTier:
        """
        Infer algorithmic complexity tier from runtime scaling

        Args:
            duration_ms: Execution duration
            data_size_mb: Input data size

        Returns:
            Inferred ComplexityTier
        """
        # Very fast operations with tiny data are likely trivial
        if duration_ms < 1.0 and data_size_mb < 0.01:
            return ComplexityTier.TRIVIAL

        # If data is very small, can't infer much - assume trivial
        if data_size_mb < 0.001:
            return ComplexityTier.TRIVIAL

        # Compute time per MB
        time_per_mb = duration_ms / max(data_size_mb, 0.001)

        # Classify based on time per MB scaling
        # Adjusted thresholds to be more reasonable
        if time_per_mb < 5.0:
            return ComplexityTier.TRIVIAL      # Sub-linear or O(1), O(log n)
        elif time_per_mb < 15.0:
            return ComplexityTier.LINEAR       # Linear scaling
        elif time_per_mb < 150.0:
            return ComplexityTier.POLYNOMIAL   # Polynomial scaling
        else:
            return ComplexityTier.EXPONENTIAL  # Exponential scaling

    def compute_complexity_score(self,
                                algorithmic: AlgorithmicComplexity,
                                operational: OperationalComplexity) -> ComplexityScore:
        """
        Compute unified complexity score with multiplicative hierarchy

        Args:
            algorithmic: Algorithmic complexity
            operational: Operational complexity

        Returns:
            ComplexityScore with all components
        """
        # Base algorithmic score from tier
        base_score = self.tier_base_scores[algorithmic.tier]

        # Apply data size multiplier
        data_multiplier = max(operational.data_size_mb / 10.0, 0.1)  # Normalize to 10MB
        algorithmic_score = base_score * data_multiplier

        # Operational score based on FLOP count (normalized to 1 GFLOP)
        operational_score = operational.flop_count / 1e9

        # Memory score based on memory usage (normalized to 100MB)
        memory_score = operational.data_size_mb / 100.0

        # Parallelism score (higher is better - inverted)
        if algorithmic.is_parallelizable:
            parallelism_effectiveness = min(algorithmic.parallelism_degree / 100.0, 10.0)
            parallelism_score = base_score / max(parallelism_effectiveness, 1.0)
        else:
            parallelism_score = base_score * 2.0  # Penalty for non-parallelizable

        # Total score (weighted combination)
        total_score = (
            algorithmic_score * 0.4 +
            operational_score * 0.3 +
            memory_score * 0.2 +
            parallelism_score * 0.1
        )

        # Normalize to 0-1 range (log scale)
        max_score = 10000.0  # Arbitrary maximum
        normalized_score = min(math.log10(total_score + 1) / math.log10(max_score), 1.0)

        # Assign grade
        if normalized_score < 0.2:
            grade = "A"
        elif normalized_score < 0.4:
            grade = "B"
        elif normalized_score < 0.6:
            grade = "C"
        elif normalized_score < 0.8:
            grade = "D"
        else:
            grade = "F"

        # Identify bottleneck
        if operational.flop_per_byte > 10:
            bottleneck = "compute"
        elif operational.flop_per_byte < 2:
            bottleneck = "memory"
        elif operational.memory_bandwidth_utilization > 80:
            bottleneck = "transfer"
        else:
            bottleneck = "none"

        return ComplexityScore(
            algorithmic_score=algorithmic_score,
            operational_score=operational_score,
            memory_score=memory_score,
            parallelism_score=parallelism_score,
            total_score=total_score,
            normalized_score=normalized_score,
            complexity_grade=grade,
            tier=algorithmic.tier,
            bottleneck=bottleneck
        )

    def track_transformation_complexity(self,
                                       original: ComplexityScore,
                                       transformation_name: str,
                                       new_score: ComplexityScore,
                                       existing_chain: Optional[TransformationComplexity] = None) -> TransformationComplexity:
        """
        Track complexity changes through transformation pipeline

        Args:
            original: Original complexity score
            transformation_name: Name of transformation applied
            new_score: New complexity score after transformation
            existing_chain: Existing transformation chain (if any)

        Returns:
            Updated TransformationComplexity
        """
        if existing_chain:
            # Extend existing chain
            chain = existing_chain.transformation_chain + [transformation_name]
            original_tier = existing_chain.original_tier
        else:
            # Start new chain
            chain = [transformation_name]
            original_tier = original.tier

        # Compute complexity reduction
        if original.total_score > 0:
            reduction = (original.total_score - new_score.total_score) / original.total_score
        else:
            reduction = 0.0

        return TransformationComplexity(
            original_tier=original_tier,
            current_tier=new_score.tier,
            transformation_chain=chain,
            chain_depth=len(chain),
            complexity_reduction=reduction
        )


class ComplexityHierarchy:
    """
    Manages hierarchical complexity relationships and bottleneck analysis
    """

    def __init__(self, analyzer: ComplexityAnalyzer):
        """Initialize hierarchy manager"""
        self.analyzer = analyzer

    def build_hierarchy(self, operations: List[Dict]) -> Dict:
        """
        Build complexity hierarchy tree from operations

        Args:
            operations: List of operation dictionaries with complexity data

        Returns:
            Hierarchy dictionary organized by tier
        """
        hierarchy = {
            'tiers': {
                ComplexityTier.TRIVIAL.value: [],
                ComplexityTier.LINEAR.value: [],
                ComplexityTier.POLYNOMIAL.value: [],
                ComplexityTier.EXPONENTIAL.value: []
            },
            'total_operations': len(operations),
            'total_complexity_score': 0.0,
            'average_complexity_score': 0.0
        }

        total_score = 0.0

        for op in operations:
            complexity_score = op.get('complexity_score', {})
            tier = complexity_score.get('tier', 0)
            score = complexity_score.get('total_score', 0.0)

            tier_key = tier
            hierarchy['tiers'][tier_key].append({
                'operation': op.get('operation', 'unknown'),
                'score': score,
                'grade': complexity_score.get('complexity_grade', 'N/A'),
                'bottleneck': complexity_score.get('bottleneck', 'none')
            })

            total_score += score

        hierarchy['total_complexity_score'] = total_score
        hierarchy['average_complexity_score'] = total_score / max(len(operations), 1)

        # Sort each tier by score (descending)
        for tier_ops in hierarchy['tiers'].values():
            tier_ops.sort(key=lambda x: x['score'], reverse=True)

        return hierarchy

    def find_complexity_bottlenecks(self,
                                   hierarchy: Dict,
                                   threshold: float = 100.0) -> List[Dict]:
        """
        Identify operations above complexity threshold

        Args:
            hierarchy: Complexity hierarchy from build_hierarchy()
            threshold: Complexity score threshold

        Returns:
            List of bottleneck operations
        """
        bottlenecks = []

        for tier, ops in hierarchy['tiers'].items():
            for op in ops:
                if op['score'] >= threshold:
                    bottlenecks.append({
                        'operation': op['operation'],
                        'tier': tier,
                        'score': op['score'],
                        'grade': op['grade'],
                        'bottleneck': op['bottleneck']
                    })

        # Sort by score (descending)
        bottlenecks.sort(key=lambda x: x['score'], reverse=True)

        return bottlenecks

    def suggest_complexity_reductions(self,
                                     operation: str,
                                     complexity: ComplexityScore) -> List[str]:
        """
        Suggest ways to reduce complexity

        Args:
            operation: Operation name
            complexity: Current complexity score

        Returns:
            List of suggestion strings
        """
        suggestions = []

        # Tier-based suggestions
        if complexity.tier == ComplexityTier.EXPONENTIAL:
            suggestions.append("Consider algorithmic optimization (e.g., dynamic programming, pruning)")
            suggestions.append("Use approximation algorithms for NP-complete problems")
            suggestions.append("Consider heuristic-based search with early termination")

        if complexity.tier == ComplexityTier.POLYNOMIAL:
            suggestions.append("Consider batch fusion to amortize overhead")
            suggestions.append("Use GPU parallelization if not already applied")
            suggestions.append("Consider algorithmic improvements (e.g., Strassen for matrix multiply)")

        # Bottleneck-specific suggestions
        if complexity.bottleneck == "compute":
            suggestions.append("Route to GPU for higher compute throughput")
            suggestions.append("Consider precision reduction (FP64 → FP32)")

        if complexity.bottleneck == "memory":
            suggestions.append("Use memory pooling to reduce allocation overhead")
            suggestions.append("Optimize data layout for better cache locality")

        if complexity.bottleneck == "transfer":
            suggestions.append("Route small operations to CPU to avoid transfer overhead")
            suggestions.append("Use kernel fusion to reduce transfer count")

        # Grade-based suggestions
        if complexity.complexity_grade in ['D', 'F']:
            suggestions.append("High complexity detected - prioritize optimization")

        return suggestions


class ComplexityVisualizer:
    """
    Export and visualize complexity data
    """

    def export_complexity_tree(self, hierarchy: Dict, filepath: str) -> None:
        """
        Export complexity hierarchy as JSON tree

        Args:
            hierarchy: Complexity hierarchy from build_hierarchy()
            filepath: Output JSON file path
        """
        with open(filepath, 'w') as f:
            json.dump(hierarchy, f, indent=2)

        logger.info(f"Exported complexity tree to {filepath}")

    def generate_complexity_heatmap(self, operations: List[Dict]) -> Dict:
        """
        Generate data for complexity heatmap visualization

        Args:
            operations: List of operation dictionaries

        Returns:
            Heatmap data dictionary
        """
        heatmap = {
            'operations': [],
            'scores': [],
            'tiers': [],
            'grades': []
        }

        for op in operations:
            complexity_score = op.get('complexity_score', {})
            heatmap['operations'].append(op.get('operation', 'unknown'))
            heatmap['scores'].append(complexity_score.get('total_score', 0.0))
            heatmap['tiers'].append(complexity_score.get('tier', 0))
            heatmap['grades'].append(complexity_score.get('complexity_grade', 'N/A'))

        return heatmap


# Singleton instance
_complexity_analyzer = None


def get_complexity_analyzer() -> ComplexityAnalyzer:
    """Get singleton complexity analyzer"""
    global _complexity_analyzer
    if _complexity_analyzer is None:
        _complexity_analyzer = ComplexityAnalyzer()
    return _complexity_analyzer
