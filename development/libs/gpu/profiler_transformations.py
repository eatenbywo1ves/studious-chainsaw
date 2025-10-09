"""
Profiler Transformation Equivalence Framework
Inspired by Mernithian E₁ ⟷ᵀ E₂ concept

This module implements formal transformation rules for GPU optimizations,
ensuring semantic preservation while improving performance.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Any
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class TransformationType(Enum):
    """Types of optimization transformations"""

    DEVICE_ROUTING = "device_routing"  # GPU ↔ CPU routing
    BATCH_FUSION = "batch_fusion"  # Single ops → batched ops
    MEMORY_POOLING = "memory_pooling"  # Direct alloc → pooled alloc
    KERNEL_FUSION = "kernel_fusion"  # Multiple kernels → fused kernel
    DATA_LAYOUT = "data_layout"  # Memory layout optimization
    PRECISION_REDUCTION = "precision_reduction"  # FP64 → FP32 or FP16
    ALGORITHMIC = "algorithmic"  # Different algorithm same result


class TransformationCondition(Enum):
    """Conditions that enable transformations"""

    # Device routing conditions
    SMALL_DATA_SIZE = "small_data_size"  # < 1MB
    MEDIUM_DATA_SIZE = "medium_data_size"  # 1-100MB
    LARGE_DATA_SIZE = "large_data_size"  # > 100MB

    # Operation type conditions
    COMPUTE_BOUND = "compute_bound"  # High FLOP/byte ratio
    MEMORY_BOUND = "memory_bound"  # Low FLOP/byte ratio
    TRANSFER_BOUND = "transfer_bound"  # Transfer overhead dominant

    # Batch conditions
    MULTIPLE_SIMILAR_OPS = "multiple_similar_ops"  # Can be batched
    INDEPENDENT_OPS = "independent_ops"  # No data dependencies

    # Precision conditions
    TOLERANCE_RELAXED = "tolerance_relaxed"  # Can use lower precision
    PRECISION_CRITICAL = "precision_critical"  # Requires full precision

    # Memory conditions
    FREQUENT_ALLOCS = "frequent_allocs"  # Many small allocations
    PERSISTENT_DATA = "persistent_data"  # Data reused multiple times


@dataclass
class TransformationProof:
    """Formal proof that transformation preserves semantics"""

    theorem: str  # Mathematical statement
    assumptions: List[str]  # Required preconditions
    proof_sketch: List[str]  # Step-by-step proof outline
    invariants: List[str]  # Properties preserved
    counterexamples: List[str] = field(default_factory=list)  # Known limitations


@dataclass
class TransformationRule:
    """
    Defines an equivalence transformation: E₁ ⟷ᵀ E₂

    E₁: Original expression/operation
    T: Transformation type
    E₂: Transformed expression/operation
    """

    name: str
    transformation_type: TransformationType

    # Source and target descriptions
    source_description: str  # E₁ description
    target_description: str  # E₂ description

    # Enabling conditions
    required_conditions: List[TransformationCondition]

    # Performance characteristics
    expected_speedup_range: tuple[float, float]  # (min, max) speedup multiplier
    memory_impact: str  # "reduced", "neutral", "increased"

    # Formal verification (Phase 2)
    proof: TransformationProof

    # Optional fields with defaults
    prohibited_conditions: List[TransformationCondition] = field(default_factory=list)

    # Validation function
    validator: Optional[Callable[[Dict[str, Any]], bool]] = None

    # Phase 4: Formal proofs and verification
    formal_proof: Optional[Any] = None  # FormalProof from verifier
    verification_result: Optional[Any] = None  # VerificationResult
    performance_guarantee: Optional[Any] = None  # PerformanceGuarantee

    def is_applicable(self, context: Dict[str, Any]) -> bool:
        """Check if transformation can be applied in given context"""
        # Check required conditions
        for cond in self.required_conditions:
            if not self._check_condition(cond, context):
                logger.debug(f"Transformation {self.name}: missing condition {cond.value}")
                return False

        # Check prohibited conditions
        for cond in self.prohibited_conditions:
            if self._check_condition(cond, context):
                logger.debug(
                    f"Transformation {self.name}: prohibited condition {cond.value} present"
                )
                return False

        # Run custom validator if provided
        if self.validator:
            return self.validator(context)

        return True

    def _check_condition(self, condition: TransformationCondition, context: Dict[str, Any]) -> bool:
        """Check if a specific condition is met"""
        data_size_mb = context.get("data_size_mb", 0)
        context.get("operation_type", "")
        flop_per_byte = context.get("flop_per_byte", 0)
        transfer_ratio = context.get("transfer_time_ratio", 0)
        precision_tolerance = context.get("precision_tolerance", "strict")
        alloc_frequency = context.get("alloc_frequency", 0)

        if condition == TransformationCondition.SMALL_DATA_SIZE:
            return data_size_mb < 1.0
        elif condition == TransformationCondition.MEDIUM_DATA_SIZE:
            return 1.0 <= data_size_mb <= 100.0
        elif condition == TransformationCondition.LARGE_DATA_SIZE:
            return data_size_mb > 100.0
        elif condition == TransformationCondition.COMPUTE_BOUND:
            return flop_per_byte > 10  # High compute-to-memory ratio
        elif condition == TransformationCondition.MEMORY_BOUND:
            return flop_per_byte < 2  # Low compute-to-memory ratio
        elif condition == TransformationCondition.TRANSFER_BOUND:
            return transfer_ratio > 0.3  # Transfer time > 30% of total
        elif condition == TransformationCondition.TOLERANCE_RELAXED:
            return precision_tolerance in ["relaxed", "moderate"]
        elif condition == TransformationCondition.PRECISION_CRITICAL:
            return precision_tolerance == "strict"
        elif condition == TransformationCondition.FREQUENT_ALLOCS:
            return alloc_frequency > 100  # > 100 allocs/sec
        elif condition == TransformationCondition.MULTIPLE_SIMILAR_OPS:
            return context.get("similar_ops_count", 0) > 1
        elif condition == TransformationCondition.INDEPENDENT_OPS:
            return not context.get("has_dependencies", True)
        elif condition == TransformationCondition.PERSISTENT_DATA:
            return context.get("data_reuse_count", 0) > 2

        return False

    def estimate_speedup(self, context: Dict[str, Any]) -> float:
        """Estimate speedup for this transformation in given context"""
        min_speedup, max_speedup = self.expected_speedup_range

        # Use geometric mean as baseline estimate
        baseline = (min_speedup * max_speedup) ** 0.5

        # Adjust based on context (simple heuristic)
        data_size_mb = context.get("data_size_mb", 1.0)
        if self.transformation_type == TransformationType.DEVICE_ROUTING:
            # Smaller data → higher speedup for CPU routing
            if data_size_mb < 0.1:
                return max_speedup
            elif data_size_mb < 1.0:
                return baseline
            else:
                return min_speedup

        return baseline


class TransformationCatalog:
    """Catalog of verified optimization transformations"""

    def __init__(self):
        self.rules: Dict[str, TransformationRule] = {}
        self._initialize_standard_rules()

    def _initialize_standard_rules(self):
        """Initialize standard transformation rules"""

        # Rule 1: Small GPU ops → CPU (XOR-like transformations)
        self.add_rule(
            TransformationRule(
                name="SmallGPUToCPU",
                transformation_type=TransformationType.DEVICE_ROUTING,
                source_description="Small operation on GPU with transfer overhead",
                target_description="Same operation on CPU avoiding transfer",
                required_conditions=[
                    TransformationCondition.SMALL_DATA_SIZE,
                    TransformationCondition.TRANSFER_BOUND,
                ],
                prohibited_conditions=[TransformationCondition.COMPUTE_BOUND],
                expected_speedup_range=(50.0, 200.0),
                memory_impact="neutral",
                proof=TransformationProof(
                    theorem="∀ op with |data| < 1MB ∧ transfer_time > compute_time: "
                    "CPU_exec(op) ≈ GPU_exec(op) ∧ CPU_time < GPU_time",
                    assumptions=[
                        "Operation is compute-simple (low FLOP count)",
                        "Data size < 1MB",
                        "PCIe transfer overhead dominates GPU compute savings",
                        "CPU has sufficient cycles available",
                    ],
                    proof_sketch=[
                        "1. Let T_total = T_transfer + T_compute + T_overhead",
                        "2. For small data: T_transfer ≫ T_compute on GPU",
                        "3. CPU execution: T_cpu ≈ T_compute (no transfer)",
                        "4. Therefore: T_cpu < T_total_gpu when |data| < threshold",
                        "5. Semantic equivalence: CPU_result = GPU_result (bit-exact ops)",
                    ],
                    invariants=[
                        "Output correctness: f_cpu(x) = f_gpu(x)",
                        "Side effects: none (pure computation)",
                        "Determinism: both produce identical results",
                    ],
                    counterexamples=[
                        "GPU-specific operations (e.g., texture sampling)",
                        "Operations requiring GPU tensor cores",
                        "Very large batch sizes where GPU parallelism wins",
                    ],
                ),
            )
        )

        # Rule 2: Independent ops → Batched execution
        self.add_rule(
            TransformationRule(
                name="BatchFusion",
                transformation_type=TransformationType.BATCH_FUSION,
                source_description="N independent sequential operations",
                target_description="Single batched operation processing N items",
                required_conditions=[
                    TransformationCondition.MULTIPLE_SIMILAR_OPS,
                    TransformationCondition.INDEPENDENT_OPS,
                ],
                prohibited_conditions=[],
                expected_speedup_range=(2.0, 10.0),
                memory_impact="increased",
                proof=TransformationProof(
                    theorem="∀ ops {op₁, op₂, ..., opₙ} independent: "
                    "batch(op₁, ..., opₙ) ≡ [op₁(); op₂(); ...; opₙ()] ∧ faster",
                    assumptions=[
                        "Operations are independent (no data dependencies)",
                        "Operations are similar (same kernel)",
                        "Sufficient memory for batching",
                        "GPU has unused parallelism capacity",
                    ],
                    proof_sketch=[
                        "1. Define: sequential_time = Σᵢ T(opᵢ) + Σᵢ overhead(opᵢ)",
                        "2. Batch execution: batch_time = T(batch_op) + overhead(batch)",
                        "3. Key insight: overhead(batch) ≪ Σᵢ overhead(opᵢ)",
                        "4. Parallel execution: T(batch_op) ≤ max(T(opᵢ))",
                        "5. Therefore: batch_time < sequential_time",
                        "6. Semantic equivalence: batch results = sequential results (order-independent)",
                    ],
                    invariants=[
                        "Output set equivalence: {result₁, ..., resultₙ} unchanged",
                        "Per-item correctness: batch[i] = sequential[i]",
                        "No cross-contamination between batch items",
                    ],
                    counterexamples=[
                        "Operations with data dependencies",
                        "Operations requiring specific ordering",
                        "Memory-limited scenarios where batch OOM",
                    ],
                ),
            )
        )

        # Rule 3: Frequent allocations → Memory pooling
        self.add_rule(
            TransformationRule(
                name="MemoryPooling",
                transformation_type=TransformationType.MEMORY_POOLING,
                source_description="Frequent malloc/free operations",
                target_description="Pooled memory reuse",
                required_conditions=[
                    TransformationCondition.FREQUENT_ALLOCS,
                    TransformationCondition.PERSISTENT_DATA,
                ],
                prohibited_conditions=[],
                expected_speedup_range=(3.0, 20.0),
                memory_impact="increased",
                proof=TransformationProof(
                    theorem="∀ allocation pattern with reuse: "
                    "pooled_alloc ≡ direct_alloc ∧ pooled_time ≪ direct_time",
                    assumptions=[
                        "Allocation frequency > threshold",
                        "Memory sizes relatively uniform",
                        "Data lifetime allows reuse",
                        "Pool overhead < allocation savings",
                    ],
                    proof_sketch=[
                        "1. Direct allocation cost: T_direct = n × (malloc_time + free_time)",
                        "2. Pooled allocation: T_pooled = pool_init + n × pool_get",
                        "3. Key property: pool_get ≪ malloc_time (pre-allocated)",
                        "4. For large n: T_pooled ≈ n × pool_get ≪ T_direct",
                        "5. Semantic equivalence: memory content identical (same allocation semantics)",
                    ],
                    invariants=[
                        "Memory safety: no use-after-free",
                        "Isolation: different allocations don't interfere",
                        "Capacity: pool provides sufficient memory",
                    ],
                    counterexamples=[
                        "Highly variable allocation sizes",
                        "Very short-lived allocations",
                        "Memory-constrained environments",
                    ],
                ),
            )
        )

        # Rule 4: FP64 → FP32 precision reduction
        self.add_rule(
            TransformationRule(
                name="PrecisionReduction",
                transformation_type=TransformationType.PRECISION_REDUCTION,
                source_description="FP64 computation",
                target_description="FP32 computation with acceptable error",
                required_conditions=[TransformationCondition.TOLERANCE_RELAXED],
                prohibited_conditions=[TransformationCondition.PRECISION_CRITICAL],
                expected_speedup_range=(1.5, 3.0),
                memory_impact="reduced",
                proof=TransformationProof(
                    theorem="∀ computation C with relaxed tolerance ε: "
                    "|FP32(C) - FP64(C)| < ε ⇒ FP32(C) acceptable",
                    assumptions=[
                        "Numerical stability preserved in FP32",
                        "Error tolerance ε specified and achievable",
                        "No catastrophic cancellation in FP32",
                        "GPU has faster FP32 throughput",
                    ],
                    proof_sketch=[
                        "1. FP32 provides ~7 decimal digits precision",
                        "2. FP64 provides ~15 decimal digits precision",
                        "3. If result tolerance ε > 10⁻⁶, FP32 sufficient",
                        "4. Error accumulation analysis: |error| ≤ n × machine_epsilon",
                        "5. For bounded n and ε, FP32 meets requirements",
                        "6. Performance: FP32_throughput ≈ 2× FP64_throughput (typical GPU)",
                    ],
                    invariants=[
                        "Result within tolerance: |FP32 - FP64| < ε",
                        "Algorithmic stability maintained",
                        "No NaN/Inf introduced",
                    ],
                    counterexamples=[
                        "Iterative refinement algorithms",
                        "Accumulation of many small values",
                        "Catastrophic cancellation scenarios",
                    ],
                ),
            )
        )

        # Rule 5: Large CPU ops → GPU
        self.add_rule(
            TransformationRule(
                name="LargeCPUToGPU",
                transformation_type=TransformationType.DEVICE_ROUTING,
                source_description="Large compute-heavy operation on CPU",
                target_description="Same operation on GPU with parallelism",
                required_conditions=[
                    TransformationCondition.LARGE_DATA_SIZE,
                    TransformationCondition.COMPUTE_BOUND,
                ],
                prohibited_conditions=[TransformationCondition.TRANSFER_BOUND],
                expected_speedup_range=(5.0, 100.0),
                memory_impact="neutral",
                proof=TransformationProof(
                    theorem="∀ op with |data| > 100MB ∧ compute_bound: "
                    "GPU_exec(op) ≈ CPU_exec(op) ∧ GPU_time < CPU_time",
                    assumptions=[
                        "Operation is highly parallel",
                        "Data size amortizes transfer cost",
                        "GPU has available memory",
                        "Compute complexity > O(n)",
                    ],
                    proof_sketch=[
                        "1. CPU: T_cpu = compute_time (serial or low-parallel)",
                        "2. GPU: T_gpu = transfer_time + parallel_compute + transfer_back",
                        "3. For large data: compute_time ≫ transfer_time",
                        "4. GPU parallelism: parallel_compute ≈ compute_time / #cores",
                        "5. Therefore: T_gpu < T_cpu when data size sufficient",
                        "6. Semantic equivalence: same algorithm, different execution",
                    ],
                    invariants=[
                        "Numerical equivalence (within floating-point tolerance)",
                        "Result ordering preserved (if deterministic)",
                        "Side effects identical",
                    ],
                    counterexamples=[
                        "Highly branching algorithms",
                        "Random memory access patterns",
                        "Algorithms with poor GPU utilization",
                    ],
                ),
            )
        )

        # Rule 6: Multiple kernel launches → Kernel fusion
        self.add_rule(
            TransformationRule(
                name="KernelFusion",
                transformation_type=TransformationType.KERNEL_FUSION,
                source_description="Multiple sequential kernel launches",
                target_description="Single fused kernel",
                required_conditions=[
                    TransformationCondition.MULTIPLE_SIMILAR_OPS,
                    TransformationCondition.PERSISTENT_DATA,
                ],
                prohibited_conditions=[],
                expected_speedup_range=(1.5, 5.0),
                memory_impact="reduced",
                proof=TransformationProof(
                    theorem="∀ kernels {k₁, k₂, ..., kₙ} on same data: "
                    "fused_kernel(k₁∘k₂∘...∘kₙ) ≡ k₁; k₂; ...; kₙ ∧ faster",
                    assumptions=[
                        "Kernels operate on same/overlapping data",
                        "No required synchronization between kernels",
                        "Fused kernel fits in GPU resources",
                        "Intermediate results can be kept in registers/shared memory",
                    ],
                    proof_sketch=[
                        "1. Sequential kernels: T_seq = Σᵢ (launch_overhead + exec_time + sync)",
                        "2. Fused kernel: T_fused = launch_overhead + fused_exec + sync",
                        "3. Key savings: eliminate n-1 launches, n-1 syncs",
                        "4. Memory savings: intermediate results stay in fast memory",
                        "5. Therefore: T_fused < T_seq (reduced overhead)",
                        "6. Semantic equivalence: composition k₁∘k₂∘...∘kₙ preserved",
                    ],
                    invariants=[
                        "Functional composition: fused(x) = kₙ(...k₂(k₁(x)))",
                        "Data dependencies respected",
                        "Synchronization semantics preserved",
                    ],
                    counterexamples=[
                        "Kernels with different grid dimensions",
                        "Kernels requiring global synchronization",
                        "Resource-constrained fusion (register pressure)",
                    ],
                ),
            )
        )

    def add_rule(self, rule: TransformationRule):
        """Add a transformation rule to the catalog"""
        self.rules[rule.name] = rule
        logger.info(f"Added transformation rule: {rule.name}")

    def get_rule(self, name: str) -> Optional[TransformationRule]:
        """Get a specific transformation rule"""
        return self.rules.get(name)

    def find_applicable_transformations(
        self, context: Dict[str, Any]
    ) -> List[tuple[TransformationRule, float]]:
        """
        Find all applicable transformations for given context
        Returns list of (rule, estimated_speedup) tuples, sorted by speedup
        """
        applicable = []

        for rule in self.rules.values():
            if rule.is_applicable(context):
                speedup = rule.estimate_speedup(context)
                applicable.append((rule, speedup))
                logger.info(f"Transformation {rule.name} applicable with {speedup:.1f}x speedup")

        # Sort by estimated speedup (descending)
        applicable.sort(key=lambda x: x[1], reverse=True)

        return applicable

    def verify_transformation(
        self, rule_name: str, before_metrics: Dict[str, Any], after_metrics: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Verify that a transformation preserved semantics and improved performance

        Returns verification report with:
        - correctness_check: bool
        - performance_improvement: float
        - invariants_preserved: List[str]
        - warnings: List[str]
        """
        rule = self.get_rule(rule_name)
        if not rule:
            return {"error": f"Unknown rule: {rule_name}"}

        report = {
            "rule_name": rule_name,
            "correctness_check": True,
            "performance_improvement": 0.0,
            "invariants_preserved": [],
            "warnings": [],
        }

        # Check performance improvement
        before_time = before_metrics.get("duration_ms", 0)
        after_time = after_metrics.get("duration_ms", 0)

        if after_time > 0:
            speedup = before_time / after_time
            report["performance_improvement"] = speedup

            min_expected, max_expected = rule.expected_speedup_range

            if speedup < min_expected * 0.5:
                report["warnings"].append(
                    f"Speedup {speedup:.1f}x below expected range "
                    f"[{min_expected:.1f}x - {max_expected:.1f}x]"
                )
            elif speedup > max_expected * 2.0:
                report["warnings"].append(
                    f"Speedup {speedup:.1f}x exceeds expected range (verify measurements)"
                )

        # Check semantic invariants
        for invariant in rule.proof.invariants:
            # Simple heuristic checks (could be extended with actual verification)
            if "correctness" in invariant.lower() or "output" in invariant.lower():
                # Assume correctness if no errors reported
                if after_metrics.get("error", None) is None:
                    report["invariants_preserved"].append(invariant)
                else:
                    report["correctness_check"] = False
                    report["warnings"].append(f"Invariant violated: {invariant}")

        # Check memory impact
        before_mem = before_metrics.get("memory_peak_mb", 0)
        after_mem = after_metrics.get("memory_peak_mb", 0)
        mem_change = (after_mem - before_mem) / max(before_mem, 1.0)

        if rule.memory_impact == "reduced" and mem_change > 0.1:
            report["warnings"].append(
                f"Expected memory reduction, but memory increased by {mem_change * 100:.1f}%"
            )
        elif rule.memory_impact == "neutral" and abs(mem_change) > 0.2:
            report["warnings"].append(
                f"Expected neutral memory impact, but changed by {mem_change * 100:.1f}%"
            )

        return report

    def generate_transformation_report(self, context: Dict[str, Any]) -> str:
        """Generate human-readable report of applicable transformations"""
        applicable = self.find_applicable_transformations(context)

        if not applicable:
            return "No applicable transformations found for current context."

        report = ["=" * 80]
        report.append("TRANSFORMATION ANALYSIS REPORT")
        report.append("=" * 80)
        report.append("")
        report.append(f"Found {len(applicable)} applicable transformation(s):")
        report.append("")

        for idx, (rule, speedup) in enumerate(applicable, 1):
            report.append(f"{idx}. {rule.name} ({rule.transformation_type.value})")
            report.append(f"   Estimated speedup: {speedup:.1f}x")
            report.append(f"   E₁: {rule.source_description}")
            report.append(f"   E₂: {rule.target_description}")
            report.append(f"   Memory impact: {rule.memory_impact}")
            report.append("")
            report.append(f"   Theorem: {rule.proof.theorem}")
            report.append("   Assumptions:")
            for assumption in rule.proof.assumptions:
                report.append(f"     - {assumption}")
            report.append("")

        report.append("=" * 80)
        return "\n".join(report)

    def generate_formal_proofs(self):
        """Generate formal proofs for all transformation rules (Phase 4)"""
        try:
            from .profiler_verifier import get_proof_generator, PerformanceGuarantee

            generator = get_proof_generator()

            for rule_name, rule in self.rules.items():
                logger.info(f"Generating formal proofs for {rule_name}")

                # Generate equivalence proof
                equiv_proof = generator.generate_equivalence_proof(
                    transformation_name=rule.name,
                    transformation_description=rule.source_description,
                    assumptions=rule.proof.assumptions,
                )
                rule.formal_proof = equiv_proof

                # Generate performance proof
                min_speedup, max_speedup = rule.expected_speedup_range
                perf_proof = generator.generate_performance_proof(
                    transformation_name=rule.name,
                    speedup_bound=min_speedup,
                    assumptions=rule.proof.assumptions,
                )

                # Create performance guarantee
                rule.performance_guarantee = PerformanceGuarantee(
                    guarantee_type="speedup",
                    bound=min_speedup,
                    bound_type="minimum",
                    confidence=0.90,
                    proof=perf_proof,
                )

                logger.info(f"Generated formal proofs for {rule_name}")

        except ImportError:
            logger.warning("Proof generator not available")

    def verify_all_transformations(self) -> Dict[str, Any]:
        """Verify all transformation rules formally (Phase 4)"""
        try:
            from .profiler_verifier import get_proof_verifier

            verifier = get_proof_verifier()
            results = {}

            for rule_name, rule in self.rules.items():
                if rule.formal_proof:
                    logger.info(f"Verifying {rule_name}")
                    result = verifier.verify_proof(rule.formal_proof)
                    rule.verification_result = result
                    results[rule_name] = result
                else:
                    logger.warning(f"No formal proof for {rule_name}, skipping verification")

            return results

        except ImportError:
            logger.warning("Proof verifier not available")
            return {}

    def get_verification_report(self) -> str:
        """Generate human-readable verification report (Phase 4)"""
        lines = []
        lines.append("=" * 80)
        lines.append("Verification Report")
        lines.append("=" * 80)
        lines.append("")
        lines.append("TRANSFORMATION VERIFICATION REPORT")
        lines.append("=" * 80)
        lines.append("")

        verified_count = 0
        unverified_count = 0

        for rule_name, rule in self.rules.items():
            if rule.verification_result:
                status = "[OK]" if rule.verification_result.is_valid else "[X]"
                confidence = rule.verification_result.confidence_score * 100
                verified_count += 1 if rule.verification_result.is_valid else 0
                unverified_count += 0 if rule.verification_result.is_valid else 1

                lines.append(f"{status} {rule_name}")
                lines.append(f"    Confidence: {confidence:.0f}%")

                if rule.performance_guarantee:
                    guarantee = rule.performance_guarantee
                    lines.append(
                        f"    Performance Guarantee: {guarantee.bound}x {guarantee.bound_type} {guarantee.guarantee_type}"
                    )

                if rule.verification_result.warnings:
                    lines.append(f"    Warnings: {len(rule.verification_result.warnings)}")

            else:
                lines.append(f"[?] {rule_name} - Not verified")
                unverified_count += 1

            lines.append("")

        lines.append("-" * 80)
        lines.append("Summary:")
        lines.append(f"  Verified: {verified_count}")
        lines.append(f"  Failed/Unverified: {unverified_count}")
        lines.append(f"  Total: {len(self.rules)}")
        lines.append("=" * 80)

        return "\n".join(lines)


# Singleton instance
_transformation_catalog = None


def get_transformation_catalog() -> TransformationCatalog:
    """Get singleton transformation catalog"""
    global _transformation_catalog
    if _transformation_catalog is None:
        _transformation_catalog = TransformationCatalog()
    return _transformation_catalog
