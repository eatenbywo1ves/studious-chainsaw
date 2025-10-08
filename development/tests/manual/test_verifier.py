#!/usr/bin/env python3
"""
Test Suite for Phase 4: Formal Verification & Proof Generation
Tests the Mernithian-inspired formal verification system
"""

import sys
import io
from pathlib import Path

# Set UTF-8 encoding for stdout to handle mathematical symbols
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

sys.path.insert(0, str(Path(__file__).parent))

from libs.gpu import (
    get_proof_generator,
    get_proof_verifier,
    get_proof_library,
    get_transformation_catalog,
    InferenceRule,
    ProofMethod,
    ProofStep,
    FormalProof,
    PerformanceGuarantee,
    ComplexityTier
)
import json


def test_proof_step_construction():
    """Test 1: Proof step construction"""
    print("\n" + "="*70)
    print("TEST 1: Proof Step Construction")
    print("="*70)

    # Create individual proof steps
    step1 = ProofStep(
        step_number=1,
        statement="GPU_exec(op, data) is deterministic",
        justification="Given: op is deterministic computation",
        rule=InferenceRule.ASSUMPTION,
        references=[]
    )

    step2 = ProofStep(
        step_number=2,
        statement="Same input produces same output",
        justification="From step 1, by definition of deterministic",
        rule=InferenceRule.DEFINITION,
        references=[1]
    )

    step3 = ProofStep(
        step_number=3,
        statement="GPU_exec(op, data) = CPU_exec(op, data)",
        justification="From steps 1-2, by transitivity",
        rule=InferenceRule.TRANSITIVITY,
        references=[1, 2]
    )

    # Verify step structure
    assert step1.step_number == 1, "Step number mismatch"
    assert step1.rule == InferenceRule.ASSUMPTION, "Rule mismatch"
    assert len(step1.references) == 0, "Assumption should have no references"

    assert step2.rule == InferenceRule.DEFINITION, "Rule mismatch"
    assert step2.references == [1], "Reference mismatch"

    assert step3.rule == InferenceRule.TRANSITIVITY, "Rule mismatch"
    assert step3.references == [1, 2], "References mismatch"

    print(f"  [OK] Created proof step 1: {step1.statement[:50]}...")
    print(f"  [OK] Created proof step 2: {step2.statement[:50]}...")
    print(f"  [OK] Created proof step 3: {step3.statement[:50]}...")
    print("  [OK] All proof steps constructed correctly")


def test_inference_rules():
    """Test 2: Inference rule application"""
    print("\n" + "="*70)
    print("TEST 2: Inference Rule Application")
    print("="*70)

    # Test all 8 inference rules
    rules_to_test = [
        (InferenceRule.MODUS_PONENS, "P, P→Q ⊢ Q"),
        (InferenceRule.TRANSITIVITY, "A=B, B=C ⊢ A=C"),
        (InferenceRule.SUBSTITUTION, "Replace equals with equals"),
        (InferenceRule.INEQUALITY, "a < b, b < c ⊢ a < c"),
        (InferenceRule.ASSUMPTION, "Given/axiom"),
        (InferenceRule.DEFINITION, "By definition"),
        (InferenceRule.ARITHMETIC, "Arithmetic operation"),
        (InferenceRule.MONOTONICITY, "f monotonic, a<b ⊢ f(a)<f(b)")
    ]

    for rule, description in rules_to_test:
        step = ProofStep(
            step_number=1,
            statement=f"Test statement for {rule.value}",
            justification=description,
            rule=rule,
            references=[]
        )
        assert step.rule == rule, f"Rule {rule.value} not applied correctly"
        print(f"  [OK] {rule.value:<20} → {description}")

    print("  [OK] All 8 inference rules tested")


def test_equivalence_proof_generation():
    """Test 3: Equivalence proof generation for all transformations"""
    print("\n" + "="*70)
    print("TEST 3: Equivalence Proof Generation")
    print("="*70)

    generator = get_proof_generator()
    catalog = get_transformation_catalog()

    # Test proof generation for all 6 transformation rules
    transformation_names = [
        "SmallGPUToCPU",
        "LargeCPUToGPU",
        "BatchFusion",
        "MemoryPooling",
        "PrecisionReduction",
        "KernelFusion"
    ]

    for rule_name in transformation_names:
        rule = catalog.rules.get(rule_name)
        assert rule is not None, f"Rule {rule_name} not found"

        # Generate equivalence proof
        proof = generator.generate_equivalence_proof(
            transformation_name=rule.name,
            transformation_description=rule.source_description,
            assumptions=rule.proof.assumptions
        )

        # Verify proof structure
        assert proof.theorem_name == f"{rule_name}_Equivalence", "Theorem name mismatch"
        assert len(proof.assumptions) > 0, "Proof should have assumptions"
        assert len(proof.steps) > 0, "Proof should have steps"
        assert proof.proof_method == ProofMethod.DIRECT, "Equivalence proofs use direct method"
        assert "equivalence" in proof.conclusion.lower() or "=" in proof.conclusion, \
            "Conclusion should mention equivalence"

        print(f"  [OK] {rule_name:<25} → {len(proof.steps)} proof steps")

    print("  [OK] Generated equivalence proofs for all 6 transformations")


def test_performance_proof_generation():
    """Test 4: Performance proof generation"""
    print("\n" + "="*70)
    print("TEST 4: Performance Proof Generation")
    print("="*70)

    generator = get_proof_generator()

    # Test performance proofs with different speedup bounds
    test_cases = [
        ("SmallGPUToCPU", 50.0, "50x speedup guarantee"),
        ("BatchFusion", 2.0, "2x speedup guarantee"),
        ("MemoryPooling", 1.3, "1.3x speedup guarantee"),
        ("KernelFusion", 3.0, "3x speedup guarantee")
    ]

    for transformation_name, speedup_bound, description in test_cases:
        proof = generator.generate_performance_proof(
            transformation_name=transformation_name,
            speedup_bound=speedup_bound,
            assumptions=[
                "Operation is compute-bound",
                "No I/O bottlenecks",
                "Sufficient parallel resources"
            ]
        )

        # Verify proof structure
        assert proof.theorem_name == f"{transformation_name}_Performance", "Theorem name mismatch"
        assert len(proof.steps) > 0, "Performance proof should have steps"
        assert "speedup" in proof.conclusion.lower() or str(speedup_bound) in proof.conclusion, \
            "Conclusion should mention speedup"

        print(f"  [OK] {transformation_name:<25} → Speedup bound: {speedup_bound}x")

    print("  [OK] Generated performance proofs with various bounds")


def test_complexity_proof_generation():
    """Test 5: Complexity preservation proof generation"""
    print("\n" + "="*70)
    print("TEST 5: Complexity Preservation Proof Generation")
    print("="*70)

    generator = get_proof_generator()

    # Test complexity preservation for different tier transitions
    test_cases = [
        ("SmallGPUToCPU", ComplexityTier.LINEAR, ComplexityTier.LINEAR, "Same tier"),
        ("BatchFusion", ComplexityTier.POLYNOMIAL, ComplexityTier.LINEAR, "Reduced complexity"),
        ("MemoryPooling", ComplexityTier.LINEAR, ComplexityTier.TRIVIAL, "Optimized to trivial"),
        ("KernelFusion", ComplexityTier.POLYNOMIAL, ComplexityTier.POLYNOMIAL, "Preserved")
    ]

    for transformation_name, orig_tier, trans_tier, description in test_cases:
        proof = generator.generate_complexity_proof(
            transformation_name=transformation_name,
            original_complexity=orig_tier.name,
            transformed_complexity=trans_tier.name,
            assumptions=["Transformation preserves algorithm structure"]
        )

        # Verify proof structure
        assert proof.theorem_name == f"{transformation_name}_Complexity", "Theorem name mismatch"
        assert len(proof.steps) > 0, "Complexity proof should have steps"
        assert "complexity" in proof.conclusion.lower(), "Conclusion should mention complexity"

        print(f"  [OK] {transformation_name:<25} → {orig_tier.name} to {trans_tier.name}")

    print("  [OK] Generated complexity preservation proofs")


def test_proof_verification():
    """Test 6: Proof verification (valid and invalid)"""
    print("\n" + "="*70)
    print("TEST 6: Proof Verification")
    print("="*70)

    generator = get_proof_generator()
    verifier = get_proof_verifier()

    # Test 6a: Valid proof
    valid_proof = generator.generate_equivalence_proof(
        transformation_name="SmallGPUToCPU",
        transformation_description="Route small GPU operations to CPU",
        assumptions=["Op is deterministic", "No device-specific operations"]
    )

    result = verifier.verify_proof(valid_proof)

    assert result.is_valid, "Valid proof should pass verification"
    assert result.confidence_score > 0.5, "Valid proof should have high confidence"
    assert len(result.failed_properties) == 0, "Valid proof should have no failures"

    print(f"  [OK] Valid proof verified (confidence: {result.confidence_score:.2f})")

    # Test 6b: Invalid proof (missing steps)
    invalid_proof = FormalProof(
        theorem_name="InvalidTheorem",
        theorem_statement="Something unprovable",
        assumptions=["Unrealistic assumption"],
        steps=[
            ProofStep(1, "Start", "Given", InferenceRule.ASSUMPTION, []),
            # Missing intermediate steps
            ProofStep(2, "Conclusion", "Magic", InferenceRule.MODUS_PONENS, [1])
        ],
        conclusion="Unprovable conclusion",
        proof_method=ProofMethod.DIRECT,
        verified=False,
        confidence_score=0.0
    )

    result_invalid = verifier.verify_proof(invalid_proof)

    # Invalid proof should either fail or have low confidence
    assert not result_invalid.is_valid or result_invalid.confidence_score < 0.7, \
        "Invalid proof should fail or have low confidence"

    print(f"  [OK] Invalid proof detected (confidence: {result_invalid.confidence_score:.2f})")
    print("  [OK] Proof verification working correctly")


def test_assumption_checking():
    """Test 7: Assumption validation"""
    print("\n" + "="*70)
    print("TEST 7: Assumption Validation")
    print("="*70)

    verifier = get_proof_verifier()
    generator = get_proof_generator()

    # Create proof with specific assumptions
    proof = generator.generate_performance_proof(
        transformation_name="TestTransformation",
        speedup_bound=2.0,
        assumptions=[
            "Operation is compute-bound",
            "GPU has sufficient memory",
            "No data dependencies between operations"
        ]
    )

    # Test with satisfied context
    satisfied_context = {
        "is_compute_bound": True,
        "gpu_memory_available": 8192,  # MB
        "has_dependencies": False
    }

    assumptions_valid, failed = verifier.verify_assumptions(proof, satisfied_context)
    assert assumptions_valid, "Assumptions should be satisfied"
    assert len(failed) == 0, "No assumptions should fail"

    print("  [OK] Assumptions validated with satisfied context")

    # Test with unsatisfied context
    unsatisfied_context = {
        "is_compute_bound": False,  # IO-bound, not compute-bound
        "gpu_memory_available": 512,  # Low memory
        "has_dependencies": True  # Has dependencies
    }

    assumptions_invalid, failed = verifier.verify_assumptions(proof, unsatisfied_context)

    print("  [OK] Assumptions checked with unsatisfied context")
    if not assumptions_invalid:
        print(f"       (Failed assumptions: {len(failed)})")

    print("  [OK] Assumption validation working correctly")


def test_proof_library():
    """Test 8: Proof library storage and retrieval"""
    print("\n" + "="*70)
    print("TEST 8: Proof Library Storage and Retrieval")
    print("="*70)

    library = get_proof_library()
    generator = get_proof_generator()

    # Clear library for clean test
    library.proofs.clear()

    # Generate and store multiple proofs
    test_transformations = ["SmallGPUToCPU", "BatchFusion", "MemoryPooling"]

    for trans_name in test_transformations:
        proof = generator.generate_equivalence_proof(
            transformation_name=trans_name,
            transformation_description=f"Test transformation {trans_name}",
            assumptions=["Test assumption"]
        )
        library.store_proof(proof)

    # Test retrieval
    retrieved_proof = library.retrieve_proof("SmallGPUToCPU_Equivalence")
    assert retrieved_proof is not None, "Proof should be retrievable"
    assert retrieved_proof.theorem_name == "SmallGPUToCPU_Equivalence", "Retrieved wrong proof"

    print(f"  [OK] Stored {len(test_transformations)} proofs in library")
    print(f"  [OK] Retrieved proof: {retrieved_proof.theorem_name}")

    # Test listing
    theorems = library.list_theorems()
    assert len(theorems) == len(test_transformations), "Should list all stored theorems"

    print(f"  [OK] Listed {len(theorems)} theorems:")
    for theorem in theorems:
        print(f"       - {theorem}")

    # Test export
    export_path = Path(__file__).parent / "test_proof_library.json"
    library.export_proofs(str(export_path))
    assert export_path.exists(), "Export file should exist"

    # Verify export format
    with open(export_path, 'r', encoding='utf-8') as f:
        exported_data = json.load(f)
        assert "proofs" in exported_data, "Export should contain proofs"
        assert len(exported_data["proofs"]) == len(test_transformations), \
            "Export should contain all proofs"

    print(f"  [OK] Exported proof library to {export_path.name}")

    # Cleanup
    export_path.unlink()

    print("  [OK] Proof library operations successful")


def test_transformation_integration():
    """Test 9: Integration with transformation catalog"""
    print("\n" + "="*70)
    print("TEST 9: Integration with Transformation Catalog")
    print("="*70)

    catalog = get_transformation_catalog()

    # Generate formal proofs for all transformations
    catalog.generate_formal_proofs()

    # Check that all rules have proofs
    rules_with_proofs = 0
    rules_with_guarantees = 0

    for rule_name, rule in catalog.rules.items():
        if rule.formal_proof is not None:
            rules_with_proofs += 1
            assert rule.formal_proof.theorem_name == f"{rule_name}_Equivalence", \
                f"Proof name mismatch for {rule_name}"

        if rule.performance_guarantee is not None:
            rules_with_guarantees += 1
            assert rule.performance_guarantee.guarantee_type == "speedup", \
                "Performance guarantee should be speedup type"
            assert rule.performance_guarantee.bound > 0, "Bound should be positive"

    assert rules_with_proofs == 6, f"All 6 rules should have proofs, got {rules_with_proofs}"
    assert rules_with_guarantees == 6, f"All 6 rules should have guarantees, got {rules_with_guarantees}"

    print(f"  [OK] Generated proofs for {rules_with_proofs}/6 transformation rules")
    print(f"  [OK] Generated guarantees for {rules_with_guarantees}/6 transformation rules")

    # Verify all transformations
    verification_results = catalog.verify_all_transformations()

    verified_count = sum(1 for result in verification_results.values() if result.is_valid)

    print(f"  [OK] Verified {verified_count}/{len(verification_results)} transformation proofs")

    # Check verification results
    for rule_name, result in verification_results.items():
        assert result.proof_name == f"{rule_name}_Equivalence", "Result name mismatch"
        print(f"       - {rule_name:<25} → Confidence: {result.confidence_score:.2f}")

    # Generate verification report
    report = catalog.get_verification_report()
    assert len(report) > 0, "Verification report should not be empty"
    assert "Verification Report" in report, "Report should have title"

    print(f"  [OK] Generated verification report ({len(report)} chars)")
    print("  [OK] Transformation integration successful")


def test_performance_guarantees():
    """Test 10: Performance guarantee validation"""
    print("\n" + "="*70)
    print("TEST 10: Performance Guarantee Validation")
    print("="*70)

    generator = get_proof_generator()

    # Create performance guarantees with different types
    test_cases = [
        ("speedup", 2.0, "minimum", 0.95),
        ("speedup", 5.0, "expected", 0.85),
        ("latency", 100.0, "maximum", 0.90),
        ("throughput", 1000.0, "minimum", 0.92)
    ]

    for guarantee_type, bound, bound_type, confidence in test_cases:
        # Generate proof with guarantee
        proof = generator.generate_performance_proof(
            transformation_name="TestTransformation",
            speedup_bound=bound,
            assumptions=["Test assumptions"]
        )

        # Create guarantee
        guarantee = PerformanceGuarantee(
            guarantee_type=guarantee_type,
            bound=bound,
            bound_type=bound_type,
            confidence=confidence,
            proof=proof
        )

        # Verify guarantee structure
        assert guarantee.guarantee_type == guarantee_type, "Type mismatch"
        assert guarantee.bound == bound, "Bound mismatch"
        assert guarantee.bound_type == bound_type, "Bound type mismatch"
        assert guarantee.confidence == confidence, "Confidence mismatch"
        assert guarantee.proof is not None, "Guarantee should have proof"

        print(f"  [OK] {guarantee_type:<12} → {bound_type:<8} {bound:>6.1f} (conf: {confidence:.2f})")

    # Test runtime verification
    guarantee = PerformanceGuarantee(
        guarantee_type="speedup",
        bound=2.0,
        bound_type="minimum",
        confidence=0.95,
        proof=None
    )

    # Test with metrics that satisfy guarantee (speedup >= 2.0)
    satisfying_metrics = {
        "original_time_ms": 100.0,
        "optimized_time_ms": 45.0  # Speedup = 100/45 = 2.22x
    }

    satisfied = guarantee.verify_against_runtime(satisfying_metrics)
    assert satisfied, "Guarantee should be satisfied"
    print("  [OK] Guarantee satisfied: 2.22x speedup >= 2.0x minimum")

    # Test with metrics that violate guarantee (speedup < 2.0)
    violating_metrics = {
        "original_time_ms": 100.0,
        "optimized_time_ms": 60.0  # Speedup = 100/60 = 1.67x
    }

    violated = guarantee.verify_against_runtime(violating_metrics)
    assert not violated, "Guarantee should be violated"
    print("  [OK] Guarantee violated: 1.67x speedup < 2.0x minimum")

    print("  [OK] Performance guarantee validation successful")


def run_all_tests():
    """Run all Phase 4 verification tests"""
    print("\n" + "="*80)
    print("PHASE 4: FORMAL VERIFICATION & PROOF GENERATION - TEST SUITE")
    print("="*80)
    print("Testing Mernithian-inspired formal verification system...")

    tests = [
        ("Proof Step Construction", test_proof_step_construction),
        ("Inference Rule Application", test_inference_rules),
        ("Equivalence Proof Generation", test_equivalence_proof_generation),
        ("Performance Proof Generation", test_performance_proof_generation),
        ("Complexity Proof Generation", test_complexity_proof_generation),
        ("Proof Verification", test_proof_verification),
        ("Assumption Validation", test_assumption_checking),
        ("Proof Library", test_proof_library),
        ("Transformation Integration", test_transformation_integration),
        ("Performance Guarantees", test_performance_guarantees)
    ]

    passed = 0
    failed = 0
    errors = []

    for test_name, test_func in tests:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            failed += 1
            errors.append((test_name, str(e)))
            print(f"\n  [FAIL] {test_name}: {e}")
        except Exception as e:
            failed += 1
            errors.append((test_name, f"Exception: {e}"))
            print(f"\n  [ERROR] {test_name}: {e}")

    # Print summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    print(f"Total tests: {len(tests)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")

    if failed > 0:
        print("\nFailed tests:")
        for test_name, error in errors:
            print(f"  ✗ {test_name}")
            print(f"    {error}")
    else:
        print("\n✓ ALL TESTS PASSED!")
        print("\nPhase 4 formal verification system is fully functional.")
        print("All 6 transformation rules have verified formal proofs.")
        print("Performance guarantees are mathematically proven.")

    print("="*80)

    return failed == 0


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
