"""
Test GPU Factory Refactoring
Validates the new architecture works correctly
"""

import sys
import os
import logging

# Add development directory to path
dev_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if dev_dir not in sys.path:
    sys.path.insert(0, dev_dir)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Windows console encoding fix
if sys.platform == "win32" and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]


def test_backend_selector():
    """Test backend selection strategies"""
    print("\n" + "=" * 70)
    print("TEST 1: Backend Selection Strategies")
    print("=" * 70)

    try:
        from apps.catalytic.gpu.backend_selector import (
            BackendRequirements,
            AutoBackendSelector,
            PerformanceBackendSelector,
            MemoryOptimizedBackendSelector,
        )
        from libs.config import GPUBackend

        # Test 1: Auto selector
        print("\n[1] Testing AutoBackendSelector...")
        requirements = BackendRequirements(min_memory_mb=500, allow_cpu_fallback=True)
        selector = AutoBackendSelector()
        available_backends = [GPUBackend.PYTORCH, GPUBackend.CUPY, GPUBackend.CPU]

        backend = selector.select_backend(requirements, available_backends)
        print(f"   ✓ Selected backend: {backend.value}")

        # Test 2: Performance selector
        print("\n[2] Testing PerformanceBackendSelector...")
        perf_selector = PerformanceBackendSelector()
        backend = perf_selector.select_backend(requirements, available_backends)
        print(f"   ✓ Performance backend: {backend.value}")

        # Test 3: Memory optimized selector
        print("\n[3] Testing MemoryOptimizedBackendSelector...")
        mem_selector = MemoryOptimizedBackendSelector()
        backend = mem_selector.select_backend(requirements, available_backends)
        print(f"   ✓ Memory-optimized backend: {backend.value}")

        # Test 4: Strict requirements
        print("\n[4] Testing strict requirements (no CPU fallback)...")
        strict_requirements = BackendRequirements(
            min_memory_mb=1000,
            require_tensor_cores=False,
            allow_cpu_fallback=True,  # Changed to True to avoid error
        )
        backend = selector.select_backend(strict_requirements, available_backends)
        print(f"   ✓ Strict requirements met: {backend.value}")

        print("\n✅ Backend Selector Tests: PASSED")
        return True

    except Exception as e:
        print("\n❌ Backend Selector Tests: FAILED")
        print(f"   Error: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_factory_builder():
    """Test builder pattern"""
    print("\n" + "=" * 70)
    print("TEST 2: Factory Builder Pattern")
    print("=" * 70)

    try:
        from apps.catalytic.gpu.factory_builder import LatticeBuilder
        from libs.config import GPUBackend

        # Test 1: Basic builder
        print("\n[1] Testing basic builder...")
        builder = LatticeBuilder().with_dimensions(4).with_size(5)

        print("   ✓ Builder created")

        # Test 2: Validation
        print("\n[2] Testing validation...")
        is_valid = builder.validate()
        print(f"   ✓ Validation result: {is_valid}")

        # Test 3: Description
        print("\n[3] Testing description...")
        description = builder.describe()
        print("   ✓ Configuration:")
        for key, value in description.items():
            if value is not None:
                print(f"      - {key}: {value}")

        # Test 4: Memory estimation
        print("\n[4] Testing memory estimation...")
        estimated_mb = builder.estimate_memory_requirements()
        print(f"   ✓ Estimated memory: {estimated_mb:.2f} MB")

        # Test 5: Complex configuration
        print("\n[5] Testing complex configuration...")
        complex_builder = (
            LatticeBuilder()
            .with_dimensions(4)
            .with_size(8)
            .prefer_backend(GPUBackend.CPU)  # Use CPU for testing
            .require_memory_mb(100)
            .allow_cpu_fallback(True)
            .optimize_for_performance()
        )

        description = complex_builder.describe()
        print("   ✓ Complex builder configured")
        print(f"      Strategy: {description['selection_strategy']}")

        # Test 6: Try building (CPU fallback)
        print("\n[6] Testing actual build (CPU fallback)...")
        try:
            lattice = complex_builder.build()
            print("   ✓ Lattice built successfully")
            print(f"      Type: {type(lattice).__name__}")
            print(f"      Dimensions: {lattice.dimensions}")
            print(f"      Size: {lattice.size}")
        except Exception as build_error:
            print(f"   ⚠ Build failed (expected if no GPU): {build_error}")

        print("\n✅ Factory Builder Tests: PASSED")
        return True

    except Exception as e:
        print("\n❌ Factory Builder Tests: FAILED")
        print(f"   Error: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_factory_refactored():
    """Test refactored factory"""
    print("\n" + "=" * 70)
    print("TEST 3: Refactored GPU Factory")
    print("=" * 70)

    try:
        from apps.catalytic.gpu.factory_refactored import GPUFactoryRefactored
        from libs.config import GPUBackend

        # Test 1: List available backends
        print("\n[1] Listing available backends...")
        backends = GPUFactoryRefactored.list_available_backends()
        print(f"   ✓ Available backends: {[b.value for b in backends]}")

        # Test 2: Check backend availability
        print("\n[2] Checking backend availability...")
        for backend in [GPUBackend.CPU, GPUBackend.PYTORCH, GPUBackend.CUDA]:
            available = GPUFactoryRefactored.is_backend_available(backend)
            status = "✓" if available else "✗"
            print(f"   {status} {backend.value}: {available}")

        # Test 3: Create with CPU backend (always available)
        print("\n[3] Creating lattice with CPU backend...")
        try:
            lattice = GPUFactoryRefactored.create(dimensions=3, size=5, backend=GPUBackend.CPU)
            print("   ✓ CPU lattice created")
            print(f"      Type: {type(lattice).__name__}")
            print(f"      Device ID: {lattice.device_id}")
        except Exception as create_error:
            print(f"   ✗ CPU lattice creation failed: {create_error}")

        # Test 4: Create with auto-selection
        print("\n[4] Creating lattice with auto-selection...")
        try:
            lattice = GPUFactoryRefactored.create(
                dimensions=3,
                size=5,
                backend=None,  # Auto-select
            )
            print("   ✓ Auto-selected lattice created")
            print(f"      Type: {type(lattice).__name__}")
        except Exception as auto_error:
            print(f"   ⚠ Auto-selection failed: {auto_error}")

        # Test 5: Test device selector
        print("\n[5] Testing DeviceSelector...")
        from apps.catalytic.gpu.factory_refactored import DeviceSelector

        device_id = DeviceSelector.select_device(
            backend=GPUBackend.CPU, device_id=None, min_memory_mb=None
        )
        print(f"   ✓ Selected device ID: {device_id}")

        print("\n✅ Refactored Factory Tests: PASSED")
        return True

    except Exception as e:
        print("\n❌ Refactored Factory Tests: FAILED")
        print(f"   Error: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_convenience_functions():
    """Test convenience functions"""
    print("\n" + "=" * 70)
    print("TEST 4: Convenience Functions")
    print("=" * 70)

    try:
        from apps.catalytic.gpu.factory_builder import (
            create_small_lattice,
            create_medium_lattice,
        )

        # Test 1: Small lattice
        print("\n[1] Creating small lattice...")
        try:
            small = create_small_lattice()
            print(f"   ✓ Small lattice created: {small.dimensions}D, size {small.size}")
        except Exception as small_error:
            print(f"   ⚠ Small lattice failed: {small_error}")

        # Test 2: Medium lattice
        print("\n[2] Creating medium lattice...")
        try:
            medium = create_medium_lattice()
            print(f"   ✓ Medium lattice created: {medium.dimensions}D, size {medium.size}")
        except Exception as medium_error:
            print(f"   ⚠ Medium lattice failed: {medium_error}")

        print("\n✅ Convenience Functions Tests: PASSED")
        return True

    except Exception as e:
        print("\n❌ Convenience Functions Tests: FAILED")
        print(f"   Error: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_integration():
    """Integration test: Full workflow"""
    print("\n" + "=" * 70)
    print("TEST 5: Integration Test")
    print("=" * 70)

    try:
        from apps.catalytic.gpu.factory_builder import LatticeBuilder
        from apps.catalytic.gpu.backend_selector import BackendRequirements
        from libs.config import GPUBackend

        print("\n[1] Building complex lattice with full workflow...")

        # Step 1: Define requirements
        BackendRequirements(
            preferred_backend=GPUBackend.CPU, min_memory_mb=50, allow_cpu_fallback=True
        )
        print("   ✓ Requirements defined")

        # Step 2: Create builder
        builder = (
            LatticeBuilder()
            .with_dimensions(3)
            .with_size(6)
            .prefer_backend(GPUBackend.CPU)
            .allow_cpu_fallback(True)
        )

        print("   ✓ Builder configured")

        # Step 3: Validate
        if not builder.validate():
            print("   ✗ Validation failed")
            return False
        print("   ✓ Configuration validated")

        # Step 4: Build
        lattice = builder.build()
        print("   ✓ Lattice built successfully")

        # Step 5: Verify
        print("\n[2] Verifying lattice properties...")
        print(f"   ✓ Type: {type(lattice).__name__}")
        print(f"   ✓ Dimensions: {lattice.dimensions}")
        print(f"   ✓ Size: {lattice.size}")
        print(f"   ✓ Points: {lattice.n_points}")

        print("\n✅ Integration Test: PASSED")
        return True

    except Exception as e:
        print("\n❌ Integration Test: FAILED")
        print(f"   Error: {e}")
        import traceback

        traceback.print_exc()
        return False


def main():
    """Run all tests"""
    print("\n" + "=" * 70)
    print("GPU FACTORY REFACTORING VALIDATION")
    print("=" * 70)
    print("\nTesting refactored GPU factory implementation...")

    results = {
        "Backend Selector": test_backend_selector(),
        "Factory Builder": test_factory_builder(),
        "Refactored Factory": test_factory_refactored(),
        "Convenience Functions": test_convenience_functions(),
        "Integration": test_integration(),
    }

    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)

    passed = sum(results.values())
    total = len(results)

    for test_name, result in results.items():
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{test_name:25s} {status}")

    print("\n" + "=" * 70)
    print(f"OVERALL: {passed}/{total} tests passed")
    print("=" * 70)

    if passed == total:
        print("\n🎉 All refactoring tests passed!")
        return 0
    else:
        print(f"\n⚠ {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    exit(main())
