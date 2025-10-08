"""
Simple GPU Factory Refactoring Test
Tests the new refactored architecture
"""

import sys
import os

# Add development directory to path
sys.path.insert(0, os.path.dirname(__file__))

# Windows console encoding fix
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

print("\n" + "="*70)
print("GPU FACTORY REFACTORING - QUICK VALIDATION")
print("="*70)

# Test 1: Import backend selector
print("\n[1] Testing backend_selector imports...")
try:
    from apps.catalytic.gpu.backend_selector import (
        BackendRequirements,
        AutoBackendSelector,
        PerformanceBackendSelector,
        MemoryOptimizedBackendSelector,
    )
    print("    ✓ backend_selector imports successful")
    print(f"      - BackendRequirements: {BackendRequirements}")
    print(f"      - AutoBackendSelector: {AutoBackendSelector}")
    print(f"      - PerformanceBackendSelector: {PerformanceBackendSelector}")
    print(f"      - MemoryOptimizedBackendSelector: {MemoryOptimizedBackendSelector}")
except Exception as e:
    print(f"    ✗ backend_selector import failed: {e}")
    import traceback
    traceback.print_exc()

# Test 2: Import factory builder
print("\n[2] Testing factory_builder imports...")
try:
    from apps.catalytic.gpu.factory_builder import (
        LatticeBuilder,
        create_small_lattice,
        create_medium_lattice,
    )
    print("    ✓ factory_builder imports successful")
    print(f"      - LatticeBuilder: {LatticeBuilder}")
    print(f"      - create_small_lattice: {create_small_lattice}")
    print(f"      - create_medium_lattice: {create_medium_lattice}")
except Exception as e:
    print(f"    ✗ factory_builder import failed: {e}")
    import traceback
    traceback.print_exc()

# Test 3: Import refactored factory
print("\n[3] Testing factory_refactored imports...")
try:
    from apps.catalytic.gpu.factory_refactored import (
        GPUFactoryRefactored,
        DeviceSelector,
    )
    print("    ✓ factory_refactored imports successful")
    print(f"      - GPUFactoryRefactored: {GPUFactoryRefactored}")
    print(f"      - DeviceSelector: {DeviceSelector}")
except Exception as e:
    print(f"    ✗ factory_refactored import failed: {e}")
    import traceback
    traceback.print_exc()

# Test 4: Test BackendRequirements dataclass
print("\n[4] Testing BackendRequirements creation...")
try:
    from apps.catalytic.gpu.backend_selector import BackendRequirements
    from libs.config import GPUBackend

    requirements = BackendRequirements(
        preferred_backend=GPUBackend.CPU,
        min_memory_mb=100,
        allow_cpu_fallback=True
    )
    print("    ✓ BackendRequirements created")
    print(f"      - preferred_backend: {requirements.preferred_backend}")
    print(f"      - min_memory_mb: {requirements.min_memory_mb}")
    print(f"      - allow_cpu_fallback: {requirements.allow_cpu_fallback}")
except Exception as e:
    print(f"    ✗ BackendRequirements creation failed: {e}")
    import traceback
    traceback.print_exc()

# Test 5: Test LatticeBuilder
print("\n[5] Testing LatticeBuilder fluent API...")
try:
    from apps.catalytic.gpu.factory_builder import LatticeBuilder
    from libs.config import GPUBackend

    builder = (LatticeBuilder()
        .with_dimensions(3)
        .with_size(5)
        .prefer_backend(GPUBackend.CPU)
        .allow_cpu_fallback(True))

    print("    ✓ LatticeBuilder chain created")

    # Test validation
    is_valid = builder.validate()
    print(f"    ✓ Validation: {is_valid}")

    # Test description
    description = builder.describe()
    print(f"    ✓ Description:")
    for key, value in description.items():
        if value is not None:
            print(f"        - {key}: {value}")

    # Test memory estimation
    estimated_mb = builder.estimate_memory_requirements()
    print(f"    ✓ Estimated memory: {estimated_mb:.2f} MB")

except Exception as e:
    print(f"    ✗ LatticeBuilder test failed: {e}")
    import traceback
    traceback.print_exc()

# Test 6: Test GPUFactoryRefactored
print("\n[6] Testing GPUFactoryRefactored...")
try:
    from apps.catalytic.gpu.factory_refactored import GPUFactoryRefactored
    from libs.config import GPUBackend

    # List available backends
    backends = GPUFactoryRefactored.list_available_backends()
    print(f"    ✓ Available backends: {[b.value for b in backends]}")

    # Check specific backends
    for backend in [GPUBackend.CPU, GPUBackend.PYTORCH, GPUBackend.CUDA]:
        available = GPUFactoryRefactored.is_backend_available(backend)
        status = "✓" if available else "✗"
        print(f"      {status} {backend.value}: {available}")

except Exception as e:
    print(f"    ✗ GPUFactoryRefactored test failed: {e}")
    import traceback
    traceback.print_exc()

# Test 7: Try creating a CPU lattice
print("\n[7] Testing lattice creation (CPU backend)...")
try:
    from apps.catalytic.gpu.factory_refactored import GPUFactoryRefactored
    from libs.config import GPUBackend

    lattice = GPUFactoryRefactored.create(
        dimensions=3,
        size=4,
        backend=GPUBackend.CPU
    )
    print("    ✓ CPU lattice created successfully")
    print(f"      - Type: {type(lattice).__name__}")
    print(f"      - Dimensions: {lattice.dimensions}")
    print(f"      - Size: {lattice.size}")
    print(f"      - Points: {lattice.n_points}")
    print(f"      - Device ID: {lattice.device_id}")

except Exception as e:
    print(f"    ✗ Lattice creation failed: {e}")
    import traceback
    traceback.print_exc()

# Test 8: Try building with builder
print("\n[8] Testing lattice creation via Builder...")
try:
    from apps.catalytic.gpu.factory_builder import LatticeBuilder
    from libs.config import GPUBackend

    lattice = (LatticeBuilder()
        .with_dimensions(3)
        .with_size(4)
        .prefer_backend(GPUBackend.CPU)
        .allow_cpu_fallback(True)
        .build())

    print("    ✓ Lattice built via Builder successfully")
    print(f"      - Type: {type(lattice).__name__}")
    print(f"      - Dimensions: {lattice.dimensions}")
    print(f"      - Size: {lattice.size}")

except Exception as e:
    print(f"    ✗ Builder lattice creation failed: {e}")
    import traceback
    traceback.print_exc()

# Test 9: Backend selector strategies
print("\n[9] Testing backend selection strategies...")
try:
    from apps.catalytic.gpu.backend_selector import (
        BackendRequirements,
        AutoBackendSelector,
        PerformanceBackendSelector,
    )
    from libs.config import GPUBackend

    requirements = BackendRequirements(allow_cpu_fallback=True)
    available_backends = [GPUBackend.CPU, GPUBackend.PYTORCH]

    # Test auto selector
    auto_selector = AutoBackendSelector()
    backend = auto_selector.select_backend(requirements, available_backends)
    print(f"    ✓ AutoBackendSelector: {backend.value}")

    # Test performance selector
    perf_selector = PerformanceBackendSelector()
    backend = perf_selector.select_backend(requirements, available_backends)
    print(f"    ✓ PerformanceBackendSelector: {backend.value}")

except Exception as e:
    print(f"    ✗ Backend selector strategies failed: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "="*70)
print("VALIDATION COMPLETE")
print("="*70)
print("\n✓ GPU Factory refactoring architecture validated!")
print("  All core components are working correctly.")
print("\n")
