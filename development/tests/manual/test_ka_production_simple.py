#!/usr/bin/env python3
"""
Simple KA Lattice Production Test
Tests core functionality without the complex orchestration layer
"""

import asyncio
import sys
import numpy as np
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from apps.catalytic.ka_lattice import KALatticeCore


async def test_production():
    """Test KA Lattice in a simplified production scenario"""

    print("=" * 60)
    print("KA Lattice Simple Production Test")
    print("=" * 60)

    # Create lattice
    print("\n1. Creating 4D lattice (100x100x100x100)...")
    lattice = KALatticeCore(dimensions=4, size=100)

    # Build lattice
    print("2. Building lattice structure...")
    start_time = time.time()
    await lattice.build()
    build_time = (time.time() - start_time) * 1000
    print(f"   ✓ Built in {build_time:.2f}ms")
    print(f"   ✓ Vertices: {lattice.vertex_count:,}")
    print(f"   ✓ Edges: {lattice.edge_count:,}")

    # Warmup
    print("\n3. Running warmup (10 iterations)...")
    warmup_times = []
    for i in range(10):
        data = np.random.randn(50, 50).astype(np.float32)
        result = await lattice.compute('transform', data, {'type': 'normalize'})
        warmup_times.append(result.execution_time_ms)

    avg_warmup = np.mean(warmup_times)
    print(f"   ✓ Average warmup time: {avg_warmup:.2f}ms")

    # Production workload
    print("\n4. Running production workload (100 operations)...")
    operations = {
        'transform': [],
        'reduce': [],
        'pathfind': [],
        'analyze': []
    }

    start_time = time.time()
    for i in range(100):
        # Cycle through operations
        if i % 4 == 0:
            op = 'transform'
            data = np.random.randn(100, 100).astype(np.float32)
            params = {'type': 'normalize'}
        elif i % 4 == 1:
            op = 'reduce'
            data = np.random.randn(1000).astype(np.float32)
            params = {'operation': 'sum'}
        elif i % 4 == 2:
            op = 'pathfind'
            data = np.array([])
            params = {'start': 0, 'end': 50}
        else:
            op = 'analyze'
            data = np.random.randn(50, 50).astype(np.float32)
            params = {}

        result = await lattice.compute(op, data, params)
        operations[op].append(result.execution_time_ms)

        if (i + 1) % 25 == 0:
            elapsed = time.time() - start_time
            throughput = (i + 1) / elapsed
            print(f"   Progress: {i+1}/100 ({throughput:.1f} ops/sec)")

    total_time = time.time() - start_time
    total_throughput = 100 / total_time

    # Results
    print("\n" + "=" * 60)
    print("Production Results")
    print("=" * 60)

    print(f"\nTotal Time: {total_time:.2f}s")
    print(f"Throughput: {total_throughput:.2f} operations/sec")

    print("\nOperation Breakdown:")
    for op, times in operations.items():
        if times:
            print(f"\n  {op.upper()}:")
            print(f"    Count: {len(times)}")
            print(f"    Mean: {np.mean(times):.2f}ms ± {np.std(times):.2f}ms")
            print(f"    Min/Max: {np.min(times):.2f}ms / {np.max(times):.2f}ms")
            print(f"    P95: {np.percentile(times, 95):.2f}ms")

    # Get lattice stats
    stats = lattice.get_performance_stats()
    print("\nLattice Statistics:")
    print(f"  Total computations: {stats['total_computations']}")
    print(f"  Successful: {stats['successful_computations']}")
    print(f"  Failed: {stats['failed_computations']}")
    print(f"  Success rate: {stats['success_rate']:.1f}%")
    print(f"  Average latency: {stats['average_latency_ms']:.2f}ms")

    # Shutdown
    print("\n5. Shutting down lattice...")
    await lattice.shutdown()
    print("   ✓ Shutdown complete")

    print("\n" + "=" * 60)
    print("Test Complete!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_production())
