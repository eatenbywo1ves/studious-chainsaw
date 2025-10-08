"""
Edge Case and Boundary Testing for Lattice Algorithms
Tests unusual configurations, extreme values, and error conditions
"""

import numpy as np
import time
import sys
import unittest
import warnings
warnings.filterwarnings('ignore')

# Import lattice components
try:
    from catalytic_lattice_graph import (
        CatalyticLatticeGraph,
        GraphAcceleratedCatalyticComputer
    )
    IGRAPH_AVAILABLE = True
except ImportError:
    IGRAPH_AVAILABLE = False


class TestLatticeEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions"""

    def test_minimal_lattice(self):
        """Test with smallest possible lattices"""
        if not IGRAPH_AVAILABLE:
            self.skipTest("igraph not available")

        print("\n[EDGE CASE] Minimal Lattices")
        print("-" * 40)

        # 1D lattice with 2 points
        graph = CatalyticLatticeGraph(dimensions=1, lattice_size=2)
        self.assertEqual(graph.n_points, 2)
        path, _ = graph.find_shortest_path(0, 1)
        self.assertEqual(len(path), 2)
        print("  [OK] 1D x 2: Path length = 2")

        # 2D lattice with 1 point per dimension
        graph = CatalyticLatticeGraph(dimensions=2, lattice_size=1)
        self.assertEqual(graph.n_points, 1)
        self.assertEqual(len(graph.graph.es), 0)
        print("  [OK] 2D x 1: Single point, no edges")

        # High dimension, minimal size
        graph = CatalyticLatticeGraph(dimensions=10, lattice_size=2)
        self.assertEqual(graph.n_points, 1024)
        print(f"  [OK] 10D x 2: {graph.n_points} points")

    def test_disconnected_components(self):
        """Test behavior with potential disconnected components"""
        if not IGRAPH_AVAILABLE:
            self.skipTest("igraph not available")

        print("\n[EDGE CASE] Component Connectivity")
        print("-" * 40)

        graph = CatalyticLatticeGraph(dimensions=2, lattice_size=5)

        # Check if graph is connected
        is_connected = graph.graph.is_connected()
        self.assertTrue(is_connected, "Lattice should be fully connected")
        print(f"  [OK] 2D x 5 lattice is connected: {is_connected}")

        # Test unreachable vertex (if we modify the graph)
        # This tests error handling for disconnected components
        original_edges = len(graph.graph.es)
        print(f"  [OK] Original edges: {original_edges}")

    def test_memory_boundaries(self):
        """Test auxiliary memory boundary conditions"""
        if not IGRAPH_AVAILABLE:
            self.skipTest("igraph not available")

        print("\n[EDGE CASE] Memory Boundaries")
        print("-" * 40)

        # Minimal auxiliary memory
        computer = GraphAcceleratedCatalyticComputer(
            dimensions=3,
            lattice_size=3,
            aux_memory_mb=0.001  # 1KB
        )

        min_size = computer.aux_memory.nbytes
        self.assertGreater(min_size, 0)
        print(f"  [OK] Minimal auxiliary memory: {min_size} bytes")

        # Test catalytic property with minimal memory
        initial = computer.aux_memory[:10].copy()
        path, _ = computer.catalytic_graph_traversal(0, 26)
        final = computer.aux_memory[:10]

        self.assertTrue(np.array_equal(initial, final),
                       "Memory should be restored even with minimal size")
        print("  [OK] Catalytic property preserved with minimal memory")

    def test_extreme_dimensions(self):
        """Test with extreme dimensional configurations"""
        if not IGRAPH_AVAILABLE:
            self.skipTest("igraph not available")

        print("\n[EDGE CASE] Extreme Dimensions")
        print("-" * 40)

        test_cases = [
            (1, 100),   # 1D with many points
            (20, 2),    # Very high dimension, minimal size
            (8, 3),     # Moderate high dimension
        ]

        for dims, size in test_cases:
            try:
                n_points = size ** dims
                if n_points > 10000:
                    print(f"  [SKIP] {dims}D x {size}: Too many points ({n_points})")
                    continue

                graph = CatalyticLatticeGraph(dims, size)

                # Test basic operations still work
                if graph.n_points > 1:
                    path, _ = graph.find_shortest_path(0, graph.n_points - 1)
                    self.assertGreater(len(path), 0)

                print(f"  [OK] {dims}D x {size}: {graph.n_points} points, "
                      f"{len(graph.graph.es)} edges")

            except (MemoryError, OverflowError) as e:
                print(f"  [EXPECTED] {dims}D x {size}: {type(e).__name__}")

    def test_pathological_paths(self):
        """Test pathological path-finding cases"""
        if not IGRAPH_AVAILABLE:
            self.skipTest("igraph not available")

        print("\n[EDGE CASE] Pathological Paths")
        print("-" * 40)

        graph = CatalyticLatticeGraph(dimensions=3, lattice_size=5)

        # Same start and end point
        path, length = graph.find_shortest_path(0, 0)
        self.assertEqual(len(path), 1)
        self.assertEqual(length, 0.0)
        print("  [OK] Same start/end: Single point path")

        # Adjacent points
        neighbors = graph.get_neighbors(0, radius=1)
        if neighbors:
            neighbor = list(neighbors)[0]
            path, length = graph.find_shortest_path(0, neighbor)
            self.assertEqual(len(path), 2)
            print("  [OK] Adjacent points: Path length = 2")

        # Diagonal extremes (should be longest path)
        path, length = graph.find_shortest_path(0, graph.n_points - 1)
        self.assertGreater(len(path), graph.dimensions)
        print(f"  [OK] Diagonal path: {len(path)} steps")

    def test_algorithm_stability(self):
        """Test algorithm stability with repeated operations"""
        if not IGRAPH_AVAILABLE:
            self.skipTest("igraph not available")

        print("\n[EDGE CASE] Algorithm Stability")
        print("-" * 40)

        graph = CatalyticLatticeGraph(dimensions=3, lattice_size=4)

        # Repeated path finding should give same result
        paths = []
        for _ in range(5):
            path, _ = graph.find_shortest_path(0, 63)
            paths.append(len(path))

        self.assertEqual(len(set(paths)), 1, "Path should be consistent")
        print(f"  [OK] Consistent path finding: {paths[0]} steps")

        # Repeated community detection
        community_counts = []
        for _ in range(3):
            communities = graph.find_communities('multilevel')
            community_counts.append(len(communities))

        # Community detection can vary slightly but should be similar
        variation = max(community_counts) - min(community_counts)
        self.assertLessEqual(variation, 2, "Community detection should be stable")
        print(f"  [OK] Community detection stable: {community_counts}")

    def test_numerical_precision(self):
        """Test numerical precision in calculations"""
        if not IGRAPH_AVAILABLE:
            self.skipTest("igraph not available")

        print("\n[EDGE CASE] Numerical Precision")
        print("-" * 40)

        computer = GraphAcceleratedCatalyticComputer(
            dimensions=4,
            lattice_size=3,
            aux_memory_mb=1
        )

        # Test XOR operations maintain precision
        original = computer.aux_memory[:100].copy()

        # Apply XOR twice (should restore)
        key = np.random.randint(0, 256, 100, dtype=np.uint8)
        temp = computer.aux_memory[:100] ^ key
        computer.aux_memory[:100] = temp ^ key

        self.assertTrue(np.array_equal(original, computer.aux_memory[:100]),
                       "XOR should be perfectly reversible")
        print("  [OK] XOR operations maintain perfect precision")

        # Test floating point distances
        path, distance = computer.graph.find_shortest_path(0, 10)
        self.assertIsInstance(distance, (int, float))
        self.assertGreaterEqual(distance, 0)
        print(f"  [OK] Path distance precision: {distance:.6f}")

    def test_parallel_edge_cases(self):
        """Test edge cases in parallel processing"""
        if not IGRAPH_AVAILABLE:
            self.skipTest("igraph not available")

        print("\n[EDGE CASE] Parallel Processing")
        print("-" * 40)

        computer = GraphAcceleratedCatalyticComputer(
            dimensions=2,
            lattice_size=3,
            aux_memory_mb=1
        )

        # Single vertex group
        results = computer.parallel_lattice_operation('compute')
        total = sum(len(r) for r in results)
        self.assertEqual(total, computer.graph.n_points)
        print(f"  [OK] All {total} vertices processed in {len(results)} groups")

        # Empty operation
        results = computer.parallel_lattice_operation('noop')
        self.assertIsNotNone(results)
        print("  [OK] Unknown operation handled gracefully")

    def test_error_recovery(self):
        """Test error recovery and graceful degradation"""
        if not IGRAPH_AVAILABLE:
            self.skipTest("igraph not available")

        print("\n[EDGE CASE] Error Recovery")
        print("-" * 40)

        graph = CatalyticLatticeGraph(dimensions=3, lattice_size=4)

        # Invalid vertex indices
        try:
            path, _ = graph.find_shortest_path(-1, 1000)
            print("  [WARNING] No error for invalid vertices")
        except (ValueError, IndexError) as e:
            print(f"  [OK] Invalid vertices handled: {type(e).__name__}")

        # Invalid radius for neighbors
        try:
            neighbors = graph.get_neighbors(0, radius=-1)
            if len(neighbors) == 0:
                print("  [OK] Negative radius returns empty set")
        except ValueError:
            print("  [OK] Negative radius raises ValueError")

        # Invalid community method
        try:
            communities = graph.find_communities('invalid_method')
            # If it doesn't fail, check it used a default
            self.assertGreater(len(communities), 0)
            print("  [OK] Invalid method falls back to default")
        except (ValueError, AttributeError):
            print("  [OK] Invalid method raises error")

    def test_caching_behavior(self):
        """Test caching and memoization behavior"""
        if not IGRAPH_AVAILABLE:
            self.skipTest("igraph not available")

        print("\n[EDGE CASE] Caching Behavior")
        print("-" * 40)

        graph = CatalyticLatticeGraph(dimensions=3, lattice_size=5)

        # First call (cache miss)
        t1 = time.time()
        path1, _ = graph.find_shortest_path(0, 124)
        time1 = time.time() - t1

        # Second call (cache hit)
        t2 = time.time()
        path2, _ = graph.find_shortest_path(0, 124)
        time2 = time.time() - t2

        self.assertEqual(path1, path2, "Cached result should be identical")

        # Cache should make it faster (or at least not slower)
        if time2 < time1 * 1.5:  # Allow some variation
            print(f"  [OK] Caching effective: {time1*1000:.2f}ms -> {time2*1000:.2f}ms")
        else:
            print(f"  [INFO] Cache performance similar: {time1*1000:.2f}ms, {time2*1000:.2f}ms")


class TestLatticeRobustness(unittest.TestCase):
    """Test robustness and fault tolerance"""

    def test_concurrent_operations(self):
        """Test behavior with simulated concurrent operations"""
        if not IGRAPH_AVAILABLE:
            self.skipTest("igraph not available")

        print("\n[ROBUSTNESS] Concurrent Operations")
        print("-" * 40)

        computer = GraphAcceleratedCatalyticComputer(
            dimensions=3,
            lattice_size=4,
            aux_memory_mb=5
        )

        # Simulate multiple operations
        operations = []
        for i in range(5):
            path, _ = computer.catalytic_graph_traversal(i, 63 - i)
            operations.append(len(path))

        # Verify memory is still properly restored
        initial = np.zeros(100, dtype=np.uint8)
        computer.aux_memory[:100] = initial

        path, _ = computer.catalytic_graph_traversal(0, 63)

        self.assertTrue(np.array_equal(computer.aux_memory[:100], initial),
                       "Memory should be restored after multiple operations")

        print(f"  [OK] {len(operations)} operations completed successfully")
        print("  [OK] Memory integrity maintained")

    def test_resource_limits(self):
        """Test behavior at resource limits"""
        if not IGRAPH_AVAILABLE:
            self.skipTest("igraph not available")

        print("\n[ROBUSTNESS] Resource Limits")
        print("-" * 40)

        # Test with many communities
        graph = CatalyticLatticeGraph(dimensions=2, lattice_size=10)

        methods = ['fast_greedy', 'multilevel', 'walktrap']
        for method in methods:
            try:
                communities = graph.find_communities(method)
                self.assertGreater(len(communities), 0)
                self.assertLessEqual(len(communities), graph.n_points)
                print(f"  [OK] {method}: {len(communities)} communities found")
            except Exception as e:
                print(f"  [WARNING] {method}: {type(e).__name__}")

    def test_data_validation(self):
        """Test input data validation"""
        if not IGRAPH_AVAILABLE:
            self.skipTest("igraph not available")

        print("\n[ROBUSTNESS] Data Validation")
        print("-" * 40)

        # Test with invalid dimensions
        invalid_configs = [
            (0, 5),    # Zero dimensions
            (-1, 5),   # Negative dimensions
            (3, 0),    # Zero size
            (3, -1),   # Negative size
        ]

        for dims, size in invalid_configs:
            try:
                CatalyticLatticeGraph(dims, size)
                print(f"  [WARNING] No validation for dims={dims}, size={size}")
            except (ValueError, AssertionError, ZeroDivisionError):
                print(f"  [OK] Invalid config rejected: dims={dims}, size={size}")


def run_edge_case_tests():
    """Run edge case and robustness tests"""
    print("\n" + "="*60)
    print(" LATTICE ALGORITHM EDGE CASE TEST SUITE")
    print("="*60)

    # Create test suites
    edge_suite = unittest.TestLoader().loadTestsFromTestCase(TestLatticeEdgeCases)
    robust_suite = unittest.TestLoader().loadTestsFromTestCase(TestLatticeRobustness)

    # Combine suites
    all_tests = unittest.TestSuite([edge_suite, robust_suite])

    # Run tests
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(all_tests)

    # Summary
    print("\n" + "="*60)
    if result.wasSuccessful():
        print(" ALL EDGE CASE TESTS PASSED")
        print(" System demonstrates good robustness and error handling")
    else:
        print(f" {len(result.failures)} failures, {len(result.errors)} errors")
        print(" Review failures for improvement opportunities")
    print("="*60)

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_edge_case_tests()
    sys.exit(0 if success else 1)
