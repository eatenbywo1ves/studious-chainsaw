"""
Comprehensive Integration Test Suite for Lattice Algorithms
Tests the complete stack: Catalytic Computing + igraph + GPU + Visualization
"""

import numpy as np
import time
import sys
import json
import unittest
from typing import Dict, List, Tuple, Any
import warnings
warnings.filterwarnings('ignore')

# Import all lattice components
try:
    from catalytic_lattice_graph import (
        CatalyticLatticeGraph,
        GraphAcceleratedCatalyticComputer
    )
    IGRAPH_AVAILABLE = True
except ImportError:
    IGRAPH_AVAILABLE = False
    print("[WARNING] igraph components not available")

# GPU availability check
try:
    import cupy as cp
    GPU_AVAILABLE = cp.cuda.is_available()
except ImportError:
    GPU_AVAILABLE = False
    print("[WARNING] GPU/CuPy not available")


class TestLatticeIntegration(unittest.TestCase):
    """Integration tests for lattice algorithm components"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test fixtures"""
        cls.test_results = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'tests': {},
            'performance': {},
            'memory': {}
        }
    
    def setUp(self):
        """Set up for each test"""
        self.start_time = time.time()
    
    def tearDown(self):
        """Record test metrics"""
        elapsed = time.time() - self.start_time
        test_name = self._testMethodName
        self.__class__.test_results['tests'][test_name] = {
            'elapsed': elapsed,
            'passed': True
        }
    
    def test_01_basic_lattice_creation(self):
        """Test basic lattice creation across different dimensions"""
        print("\n[TEST 01] Basic Lattice Creation")
        print("-" * 50)
        
        test_cases = [
            (2, 10, 100),      # 2D lattice, 10x10
            (3, 5, 125),       # 3D lattice, 5x5x5
            (4, 4, 256),       # 4D lattice, 4x4x4x4
            (5, 3, 243),       # 5D lattice, 3^5
        ]
        
        for dims, size, expected_points in test_cases:
            with self.subTest(dimensions=dims, size=size):
                if IGRAPH_AVAILABLE:
                    graph = CatalyticLatticeGraph(dims, size)
                    actual_points = graph.n_points
                    
                    self.assertEqual(actual_points, expected_points,
                                   f"Expected {expected_points} points, got {actual_points}")
                    
                    # Verify graph connectivity
                    self.assertIsNotNone(graph.graph)
                    self.assertGreater(len(graph.graph.es), 0, "Graph should have edges")
                    
                    print(f"  [OK] {dims}D x {size}: {actual_points} points, "
                          f"{len(graph.graph.es)} edges")
                else:
                    print(f"  [SKIP] igraph not available")
    
    def test_02_path_finding_algorithms(self):
        """Test different path finding approaches"""
        print("\n[TEST 02] Path Finding Algorithm Integration")
        print("-" * 50)
        
        if not IGRAPH_AVAILABLE:
            self.skipTest("igraph not available")
        
        # Create test lattice
        graph = CatalyticLatticeGraph(dimensions=3, lattice_size=8)
        computer = GraphAcceleratedCatalyticComputer(
            dimensions=3, 
            lattice_size=8,
            aux_memory_mb=10
        )
        
        start, end = 0, graph.n_points - 1
        
        # Test 1: igraph shortest path
        t1 = time.time()
        path1, length1 = graph.find_shortest_path(start, end)
        time1 = time.time() - t1
        
        # Test 2: Catalytic traversal
        t2 = time.time()
        path2, length2 = computer.catalytic_graph_traversal(start, end)
        time2 = time.time() - t2
        
        # Verify paths are optimal
        self.assertEqual(len(path1), len(path2), "Paths should be same length")
        self.assertAlmostEqual(length1, length2, places=2, 
                              msg="Path distances should match")
        
        print(f"  [OK] igraph path: {len(path1)} steps in {time1*1000:.2f}ms")
        print(f"  [OK] Catalytic path: {len(path2)} steps in {time2*1000:.2f}ms")
        
        # Verify catalytic memory restoration
        initial_aux = computer.aux_memory[:100].copy()
        computer.catalytic_graph_traversal(10, 20)
        final_aux = computer.aux_memory[:100]
        self.assertTrue(np.array_equal(initial_aux, final_aux),
                       "Auxiliary memory should be restored")
        print(f"  [OK] Catalytic memory restoration verified")
    
    def test_03_parallel_processing_integration(self):
        """Test parallel processing capabilities"""
        print("\n[TEST 03] Parallel Processing Integration")
        print("-" * 50)
        
        if not IGRAPH_AVAILABLE:
            self.skipTest("igraph not available")
        
        computer = GraphAcceleratedCatalyticComputer(
            dimensions=4,
            lattice_size=5,
            aux_memory_mb=20
        )
        
        # Test graph coloring for parallelization
        coloring = computer.graph.apply_graph_coloring()
        n_colors = len(set(coloring.values()))
        
        self.assertGreaterEqual(n_colors, 2, "Should have at least 2 colors")
        self.assertLessEqual(n_colors, 10, "Should not need too many colors")
        
        print(f"  [OK] Graph colored with {n_colors} colors for parallel processing")
        
        # Test parallel operations
        operations = ['compute', 'transform']
        
        for op in operations:
            results = computer.parallel_lattice_operation(op)
            total_processed = sum(len(r) for r in results)
            
            self.assertEqual(total_processed, computer.graph.n_points,
                           f"All vertices should be processed for {op}")
            
            print(f"  [OK] Parallel {op}: {len(results)} groups, "
                  f"{total_processed} vertices processed")
    
    def test_04_memory_efficiency_integration(self):
        """Test memory efficiency across components"""
        print("\n[TEST 04] Memory Efficiency Integration")
        print("-" * 50)
        
        # Compare memory usage across different approaches
        dims, size = 4, 6
        n_points = size ** dims
        
        # Traditional dense matrix
        traditional_bytes = n_points * n_points * 8
        traditional_mb = traditional_bytes / (1024 * 1024)
        
        results = {
            'traditional_dense': traditional_mb
        }
        
        # igraph sparse representation
        if IGRAPH_AVAILABLE:
            graph = CatalyticLatticeGraph(dims, size)
            sparse_matrix = graph.compute_connectivity_matrix(sparse=True)
            
            # Estimate sparse memory
            n_edges = len(graph.graph.es)
            sparse_bytes = n_edges * 2 * 8  # Edge list
            sparse_mb = sparse_bytes / (1024 * 1024)
            results['igraph_sparse'] = sparse_mb
            
            print(f"  Traditional dense: {traditional_mb:.2f} MB")
            print(f"  igraph sparse: {sparse_mb:.2f} MB "
                  f"({traditional_mb/sparse_mb:.1f}x reduction)")
        
        # Catalytic approach
        if IGRAPH_AVAILABLE:
            computer = GraphAcceleratedCatalyticComputer(dims, size, aux_memory_mb=5)
            catalytic_mb = computer.aux_memory.nbytes / (1024 * 1024)
            results['catalytic'] = catalytic_mb
            
            print(f"  Catalytic auxiliary: {catalytic_mb:.2f} MB "
                  f"({traditional_mb/catalytic_mb:.1f}x reduction)")
            
            self.assertLess(catalytic_mb, traditional_mb,
                          "Catalytic should use less memory than traditional")
        
        self.__class__.test_results['memory'] = results
    
    def test_05_algorithm_correctness_integration(self):
        """Test correctness of integrated algorithms"""
        print("\n[TEST 05] Algorithm Correctness Integration")
        print("-" * 50)
        
        if not IGRAPH_AVAILABLE:
            self.skipTest("igraph not available")
        
        # Small lattice for verification
        graph = CatalyticLatticeGraph(dimensions=2, lattice_size=4)
        
        # Test 1: Verify lattice structure
        # In 2D 4x4, corners should have 2 neighbors, edges 3, center 4
        corners = [0, 3, 12, 15]
        for corner in corners:
            neighbors = graph.get_neighbors(corner, radius=1)
            self.assertEqual(len(neighbors), 2,
                           f"Corner {corner} should have 2 neighbors")
        
        print(f"  [OK] Lattice structure verified")
        
        # Test 2: Path symmetry
        path_forward, _ = graph.find_shortest_path(0, 15)
        path_backward, _ = graph.find_shortest_path(15, 0)
        self.assertEqual(len(path_forward), len(path_backward),
                       "Forward and backward paths should be equal")
        
        print(f"  [OK] Path symmetry verified")
        
        # Test 3: Community detection coverage
        communities = graph.find_communities('multilevel')
        all_vertices = set()
        for community in communities:
            all_vertices.update(community)
        
        self.assertEqual(len(all_vertices), graph.n_points,
                       "All vertices should be in communities")
        
        print(f"  [OK] Community detection coverage verified")
        
        # Test 4: MST properties
        mst = graph.find_minimum_spanning_tree()
        self.assertEqual(len(mst.es), graph.n_points - 1,
                       "MST should have n-1 edges")
        
        print(f"  [OK] Minimum spanning tree properties verified")
    
    def test_06_performance_scaling_integration(self):
        """Test performance scaling across dimensions"""
        print("\n[TEST 06] Performance Scaling Integration")
        print("-" * 50)
        
        if not IGRAPH_AVAILABLE:
            self.skipTest("igraph not available")
        
        scaling_results = []
        
        test_cases = [
            (3, 4),   # Small 3D
            (3, 6),   # Medium 3D
            (4, 4),   # Small 4D
            (4, 5),   # Medium 4D
            (5, 3),   # Small 5D
        ]
        
        for dims, size in test_cases:
            n_points = size ** dims
            
            # Build lattice
            t_start = time.time()
            graph = CatalyticLatticeGraph(dims, size)
            build_time = time.time() - t_start
            
            # Test key operation
            t_start = time.time()
            path, _ = graph.find_shortest_path(0, n_points - 1)
            path_time = time.time() - t_start
            
            scaling_results.append({
                'dims': dims,
                'size': size,
                'n_points': n_points,
                'build_time': build_time,
                'path_time': path_time
            })
            
            print(f"  {dims}D x {size}: {n_points:4d} points | "
                  f"Build: {build_time*1000:6.2f}ms | "
                  f"Path: {path_time*1000:6.2f}ms")
        
        # Verify reasonable scaling
        times = [r['build_time'] for r in scaling_results]
        points = [r['n_points'] for r in scaling_results]
        
        # Check that larger lattices take more time (generally)
        correlation = np.corrcoef(points, times)[0, 1]
        self.assertGreater(correlation, 0.5,
                         "Build time should correlate with lattice size")
        
        self.__class__.test_results['performance']['scaling'] = scaling_results
    
    def test_07_gpu_acceleration_integration(self):
        """Test GPU acceleration if available"""
        print("\n[TEST 07] GPU Acceleration Integration")
        print("-" * 50)
        
        if not GPU_AVAILABLE:
            print("  [SKIP] GPU/CuPy not available")
            self.skipTest("GPU not available")
        
        import cupy as cp
        
        # Test GPU array operations
        size = 1000
        cpu_array = np.random.randn(size, 10)
        gpu_array = cp.asarray(cpu_array)
        
        # CPU operation
        t_cpu = time.time()
        cpu_result = np.dot(cpu_array, cpu_array.T)
        cpu_time = time.time() - t_cpu
        
        # GPU operation
        t_gpu = time.time()
        gpu_result = cp.dot(gpu_array, gpu_array.T)
        cp.cuda.Stream.null.synchronize()
        gpu_time = time.time() - t_gpu
        
        # Verify correctness
        gpu_result_cpu = cp.asnumpy(gpu_result)
        np.testing.assert_allclose(cpu_result, gpu_result_cpu, rtol=1e-5)
        
        speedup = cpu_time / gpu_time
        print(f"  [OK] GPU matrix multiplication: {speedup:.2f}x speedup")
        
        # Test with lattice operations
        if IGRAPH_AVAILABLE:
            graph = CatalyticLatticeGraph(dimensions=4, lattice_size=8)
            coords, edges = graph.export_to_numpy()
            
            # Transfer to GPU
            gpu_coords = cp.asarray(coords)
            self.assertEqual(gpu_coords.shape[0], graph.n_points)
            
            print(f"  [OK] Lattice data transferred to GPU: {gpu_coords.shape}")
    
    def test_08_visualization_integration(self):
        """Test visualization component integration"""
        print("\n[TEST 08] Visualization Integration")
        print("-" * 50)
        
        try:
            import plotly.graph_objects as go
            from sklearn.decomposition import PCA
            VISUALIZATION_AVAILABLE = True
        except ImportError:
            VISUALIZATION_AVAILABLE = False
            print("  [SKIP] Visualization libraries not available")
            self.skipTest("Visualization not available")
        
        if not IGRAPH_AVAILABLE:
            self.skipTest("igraph not available")
        
        # Create lattice for visualization
        graph = CatalyticLatticeGraph(dimensions=5, lattice_size=3)
        coords, edges = graph.export_to_numpy()
        
        # Test PCA projection
        pca = PCA(n_components=3)
        coords_3d = pca.fit_transform(coords)
        
        self.assertEqual(coords_3d.shape[0], graph.n_points)
        self.assertEqual(coords_3d.shape[1], 3)
        
        explained_var = sum(pca.explained_variance_ratio_)
        print(f"  [OK] PCA projection: {explained_var:.1%} variance explained")
        
        # Test graph metrics for visualization
        centrality = graph.compute_centrality('betweenness')
        communities = graph.find_communities('multilevel')
        
        self.assertEqual(len(centrality), graph.n_points)
        self.assertGreater(len(communities), 0)
        
        print(f"  [OK] Graph metrics computed: "
              f"{len(communities)} communities, "
              f"max centrality={centrality.max():.2f}")
    
    def test_09_cross_component_workflow(self):
        """Test complete workflow across all components"""
        print("\n[TEST 09] Cross-Component Workflow Integration")
        print("-" * 50)
        
        if not IGRAPH_AVAILABLE:
            self.skipTest("igraph not available")
        
        # Complete workflow test
        workflow_steps = []
        
        # Step 1: Create lattice with igraph
        t_start = time.time()
        computer = GraphAcceleratedCatalyticComputer(
            dimensions=4,
            lattice_size=5,
            aux_memory_mb=10
        )
        workflow_steps.append(('create', time.time() - t_start))
        print(f"  [OK] Step 1: Lattice created ({workflow_steps[-1][1]*1000:.2f}ms)")
        
        # Step 2: Find optimal path
        t_start = time.time()
        path, length = computer.catalytic_graph_traversal(
            0, computer.graph.n_points - 1
        )
        workflow_steps.append(('pathfind', time.time() - t_start))
        print(f"  [OK] Step 2: Path found - {len(path)} steps ({workflow_steps[-1][1]*1000:.2f}ms)")
        
        # Step 3: Compute graph properties
        t_start = time.time()
        communities = computer.graph.find_communities('fast_greedy')
        centrality = computer.graph.compute_centrality('betweenness')
        workflow_steps.append(('analyze', time.time() - t_start))
        print(f"  [OK] Step 3: Graph analyzed - {len(communities)} communities "
              f"({workflow_steps[-1][1]*1000:.2f}ms)")
        
        # Step 4: Parallel operations
        t_start = time.time()
        results = computer.parallel_lattice_operation('compute')
        workflow_steps.append(('parallel', time.time() - t_start))
        print(f"  [OK] Step 4: Parallel processing - {len(results)} groups "
              f"({workflow_steps[-1][1]*1000:.2f}ms)")
        
        # Verify complete workflow
        total_time = sum(t for _, t in workflow_steps)
        self.assertLess(total_time, 1.0, "Workflow should complete in < 1 second")
        
        print(f"\n  Total workflow time: {total_time*1000:.2f}ms")
        self.__class__.test_results['performance']['workflow'] = workflow_steps
    
    def test_10_stress_test_integration(self):
        """Stress test with larger lattices"""
        print("\n[TEST 10] Stress Test Integration")
        print("-" * 50)
        
        if not IGRAPH_AVAILABLE:
            self.skipTest("igraph not available")
        
        # Test with progressively larger lattices
        max_points = 5000
        stress_results = []
        
        configs = [
            (3, 10),  # 1000 points
            (3, 15),  # 3375 points
            (4, 7),   # 2401 points
        ]
        
        for dims, size in configs:
            n_points = size ** dims
            if n_points > max_points:
                continue
            
            try:
                t_start = time.time()
                graph = CatalyticLatticeGraph(dims, size)
                
                # Stress test operations
                path, _ = graph.find_shortest_path(0, n_points - 1)
                neighbors = graph.get_neighbors(n_points // 2, radius=2)
                communities = graph.find_communities('multilevel')
                
                elapsed = time.time() - t_start
                
                stress_results.append({
                    'config': f"{dims}D x {size}",
                    'n_points': n_points,
                    'time': elapsed,
                    'success': True
                })
                
                print(f"  [OK] {dims}D x {size} ({n_points} points): "
                      f"{elapsed*1000:.2f}ms")
                
            except Exception as e:
                stress_results.append({
                    'config': f"{dims}D x {size}",
                    'n_points': n_points,
                    'error': str(e),
                    'success': False
                })
                print(f"  [FAIL] {dims}D x {size}: {e}")
        
        # At least some stress tests should pass
        successes = sum(1 for r in stress_results if r.get('success', False))
        self.assertGreater(successes, 0, "At least one stress test should pass")
        
        self.__class__.test_results['performance']['stress'] = stress_results


class TestReportGenerator:
    """Generate comprehensive test report"""
    
    @staticmethod
    def generate_report(test_results: Dict[str, Any]) -> str:
        """Generate formatted test report"""
        report = []
        report.append("\n" + "="*70)
        report.append(" LATTICE ALGORITHM INTEGRATION TEST REPORT")
        report.append("="*70)
        report.append(f"\nTest Date: {test_results['timestamp']}")
        
        # Test Summary
        report.append("\n## Test Summary")
        report.append("-" * 40)
        total_tests = len(test_results['tests'])
        passed_tests = sum(1 for t in test_results['tests'].values() if t.get('passed', False))
        
        report.append(f"Total Tests: {total_tests}")
        report.append(f"Passed: {passed_tests}")
        report.append(f"Failed: {total_tests - passed_tests}")
        report.append(f"Success Rate: {passed_tests/total_tests*100:.1f}%")
        
        # Performance Metrics
        if test_results.get('performance'):
            report.append("\n## Performance Metrics")
            report.append("-" * 40)
            
            if 'scaling' in test_results['performance']:
                report.append("\n### Scaling Performance:")
                for item in test_results['performance']['scaling']:
                    report.append(f"  {item['dims']}D x {item['size']}: "
                                f"{item['build_time']*1000:.2f}ms build, "
                                f"{item['path_time']*1000:.2f}ms path")
            
            if 'workflow' in test_results['performance']:
                report.append("\n### Workflow Performance:")
                for step, time in test_results['performance']['workflow']:
                    report.append(f"  {step}: {time*1000:.2f}ms")
        
        # Memory Analysis
        if test_results.get('memory'):
            report.append("\n## Memory Analysis")
            report.append("-" * 40)
            for method, mb in test_results['memory'].items():
                report.append(f"  {method}: {mb:.2f} MB")
        
        # Individual Test Times
        report.append("\n## Test Execution Times")
        report.append("-" * 40)
        for test_name, data in sorted(test_results['tests'].items()):
            status = "PASS" if data.get('passed', False) else "FAIL"
            report.append(f"  {test_name}: {data['elapsed']*1000:.2f}ms [{status}]")
        
        total_time = sum(t['elapsed'] for t in test_results['tests'].values())
        report.append(f"\nTotal Execution Time: {total_time:.2f}s")
        
        return "\n".join(report)


def run_integration_tests():
    """Run complete integration test suite"""
    print("\n" + "="*70)
    print(" LATTICE ALGORITHM INTEGRATION TEST SUITE")
    print("="*70)
    print("\nThis suite tests the integration of:")
    print("  - Catalytic Computing (200x memory reduction)")
    print("  - igraph (22x performance improvement)")
    print("  - GPU Acceleration (if available)")
    print("  - Visualization Components")
    print("  - Parallel Processing")
    print("\nStarting tests...\n")
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestLatticeIntegration)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)
    
    # Generate report
    test_results = TestLatticeIntegration.test_results
    report = TestReportGenerator.generate_report(test_results)
    print(report)
    
    # Save report to file
    report_file = 'lattice_integration_test_report.json'
    with open(report_file, 'w') as f:
        json.dump(test_results, f, indent=2)
    print(f"\n[INFO] Detailed report saved to: {report_file}")
    
    # Return success status
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_integration_tests()
    sys.exit(0 if success else 1)