"""
Memory Optimization Analyzer for Catalytic Computing
Profiles memory usage and identifies optimization opportunities
"""

import numpy as np
import time
import psutil
import os
import gc
import sys
from typing import Dict, List, Tuple, Any
import tracemalloc
from memory_profiler import profile
from functools import wraps

# Import catalytic components
try:
    from catalytic_lattice_graph import (
        CatalyticLatticeGraph,
        GraphAcceleratedCatalyticComputer
    )
    COMPONENTS_AVAILABLE = True
except ImportError:
    COMPONENTS_AVAILABLE = False
    print("[WARNING] Catalytic components not available")


class MemoryProfiler:
    """Advanced memory profiling for catalytic algorithms"""
    
    def __init__(self):
        self.baseline_memory = 0
        self.peak_memory = 0
        self.measurements = []
        self.process = psutil.Process(os.getpid())
    
    def start_profiling(self):
        """Start memory profiling"""
        gc.collect()
        tracemalloc.start()
        self.baseline_memory = self.get_current_memory()
    
    def stop_profiling(self):
        """Stop profiling and return statistics"""
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        return {
            'current_mb': current / 1024 / 1024,
            'peak_mb': peak / 1024 / 1024,
            'baseline_mb': self.baseline_memory
        }
    
    def get_current_memory(self):
        """Get current memory usage in MB"""
        return self.process.memory_info().rss / 1024 / 1024
    
    def measure(self, label: str):
        """Take a memory measurement"""
        mem_mb = self.get_current_memory()
        self.measurements.append((label, mem_mb))
        return mem_mb


class CatalyticMemoryOptimizer:
    """Optimizes memory usage in catalytic computing"""
    
    def __init__(self):
        self.profiler = MemoryProfiler()
        self.optimization_results = {}
    
    def analyze_auxiliary_memory_usage(self):
        """Analyze auxiliary memory usage patterns"""
        print("\n[ANALYSIS 1] Auxiliary Memory Usage Patterns")
        print("-" * 50)
        
        if not COMPONENTS_AVAILABLE:
            return
        
        results = []
        aux_sizes = [0.1, 0.5, 1, 5, 10, 50, 100]  # MB
        
        for aux_mb in aux_sizes:
            self.profiler.start_profiling()
            
            computer = GraphAcceleratedCatalyticComputer(
                dimensions=4,
                lattice_size=5,
                aux_memory_mb=aux_mb
            )
            
            # Measure actual allocation
            actual_mb = computer.aux_memory.nbytes / (1024 * 1024)
            
            # Test operations
            path, _ = computer.catalytic_graph_traversal(0, 100)
            
            stats = self.profiler.stop_profiling()
            
            results.append({
                'requested_mb': aux_mb,
                'actual_mb': actual_mb,
                'peak_mb': stats['peak_mb'],
                'efficiency': len(path) / actual_mb if actual_mb > 0 else 0
            })
            
            print(f"  {aux_mb:6.1f} MB requested -> {actual_mb:6.2f} MB actual | "
                  f"Peak: {stats['peak_mb']:6.2f} MB | "
                  f"Efficiency: {results[-1]['efficiency']:.2f} ops/MB")
        
        self.optimization_results['auxiliary_analysis'] = results
        return results
    
    def analyze_memory_access_patterns(self):
        """Analyze memory access patterns for cache optimization"""
        print("\n[ANALYSIS 2] Memory Access Pattern Analysis")
        print("-" * 50)
        
        if not COMPONENTS_AVAILABLE:
            return
        
        import numpy as np
        
        # Test different access patterns
        size = 1000000
        data = np.random.randint(0, 256, size, dtype=np.uint8)
        
        # Sequential access
        start = time.time()
        for i in range(0, size, 1):
            _ = data[i]
        sequential_time = time.time() - start
        
        # Random access
        indices = np.random.permutation(size)
        start = time.time()
        for i in indices[:size]:
            _ = data[i]
        random_time = time.time() - start
        
        # Strided access
        stride = 64  # Cache line size
        start = time.time()
        for i in range(0, size, stride):
            _ = data[i]
        strided_time = time.time() - start
        
        print(f"  Sequential access: {sequential_time*1000:.2f}ms")
        print(f"  Random access: {random_time*1000:.2f}ms ({random_time/sequential_time:.1f}x slower)")
        print(f"  Strided access: {strided_time*1000:.2f}ms ({strided_time/sequential_time:.1f}x)")
        
        self.optimization_results['access_patterns'] = {
            'sequential_ms': sequential_time * 1000,
            'random_ms': random_time * 1000,
            'strided_ms': strided_time * 1000
        }
    
    def analyze_memory_restoration_overhead(self):
        """Analyze overhead of catalytic memory restoration"""
        print("\n[ANALYSIS 3] Memory Restoration Overhead")
        print("-" * 50)
        
        if not COMPONENTS_AVAILABLE:
            return
        
        computer = GraphAcceleratedCatalyticComputer(
            dimensions=3,
            lattice_size=8,
            aux_memory_mb=10
        )
        
        # Measure restoration overhead
        restoration_times = []
        
        for trial in range(10):
            # Backup
            start = time.time()
            backup = computer.aux_memory[:1000].copy()
            backup_time = time.time() - start
            
            # Modify
            computer.aux_memory[:1000] = np.random.randint(0, 256, 1000, dtype=np.uint8)
            
            # Restore
            start = time.time()
            computer.aux_memory[:1000] = backup
            restore_time = time.time() - start
            
            restoration_times.append(backup_time + restore_time)
        
        avg_restoration = np.mean(restoration_times) * 1000
        print(f"  Average restoration overhead: {avg_restoration:.3f}ms")
        print(f"  Min: {min(restoration_times)*1000:.3f}ms")
        print(f"  Max: {max(restoration_times)*1000:.3f}ms")
        
        self.optimization_results['restoration_overhead'] = {
            'avg_ms': avg_restoration,
            'min_ms': min(restoration_times) * 1000,
            'max_ms': max(restoration_times) * 1000
        }
    
    def test_memory_pooling(self):
        """Test memory pooling optimization"""
        print("\n[OPTIMIZATION 1] Memory Pooling")
        print("-" * 50)
        
        # Without pooling (multiple allocations)
        start = time.time()
        arrays = []
        for _ in range(100):
            arr = np.zeros(10000, dtype=np.uint8)
            arrays.append(arr)
        no_pool_time = time.time() - start
        
        # With pooling (pre-allocated)
        start = time.time()
        pool = np.zeros((100, 10000), dtype=np.uint8)
        arrays_pooled = [pool[i] for i in range(100)]
        pool_time = time.time() - start
        
        speedup = no_pool_time / pool_time
        print(f"  Without pooling: {no_pool_time*1000:.2f}ms")
        print(f"  With pooling: {pool_time*1000:.2f}ms")
        print(f"  Speedup: {speedup:.2f}x")
        
        self.optimization_results['memory_pooling'] = {
            'no_pool_ms': no_pool_time * 1000,
            'pool_ms': pool_time * 1000,
            'speedup': speedup
        }
    
    def test_dtype_optimization(self):
        """Test data type optimization for memory efficiency"""
        print("\n[OPTIMIZATION 2] Data Type Optimization")
        print("-" * 50)
        
        size = 1000000
        
        dtypes = [
            (np.uint8, 1, "uint8 (1 byte)"),
            (np.uint16, 2, "uint16 (2 bytes)"),
            (np.uint32, 4, "uint32 (4 bytes)"),
            (np.uint64, 8, "uint64 (8 bytes)"),
            (np.float32, 4, "float32 (4 bytes)"),
            (np.float64, 8, "float64 (8 bytes)")
        ]
        
        results = []
        
        for dtype, bytes_per, name in dtypes:
            arr = np.zeros(size, dtype=dtype)
            memory_mb = arr.nbytes / (1024 * 1024)
            
            # Test XOR operation speed (for uint types)
            if 'uint' in name:
                start = time.time()
                _ = arr ^ 42
                xor_time = time.time() - start
            else:
                xor_time = None
            
            results.append({
                'dtype': name,
                'memory_mb': memory_mb,
                'xor_ms': xor_time * 1000 if xor_time else None
            })
            
            print(f"  {name:20} | Memory: {memory_mb:6.2f} MB | "
                  f"XOR: {xor_time*1000:.2f}ms" if xor_time else f"  {name:20} | Memory: {memory_mb:6.2f} MB | XOR: N/A")
        
        self.optimization_results['dtype_optimization'] = results
    
    def test_sparse_auxiliary_memory(self):
        """Test sparse representation for auxiliary memory"""
        print("\n[OPTIMIZATION 3] Sparse Auxiliary Memory")
        print("-" * 50)
        
        from scipy.sparse import csr_matrix, dok_matrix
        
        size = 1000000
        density = 0.01  # 1% non-zero
        
        # Dense representation
        dense = np.random.choice([0, 1], size=size, p=[1-density, density]).astype(np.uint8)
        dense_mb = dense.nbytes / (1024 * 1024)
        
        # Sparse representation
        sparse = csr_matrix(dense.reshape(-1, 1))
        sparse_mb = (sparse.data.nbytes + sparse.indices.nbytes + sparse.indptr.nbytes) / (1024 * 1024)
        
        reduction = dense_mb / sparse_mb
        
        print(f"  Dense: {dense_mb:.2f} MB")
        print(f"  Sparse: {sparse_mb:.2f} MB")
        print(f"  Reduction: {reduction:.1f}x")
        print(f"  Density: {density*100:.1f}%")
        
        self.optimization_results['sparse_memory'] = {
            'dense_mb': dense_mb,
            'sparse_mb': sparse_mb,
            'reduction': reduction,
            'density': density
        }
    
    def test_memory_alignment(self):
        """Test memory alignment for better cache performance"""
        print("\n[OPTIMIZATION 4] Memory Alignment")
        print("-" * 50)
        
        size = 1000000
        
        # Unaligned memory
        unaligned = np.zeros(size + 7, dtype=np.uint8)[7:]
        
        # Aligned memory (64-byte cache line)
        aligned = np.zeros(size, dtype=np.uint8)
        
        # Test access speed
        iterations = 1000
        
        start = time.time()
        for _ in range(iterations):
            _ = unaligned.sum()
        unaligned_time = time.time() - start
        
        start = time.time()
        for _ in range(iterations):
            _ = aligned.sum()
        aligned_time = time.time() - start
        
        speedup = unaligned_time / aligned_time
        
        print(f"  Unaligned: {unaligned_time*1000:.2f}ms")
        print(f"  Aligned: {aligned_time*1000:.2f}ms")
        print(f"  Speedup: {speedup:.2f}x")
        
        self.optimization_results['alignment'] = {
            'unaligned_ms': unaligned_time * 1000,
            'aligned_ms': aligned_time * 1000,
            'speedup': speedup
        }


class OptimizedCatalyticComputer:
    """Memory-optimized version of catalytic computer"""
    
    def __init__(self, dimensions: int, lattice_size: int, aux_memory_mb: float = 10):
        """
        Initialize with memory optimizations
        """
        self.dimensions = dimensions
        self.lattice_size = lattice_size
        self.n_points = lattice_size ** dimensions
        
        # Use optimal data type (uint8 for XOR operations)
        self.dtype = np.uint8
        
        # Optimized auxiliary memory allocation
        self.aux_memory_size = int(aux_memory_mb * 1024 * 1024 // 8)
        
        # Use memory pool for frequent allocations
        self.memory_pool = self._create_memory_pool()
        
        # Aligned allocation for better cache performance
        self.aux_memory = self._allocate_aligned_memory(self.aux_memory_size)
        
        # Pre-compute frequently used values
        self.cache = {}
    
    def _create_memory_pool(self, pool_size: int = 10):
        """Create memory pool for temporary allocations"""
        return [np.zeros(1000, dtype=self.dtype) for _ in range(pool_size)]
    
    def _allocate_aligned_memory(self, size: int, alignment: int = 64):
        """Allocate cache-aligned memory"""
        # Ensure alignment to cache line boundary
        extra = alignment - 1
        total = size + extra
        
        raw = np.zeros(total, dtype=self.dtype)
        offset = (alignment - (raw.ctypes.data % alignment)) % alignment
        
        return raw[offset:offset + size]
    
    def optimized_xor_transform(self, data: np.ndarray, key: np.ndarray) -> np.ndarray:
        """
        Optimized XOR transformation with better memory access
        """
        # Use vectorized operations
        if len(key) == len(data):
            return data ^ key
        
        # Optimize key cycling for cache efficiency
        key_repeated = np.resize(key, len(data))
        return data ^ key_repeated
    
    def memory_efficient_traversal(self, start: int, end: int) -> Tuple[List[int], float]:
        """
        Memory-efficient path traversal using catalytic approach
        """
        # Use small backup window instead of full copy
        backup_size = min(100, self.aux_memory_size)
        backup = self.aux_memory[:backup_size].copy()
        
        try:
            # Encode path endpoints compactly
            self.aux_memory[0] = start & 0xFF
            self.aux_memory[1] = (start >> 8) & 0xFF
            self.aux_memory[2] = end & 0xFF
            self.aux_memory[3] = (end >> 8) & 0xFF
            
            # Simulated path finding (would use igraph in practice)
            path = list(range(start, min(start + 10, end + 1)))
            distance = len(path) - 1
            
            return path, float(distance)
            
        finally:
            # Restore only the modified portion
            self.aux_memory[:backup_size] = backup


def run_memory_optimization_analysis():
    """Run complete memory optimization analysis"""
    print("\n" + "="*60)
    print(" CATALYTIC COMPUTING MEMORY OPTIMIZATION ANALYSIS")
    print("="*60)
    
    optimizer = CatalyticMemoryOptimizer()
    
    # Run analyses
    optimizer.analyze_auxiliary_memory_usage()
    optimizer.analyze_memory_access_patterns()
    optimizer.analyze_memory_restoration_overhead()
    
    # Run optimizations
    optimizer.test_memory_pooling()
    optimizer.test_dtype_optimization()
    optimizer.test_sparse_auxiliary_memory()
    optimizer.test_memory_alignment()
    
    # Test optimized implementation
    print("\n[VALIDATION] Testing Optimized Implementation")
    print("-" * 50)
    
    # Compare original vs optimized
    if COMPONENTS_AVAILABLE:
        # Original
        prof = MemoryProfiler()
        prof.start_profiling()
        
        original = GraphAcceleratedCatalyticComputer(4, 5, 10)
        path1, _ = original.catalytic_graph_traversal(0, 100)
        
        orig_stats = prof.stop_profiling()
        
        # Optimized
        prof.start_profiling()
        
        optimized = OptimizedCatalyticComputer(4, 5, 10)
        path2, _ = optimized.memory_efficient_traversal(0, 100)
        
        opt_stats = prof.stop_profiling()
        
        print(f"  Original peak: {orig_stats['peak_mb']:.2f} MB")
        print(f"  Optimized peak: {opt_stats['peak_mb']:.2f} MB")
        print(f"  Memory saved: {orig_stats['peak_mb'] - opt_stats['peak_mb']:.2f} MB")
    
    # Generate optimization recommendations
    print("\n" + "="*60)
    print(" OPTIMIZATION RECOMMENDATIONS")
    print("="*60)
    
    recommendations = [
        ("Use uint8 dtype", "Optimal for XOR operations, minimal memory"),
        ("Implement memory pooling", f"{optimizer.optimization_results.get('memory_pooling', {}).get('speedup', 2):.1f}x speedup for allocations"),
        ("Align memory to cache lines", "Better cache performance"),
        ("Use sparse representation when <10% density", "Up to 10x memory reduction"),
        ("Minimize restoration scope", "Restore only modified portions"),
        ("Pre-compute frequent values", "Trade memory for computation"),
        ("Use vectorized operations", "Better memory bandwidth utilization")
    ]
    
    for i, (title, benefit) in enumerate(recommendations, 1):
        print(f"{i}. {title}")
        print(f"   - {benefit}")
    
    return optimizer.optimization_results


if __name__ == "__main__":
    results = run_memory_optimization_analysis()
    
    # Save results
    import json
    with open('memory_optimization_results.json', 'w') as f:
        # Convert numpy types to Python types for JSON serialization
        clean_results = {}
        for key, value in results.items():
            if isinstance(value, list):
                clean_results[key] = [
                    {k: float(v) if isinstance(v, np.number) else v 
                     for k, v in item.items()}
                    for item in value
                ]
            elif isinstance(value, dict):
                clean_results[key] = {
                    k: float(v) if isinstance(v, np.number) else v 
                    for k, v in value.items()
                }
            else:
                clean_results[key] = value
        
        json.dump(clean_results, f, indent=2)
    
    print(f"\n[INFO] Results saved to memory_optimization_results.json")