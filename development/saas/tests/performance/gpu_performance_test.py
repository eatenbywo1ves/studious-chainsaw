"""
GPU Performance validation tests for Catalytic Computing platform
"""
import time
import requests
import json
import os
import subprocess
import sys
from typing import Dict, List

class GPUPerformanceTest:
    """GPU performance testing and validation"""

    def __init__(self, api_base_url: str = None):
        self.api_base_url = api_base_url or os.getenv('API_BASE_URL', 'http://localhost:8000')
        self.results = {}

    def check_gpu_availability(self) -> bool:
        """Check if GPU is available and accessible"""
        try:
            # Try to import GPU libraries
            import GPUtil
            gpus = GPUtil.getGPUs()
            return len(gpus) > 0
        except ImportError:
            print("GPUtil not available, trying nvidia-smi")
            try:
                result = subprocess.run(['nvidia-smi'],
                                      capture_output=True,
                                      text=True,
                                      timeout=10)
                return result.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError):
                return False

    def get_gpu_info(self) -> List[Dict]:
        """Get GPU information"""
        gpu_info = []
        try:
            import GPUtil
            gpus = GPUtil.getGPUs()
            for gpu in gpus:
                gpu_info.append({
                    'id': gpu.id,
                    'name': gpu.name,
                    'memory_total': gpu.memoryTotal,
                    'memory_used': gpu.memoryUsed,
                    'memory_free': gpu.memoryFree,
                    'temperature': gpu.temperature,
                    'load': gpu.load
                })
        except ImportError:
            try:
                result = subprocess.run(['nvidia-smi', '--query-gpu=index,name,memory.total,memory.used,memory.free,temperature.gpu,utilization.gpu', '--format=csv,noheader,nounits'],
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        parts = line.split(', ')
                        if len(parts) >= 7:
                            gpu_info.append({
                                'id': int(parts[0]),
                                'name': parts[1],
                                'memory_total': int(parts[2]),
                                'memory_used': int(parts[3]),
                                'memory_free': int(parts[4]),
                                'temperature': int(parts[5]) if parts[5] != '[Not Supported]' else 0,
                                'load': float(parts[6]) / 100.0 if parts[6] != '[Not Supported]' else 0
                            })
            except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
                pass

        return gpu_info

    def test_gpu_compute_performance(self) -> Dict:
        """Test GPU compute performance"""
        print("Testing GPU compute performance...")

        test_payload = {
            "operation": "matrix_multiply",
            "size": 1000,
            "iterations": 100,
            "use_gpu": True
        }

        try:
            start_time = time.time()
            response = requests.post(
                f"{self.api_base_url}/api/compute/gpu-test",
                json=test_payload,
                timeout=60
            )
            end_time = time.time()

            if response.status_code == 200:
                result = response.json()
                execution_time = end_time - start_time

                return {
                    "status": "success",
                    "execution_time": execution_time,
                    "gpu_execution_time": result.get("gpu_time", 0),
                    "operations_per_second": result.get("ops_per_second", 0),
                    "memory_usage": result.get("memory_usage", {}),
                    "throughput": result.get("throughput", 0)
                }
            else:
                return {
                    "status": "failed",
                    "error": f"HTTP {response.status_code}: {response.text}"
                }

        except requests.RequestException as e:
            return {
                "status": "failed",
                "error": f"Request failed: {str(e)}"
            }
        except Exception as e:
            return {
                "status": "failed",
                "error": f"Unexpected error: {str(e)}"
            }

    def test_gpu_memory_bandwidth(self) -> Dict:
        """Test GPU memory bandwidth"""
        print("Testing GPU memory bandwidth...")

        test_payload = {
            "operation": "memory_bandwidth",
            "data_size": 1024 * 1024 * 100,  # 100MB
            "iterations": 50
        }

        try:
            response = requests.post(
                f"{self.api_base_url}/api/compute/gpu-memory-test",
                json=test_payload,
                timeout=30
            )

            if response.status_code == 200:
                result = response.json()
                return {
                    "status": "success",
                    "bandwidth_gbps": result.get("bandwidth_gbps", 0),
                    "latency_ms": result.get("latency_ms", 0),
                    "memory_efficiency": result.get("efficiency", 0)
                }
            else:
                return {
                    "status": "failed",
                    "error": f"HTTP {response.status_code}: {response.text}"
                }

        except requests.RequestException as e:
            return {
                "status": "failed",
                "error": f"Request failed: {str(e)}"
            }

    def test_concurrent_gpu_usage(self) -> Dict:
        """Test concurrent GPU usage"""
        print("Testing concurrent GPU usage...")

        import concurrent.futures

        def run_gpu_task(task_id: int) -> Dict:
            """Run a single GPU task"""
            test_payload = {
                "operation": "concurrent_test",
                "task_id": task_id,
                "size": 500,
                "iterations": 20
            }

            try:
                response = requests.post(
                    f"{self.api_base_url}/api/compute/gpu-concurrent",
                    json=test_payload,
                    timeout=30
                )

                if response.status_code == 200:
                    return {
                        "task_id": task_id,
                        "status": "success",
                        "result": response.json()
                    }
                else:
                    return {
                        "task_id": task_id,
                        "status": "failed",
                        "error": f"HTTP {response.status_code}"
                    }
            except Exception as e:
                return {
                    "task_id": task_id,
                    "status": "failed",
                    "error": str(e)
                }

        # Run multiple concurrent tasks
        num_tasks = 4
        start_time = time.time()

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_tasks) as executor:
            futures = [executor.submit(run_gpu_task, i) for i in range(num_tasks)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]

        end_time = time.time()

        successful_tasks = [r for r in results if r["status"] == "success"]
        failed_tasks = [r for r in results if r["status"] == "failed"]

        return {
            "total_tasks": num_tasks,
            "successful_tasks": len(successful_tasks),
            "failed_tasks": len(failed_tasks),
            "total_time": end_time - start_time,
            "success_rate": len(successful_tasks) / num_tasks * 100,
            "results": results
        }

    def validate_gpu_performance_baseline(self) -> Dict:
        """Validate GPU performance against baseline requirements"""
        print("Validating GPU performance against baseline...")

        # Define performance baselines
        baselines = {
            "min_compute_ops_per_second": 1000000,  # 1M ops/sec
            "min_memory_bandwidth_gbps": 100,       # 100 GB/s
            "max_latency_ms": 10,                   # 10ms
            "min_concurrent_success_rate": 90,      # 90% success rate
            "max_memory_usage_percent": 80          # 80% memory usage
        }

        results = {
            "baseline_validation": {},
            "overall_status": "unknown"
        }

        # Test compute performance
        compute_result = self.test_gpu_compute_performance()
        if compute_result["status"] == "success":
            ops_per_second = compute_result.get("operations_per_second", 0)
            results["baseline_validation"]["compute_performance"] = {
                "measured": ops_per_second,
                "baseline": baselines["min_compute_ops_per_second"],
                "passed": ops_per_second >= baselines["min_compute_ops_per_second"]
            }

        # Test memory bandwidth
        memory_result = self.test_gpu_memory_bandwidth()
        if memory_result["status"] == "success":
            bandwidth = memory_result.get("bandwidth_gbps", 0)
            latency = memory_result.get("latency_ms", float('inf'))

            results["baseline_validation"]["memory_bandwidth"] = {
                "measured": bandwidth,
                "baseline": baselines["min_memory_bandwidth_gbps"],
                "passed": bandwidth >= baselines["min_memory_bandwidth_gbps"]
            }

            results["baseline_validation"]["memory_latency"] = {
                "measured": latency,
                "baseline": baselines["max_latency_ms"],
                "passed": latency <= baselines["max_latency_ms"]
            }

        # Test concurrent performance
        concurrent_result = self.test_concurrent_gpu_usage()
        success_rate = concurrent_result.get("success_rate", 0)
        results["baseline_validation"]["concurrent_success_rate"] = {
            "measured": success_rate,
            "baseline": baselines["min_concurrent_success_rate"],
            "passed": success_rate >= baselines["min_concurrent_success_rate"]
        }

        # Determine overall status
        all_tests_passed = all(
            test.get("passed", False)
            for test in results["baseline_validation"].values()
        )
        results["overall_status"] = "passed" if all_tests_passed else "failed"

        return results

    def run_full_test_suite(self) -> Dict:
        """Run the complete GPU performance test suite"""
        print("=== GPU Performance Test Suite ===")

        suite_results = {
            "timestamp": time.time(),
            "gpu_available": self.check_gpu_availability(),
            "gpu_info": self.get_gpu_info(),
            "tests": {}
        }

        if not suite_results["gpu_available"]:
            print("❌ No GPU available - skipping GPU performance tests")
            suite_results["status"] = "skipped"
            return suite_results

        print(f"✅ Found {len(suite_results['gpu_info'])} GPU(s)")
        for gpu in suite_results['gpu_info']:
            print(f"  - {gpu['name']} (Memory: {gpu['memory_total']}MB)")

        # Run individual tests
        suite_results["tests"]["compute_performance"] = self.test_gpu_compute_performance()
        suite_results["tests"]["memory_bandwidth"] = self.test_gpu_memory_bandwidth()
        suite_results["tests"]["concurrent_usage"] = self.test_concurrent_gpu_usage()
        suite_results["tests"]["baseline_validation"] = self.validate_gpu_performance_baseline()

        # Calculate overall test status
        test_statuses = [test.get("status", "failed") for test in suite_results["tests"].values()]
        if suite_results["tests"]["baseline_validation"]["overall_status"] == "passed":
            suite_results["status"] = "passed"
        elif "success" in test_statuses:
            suite_results["status"] = "partial"
        else:
            suite_results["status"] = "failed"

        return suite_results

def main():
    """Main test execution"""
    api_url = os.getenv('API_BASE_URL', 'http://localhost:8000')

    # Initialize test suite
    gpu_test = GPUPerformanceTest(api_url)

    # Run tests
    results = gpu_test.run_full_test_suite()

    # Print results
    print("\n=== Test Results ===")
    print(f"Overall Status: {results['status']}")
    print(f"GPU Available: {results['gpu_available']}")

    if results['gpu_available']:
        print(f"GPUs Found: {len(results['gpu_info'])}")

        for test_name, test_result in results['tests'].items():
            status = test_result.get('status', 'unknown')
            print(f"{test_name}: {status}")

    # Save results to file
    with open('gpu_performance_results.json', 'w') as f:
        json.dump(results, f, indent=2)

    # Exit with appropriate code
    if results['status'] in ['passed', 'skipped']:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
