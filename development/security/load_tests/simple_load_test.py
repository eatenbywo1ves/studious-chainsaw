#!/usr/bin/env python3
"""
Simple Load Test for Optimized Redis Auth Server
Tests concurrent user load and measures pool utilization
"""

import asyncio
import aiohttp
import time
import statistics
from datetime import datetime
from typing import Dict
import json

# Test configuration
BASE_URL = "http://localhost:8002"
TEST_SCENARIOS = [
    {"name": "baseline", "users": 500, "duration": 30},
    {"name": "stress", "users": 1000, "duration": 30},
    {"name": "ultimate", "users": 2000, "duration": 30},
]

class LoadTestResults:
    def __init__(self):
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.latencies = []
        self.errors = []
        self.start_time = None
        self.end_time = None

    def add_request(self, success: bool, latency: float, error: str = None):
        self.total_requests += 1
        if success:
            self.successful_requests += 1
            self.latencies.append(latency)
        else:
            self.failed_requests += 1
            if error:
                self.errors.append(error)

    def get_stats(self) -> Dict:
        duration = self.end_time - self.start_time if self.end_time and self.start_time else 0

        if self.latencies:
            sorted_latencies = sorted(self.latencies)
            p50 = sorted_latencies[len(sorted_latencies) // 2]
            p95 = sorted_latencies[int(len(sorted_latencies) * 0.95)]
            p99 = sorted_latencies[int(len(sorted_latencies) * 0.99)]
            avg_latency = statistics.mean(self.latencies)
            min_latency = min(self.latencies)
            max_latency = max(self.latencies)
        else:
            p50 = p95 = p99 = avg_latency = min_latency = max_latency = 0

        failure_rate = (self.failed_requests / self.total_requests * 100) if self.total_requests > 0 else 0
        success_rate = 100 - failure_rate
        throughput = self.total_requests / duration if duration > 0 else 0

        return {
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "success_rate": f"{success_rate:.2f}%",
            "failure_rate": f"{failure_rate:.2f}%",
            "throughput_rps": f"{throughput:.2f}",
            "duration_seconds": f"{duration:.2f}",
            "latency_ms": {
                "min": f"{min_latency * 1000:.2f}",
                "avg": f"{avg_latency * 1000:.2f}",
                "p50": f"{p50 * 1000:.2f}",
                "p95": f"{p95 * 1000:.2f}",
                "p99": f"{p99 * 1000:.2f}",
                "max": f"{max_latency * 1000:.2f}",
            },
            "errors": self.errors[:10]  # First 10 errors
        }


async def make_login_request(session: aiohttp.ClientSession, results: LoadTestResults):
    """Make a single login request"""
    start_time = time.time()
    try:
        async with session.post(
            f"{BASE_URL}/auth/login",
            json={"email": "test@example.com", "password": "testpass"},
            timeout=aiohttp.ClientTimeout(total=30)
        ) as response:
            latency = time.time() - start_time
            success = response.status == 200
            if success:
                await response.json()  # Consume response
            results.add_request(success, latency, None if success else f"HTTP {response.status}")
    except Exception as e:
        latency = time.time() - start_time
        results.add_request(False, latency, str(e))


async def user_session(session: aiohttp.ClientSession, results: LoadTestResults, duration: int):
    """Simulate a single user making repeated requests"""
    end_time = time.time() + duration
    while time.time() < end_time:
        await make_login_request(session, results)
        await asyncio.sleep(0.1)  # 10 requests per second per user


async def get_pool_metrics() -> Dict:
    """Get current pool metrics from server"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{BASE_URL}/health/redis") as response:
                if response.status == 200:
                    return await response.json()
    except:
        pass
    return {}


async def run_load_test(name: str, concurrent_users: int, duration: int):
    """Run load test with specified parameters"""
    print("=" * 80)
    print(f"LOAD TEST: {name.upper()}")
    print("=" * 80)
    print(f"Concurrent Users:  {concurrent_users}")
    print(f"Duration:          {duration} seconds")
    print(f"Start Time:        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)

    # Get initial pool metrics
    print("\nInitial Pool Metrics:")
    initial_metrics = await get_pool_metrics()
    if initial_metrics:
        pool = initial_metrics.get("pool", {})
        print(f"  Max Connections:    {pool.get('max_connections', 'N/A')}")
        print(f"  Utilization:        {pool.get('utilization_percent', 'N/A')}%")
        print(f"  Available:          {pool.get('available_connections', 'N/A')}")
    print()

    results = LoadTestResults()
    results.start_time = time.time()

    # Create connector with connection pooling
    connector = aiohttp.TCPConnector(limit=concurrent_users, limit_per_host=concurrent_users)

    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            # Create concurrent user tasks
            tasks = [user_session(session, results, duration) for _ in range(concurrent_users)]

            # Run all tasks concurrently
            print(f"Spawning {concurrent_users} concurrent users...")
            await asyncio.gather(*tasks)

    finally:
        results.end_time = time.time()

    # Get final pool metrics
    print("\nFinal Pool Metrics:")
    final_metrics = await get_pool_metrics()
    if final_metrics:
        pool = final_metrics.get("pool", {})
        print(f"  Max Connections:    {pool.get('max_connections', 'N/A')}")
        print(f"  Utilization:        {pool.get('utilization_percent', 'N/A')}%")
        print(f"  Available:          {pool.get('available_connections', 'N/A')}")
        print(f"  Recommendations:    {', '.join(final_metrics.get('recommendations', []))}")

    # Print results
    stats = results.get_stats()
    print("\n" + "=" * 80)
    print("TEST RESULTS")
    print("=" * 80)
    print(f"Total Requests:      {stats['total_requests']}")
    print(f"Successful:          {stats['successful_requests']}")
    print(f"Failed:              {stats['failed_requests']}")
    print(f"Success Rate:        {stats['success_rate']}")
    print(f"Failure Rate:        {stats['failure_rate']}")
    print(f"Throughput:          {stats['throughput_rps']} req/s")
    print(f"Duration:            {stats['duration_seconds']}s")
    print("\nLatency (ms):")
    print(f"  Min:               {stats['latency_ms']['min']}")
    print(f"  Avg:               {stats['latency_ms']['avg']}")
    print(f"  p50:               {stats['latency_ms']['p50']}")
    print(f"  p95:               {stats['latency_ms']['p95']}")
    print(f"  p99:               {stats['latency_ms']['p99']}")
    print(f"  Max:               {stats['latency_ms']['max']}")

    if stats['errors']:
        print("\nFirst 10 Errors:")
        for error in stats['errors']:
            print(f"  - {error}")

    print("=" * 80)

    # Save results to JSON
    result_file = f"load_test_{name}_{concurrent_users}users_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(result_file, 'w') as f:
        json.dump({
            "test_name": name,
            "concurrent_users": concurrent_users,
            "duration": duration,
            "timestamp": datetime.now().isoformat(),
            "initial_pool_metrics": initial_metrics,
            "final_pool_metrics": final_metrics,
            "results": stats
        }, f, indent=2)
    print(f"\nResults saved to: {result_file}")

    return stats


async def main():
    """Run all load test scenarios"""
    print("\n" + "=" * 80)
    print("OPTIMIZED REDIS AUTH SERVER - LOAD TEST SUITE")
    print("=" * 80)
    print(f"Target: {BASE_URL}")
    print(f"Test Scenarios: {len(TEST_SCENARIOS)}")
    print("=" * 80)

    all_results = []

    for scenario in TEST_SCENARIOS:
        stats = await run_load_test(
            scenario["name"],
            scenario["users"],
            scenario["duration"]
        )
        all_results.append({
            "scenario": scenario["name"],
            "users": scenario["users"],
            "stats": stats
        })

        # Wait between tests
        if scenario != TEST_SCENARIOS[-1]:
            print("\nWaiting 10 seconds before next test...\n")
            await asyncio.sleep(10)

    # Print comparison summary
    print("\n" + "=" * 80)
    print("SUMMARY COMPARISON")
    print("=" * 80)
    print(f"{'Scenario':<15} {'Users':<10} {'Success':<10} {'Failure':<10} {'p95 (ms)':<12} {'Throughput':<12}")
    print("-" * 80)
    for result in all_results:
        print(f"{result['scenario']:<15} {result['users']:<10} "
              f"{result['stats']['success_rate']:<10} "
              f"{result['stats']['failure_rate']:<10} "
              f"{result['stats']['latency_ms']['p95']:<12} "
              f"{result['stats']['throughput_rps']:<12}")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
