#!/usr/bin/env python3
"""
Load Testing Runner for Catalytic Computing SaaS Platform
==========================================================

Automated test runner that executes all load testing scenarios and
generates comprehensive reports.

Features:
    - Runs all test scenarios (baseline, stress, spike, soak, mixed)
    - Generates HTML reports and CSV metrics
    - Validates performance against targets
    - Produces pass/fail summary

Usage:
    # Run all scenarios
    python run_load_tests.py

    # Run specific scenario
    python run_load_tests.py --scenario baseline

    # Run with custom host
    python run_load_tests.py --host http://localhost:8000

    # Run in Docker environment
    python run_load_tests.py --docker

Author: Catalytic Computing Team
Version: 1.0.0
"""

import sys
import json
import time
import argparse
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

# ============================================================================
# CONFIGURATION
# ============================================================================

SCENARIOS = {
    "baseline": {
        "name": "Baseline Test",
        "description": "Normal operations with 100 concurrent users",
        "users": 100,
        "spawn_rate": 10,
        "run_time": "10m",
        "tags": "baseline",
    },
    "stress": {
        "name": "Stress Test",
        "description": "High load with 500 concurrent users",
        "users": 500,
        "spawn_rate": 50,
        "run_time": "5m",
        "tags": "stress",
    },
    "spike": {
        "name": "Spike Test",
        "description": "Traffic spike from 0 to 1000 users",
        "users": 1000,
        "spawn_rate": 1000,
        "run_time": "5m",
        "tags": "spike",
    },
    "soak": {
        "name": "Soak Test",
        "description": "Stability test with 50 users over 4 hours",
        "users": 50,
        "spawn_rate": 5,
        "run_time": "4h",
        "tags": "soak",
    },
    "mixed": {
        "name": "Mixed Workload Test",
        "description": "Realistic production traffic with 200 users",
        "users": 200,
        "spawn_rate": 20,
        "run_time": "15m",
        "tags": "mixed",
    },
}

PERFORMANCE_TARGETS = {
    "p95_latency_ms": 500,
    "p99_latency_ms": 1000,
    "target_throughput_rps": 1000,
    "max_error_rate_pct": 1.0,
}

# ============================================================================
# TEST RUNNER
# ============================================================================


class LoadTestRunner:
    """Orchestrates load testing execution"""

    def __init__(self, host: str = "http://localhost:8000", docker: bool = False):
        self.host = host
        self.docker = docker
        self.results_dir = Path("results")
        self.results_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def run_scenario(self, scenario_key: str) -> Dict[str, Any]:
        """Run a single load test scenario"""
        scenario = SCENARIOS[scenario_key]
        print(f"\n{'=' * 80}")
        print(f"Running: {scenario['name']}")
        print(f"Description: {scenario['description']}")
        print(
            f"Configuration: {scenario['users']} users, spawn rate {scenario['spawn_rate']}, duration {scenario['run_time']}"
        )
        print(f"{'=' * 80}\n")

        # Prepare output files
        html_report = self.results_dir / f"{scenario_key}_{self.timestamp}.html"
        csv_stats = self.results_dir / f"{scenario_key}_{self.timestamp}"

        # Build Locust command
        if self.docker:
            cmd = self._build_docker_command(scenario_key, scenario)
        else:
            cmd = [
                "locust",
                "-f",
                "locustfile.py",
                "--host",
                self.host,
                "--tags",
                scenario["tags"],
                "--users",
                str(scenario["users"]),
                "--spawn-rate",
                str(scenario["spawn_rate"]),
                "--run-time",
                scenario["run_time"],
                "--headless",
                "--html",
                str(html_report),
                "--csv",
                str(csv_stats),
                "--loglevel",
                "INFO",
            ]

        # Execute test
        start_time = time.time()
        try:
            print(f"Executing command: {' '.join(cmd)}\n")
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            print(result.stdout)
            if result.stderr:
                print(f"STDERR: {result.stderr}", file=sys.stderr)
            success = True
        except subprocess.CalledProcessError as e:
            print(f"ERROR: Test failed with exit code {e.returncode}")
            print(f"STDOUT: {e.stdout}")
            print(f"STDERR: {e.stderr}", file=sys.stderr)
            success = False

        end_time = time.time()
        duration = end_time - start_time

        # Parse results
        results = {
            "scenario": scenario_key,
            "name": scenario["name"],
            "success": success,
            "duration_seconds": duration,
            "html_report": str(html_report),
            "csv_stats": str(csv_stats),
            "timestamp": self.timestamp,
        }

        # Analyze metrics if CSV exists
        csv_file = Path(f"{csv_stats}_stats.csv")
        if csv_file.exists():
            results["metrics"] = self._analyze_metrics(csv_file)

        return results

    def _build_docker_command(self, scenario_key: str, scenario: Dict[str, Any]) -> List[str]:
        """Build Docker Compose command for load testing"""
        return [
            "docker-compose",
            "-f",
            "docker-compose.load-test.yml",
            "run",
            "--rm",
            "-e",
            f"LOCUST_TAGS={scenario['tags']}",
            "-e",
            f"LOCUST_USERS={scenario['users']}",
            "-e",
            f"LOCUST_SPAWN_RATE={scenario['spawn_rate']}",
            "-e",
            f"LOCUST_RUN_TIME={scenario['run_time']}",
            "locust-master",
        ]

    def _analyze_metrics(self, csv_file: Path) -> Dict[str, Any]:
        """Analyze load test metrics from CSV"""
        try:
            import pandas as pd

            df = pd.read_csv(csv_file)

            # Calculate key metrics
            metrics = {
                "total_requests": df["Request Count"].sum() if "Request Count" in df.columns else 0,
                "total_failures": df["Failure Count"].sum() if "Failure Count" in df.columns else 0,
                "avg_response_time": df["Average Response Time"].mean()
                if "Average Response Time" in df.columns
                else 0,
                "min_response_time": df["Min Response Time"].min()
                if "Min Response Time" in df.columns
                else 0,
                "max_response_time": df["Max Response Time"].max()
                if "Max Response Time" in df.columns
                else 0,
                "requests_per_second": df["Requests/s"].mean() if "Requests/s" in df.columns else 0,
            }

            # Calculate error rate
            if metrics["total_requests"] > 0:
                metrics["error_rate_pct"] = (
                    metrics["total_failures"] / metrics["total_requests"]
                ) * 100
            else:
                metrics["error_rate_pct"] = 0

            # Validate against targets
            metrics["meets_targets"] = self._validate_targets(metrics)

            return metrics

        except Exception as e:
            print(f"Warning: Could not analyze metrics: {e}")
            return {}

    def _validate_targets(self, metrics: Dict[str, Any]) -> Dict[str, bool]:
        """Validate metrics against performance targets"""
        return {
            "error_rate": metrics.get("error_rate_pct", 100)
            <= PERFORMANCE_TARGETS["max_error_rate_pct"],
            "throughput": metrics.get("requests_per_second", 0)
            >= PERFORMANCE_TARGETS["target_throughput_rps"] * 0.8,  # 80% of target
        }

    def run_all_scenarios(self, exclude_soak: bool = True) -> List[Dict[str, Any]]:
        """Run all load test scenarios"""
        results = []

        for scenario_key in SCENARIOS.keys():
            # Skip soak test by default (too long)
            if exclude_soak and scenario_key == "soak":
                print("\nSkipping Soak Test (4 hours duration)")
                print("To run soak test: python run_load_tests.py --scenario soak\n")
                continue

            result = self.run_scenario(scenario_key)
            results.append(result)

            # Wait between scenarios
            if scenario_key != list(SCENARIOS.keys())[-1]:
                print("\nWaiting 30 seconds before next scenario...")
                time.sleep(30)

        return results

    def generate_summary_report(self, results: List[Dict[str, Any]]) -> None:
        """Generate summary report of all tests"""
        print("\n" + "=" * 80)
        print("LOAD TESTING SUMMARY REPORT")
        print("=" * 80)
        print(f"Timestamp: {self.timestamp}")
        print(f"Total Scenarios Run: {len(results)}")
        print("=" * 80)

        passed = 0
        failed = 0

        for result in results:
            status = "PASS" if result.get("success") else "FAIL"
            if result.get("success"):
                passed += 1
            else:
                failed += 1

            print(f"\n{result['name']}: {status}")
            print(f"  Duration: {result['duration_seconds']:.2f} seconds")

            if "metrics" in result:
                metrics = result["metrics"]
                print(f"  Total Requests: {metrics.get('total_requests', 0)}")
                print(f"  Failed Requests: {metrics.get('total_failures', 0)}")
                print(f"  Error Rate: {metrics.get('error_rate_pct', 0):.2f}%")
                print(f"  Avg Response Time: {metrics.get('avg_response_time', 0):.2f}ms")
                print(f"  Throughput: {metrics.get('requests_per_second', 0):.2f} req/s")

                if "meets_targets" in metrics:
                    targets = metrics["meets_targets"]
                    print(
                        f"  Meets Error Rate Target: {'YES' if targets.get('error_rate') else 'NO'}"
                    )
                    print(
                        f"  Meets Throughput Target: {'YES' if targets.get('throughput') else 'NO'}"
                    )

            print(f"  HTML Report: {result['html_report']}")

        print("\n" + "=" * 80)
        print(f"OVERALL: {passed} PASSED, {failed} FAILED")
        print("=" * 80 + "\n")

        # Save summary to JSON
        summary_file = self.results_dir / f"summary_{self.timestamp}.json"
        with open(summary_file, "w") as f:
            json.dump(
                {
                    "timestamp": self.timestamp,
                    "results": results,
                    "summary": {"passed": passed, "failed": failed},
                },
                f,
                indent=2,
            )

        print(f"Summary saved to: {summary_file}\n")


# ============================================================================
# MAIN
# ============================================================================


def main():
    parser = argparse.ArgumentParser(
        description="Load Testing Runner for Catalytic Computing SaaS Platform"
    )
    parser.add_argument(
        "--host",
        default="http://localhost:8000",
        help="API host URL (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--scenario",
        choices=list(SCENARIOS.keys()) + ["all"],
        default="all",
        help="Scenario to run (default: all)",
    )
    parser.add_argument("--docker", action="store_true", help="Run tests in Docker environment")
    parser.add_argument("--include-soak", action="store_true", help="Include soak test (4 hours)")

    args = parser.parse_args()

    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║         CATALYTIC COMPUTING SAAS - LOAD TESTING RUNNER v1.0.0                ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)

    runner = LoadTestRunner(host=args.host, docker=args.docker)

    if args.scenario == "all":
        results = runner.run_all_scenarios(exclude_soak=not args.include_soak)
        runner.generate_summary_report(results)
    else:
        result = runner.run_scenario(args.scenario)
        runner.generate_summary_report([result])

    print("\nLoad testing complete!\n")


if __name__ == "__main__":
    main()
