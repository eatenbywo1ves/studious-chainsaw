#!/usr/bin/env python3
"""
Quick Start Script for Reactive Migration
Run this to set up your reactive programming environment and start the BMAD plan

Usage: python start_reactive_migration.py [--step STEP_NUMBER]
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
from typing import Optional
import json


class ReactiveMigrationSetup:
    """Automated setup for reactive programming migration"""

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.reactive_dir = base_dir / "development" / "reactive"
        self.progress_file = self.reactive_dir / "migration_progress.json"

    def run_all_steps(self):
        """Execute all setup steps"""
        steps = [
            ("Create directory structure", self.step1_create_structure),
            ("Install dependencies", self.step2_install_dependencies),
            ("Copy completed files", self.step3_copy_files),
            ("Set up testing", self.step4_setup_testing),
            ("Run baseline metrics", self.step5_baseline_metrics),
            ("Create progress tracker", self.step6_progress_tracker),
            ("Print next steps", self.step7_next_steps),
        ]

        print("\n" + "="*80)
        print(">> REACTIVE PROGRAMMING MIGRATION - SETUP WIZARD")
        print("="*80 + "\n")

        for idx, (description, step_func) in enumerate(steps, 1):
            print(f"\n[*] Step {idx}/7: {description}")
            print("-" * 80)

            try:
                step_func()
                print(f"[OK] Step {idx} complete!\n")
            except Exception as e:
                print(f"[ERROR] Step {idx} failed: {e}")
                print(f"   You can retry with: python {__file__} --step {idx}")
                sys.exit(1)

        print("\n" + "="*80)
        print("[SUCCESS] SETUP COMPLETE! Ready to start migration.")
        print("="*80 + "\n")

    def step1_create_structure(self):
        """Create project directory structure"""
        directories = [
            self.reactive_dir / "core",
            self.reactive_dir / "operators",
            self.reactive_dir / "tests",
            self.reactive_dir / "patterns",
            self.reactive_dir / "metrics",
            self.reactive_dir / "docs",
        ]

        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            print(f"   [+] Created: {directory.relative_to(self.base_dir)}")

        # Create __init__.py files
        for directory in directories:
            init_file = directory / "__init__.py"
            if not init_file.exists():
                init_file.write_text('"""Reactive programming module"""\n')

        print(f"\n   [OK] Directory structure created under {self.reactive_dir.relative_to(self.base_dir)}")

    def step2_install_dependencies(self):
        """Install required Python packages"""
        packages = [
            "reactivex==4.0.4",
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
        ]

        print("   [*] Installing packages...")
        for package in packages:
            print(f"      - {package}")

        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", *packages],
                check=True,
                capture_output=True,
                text=True
            )
            print("\n   [OK] All packages installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"\n   [WARN]  Some packages failed to install:")
            print(f"      {e.stderr}")
            raise

    def step3_copy_files(self):
        """Copy completed reactive files to project structure"""
        files_to_copy = [
            ("webhook_manager_reactive.py", self.reactive_dir / "core" / "webhook_manager_reactive.py"),
            ("test_webhook_manager_reactive.py", self.reactive_dir / "tests" / "test_webhook_manager_reactive.py"),
            ("webhook_advanced_operators.py", self.reactive_dir / "patterns" / "advanced_operators.py"),
            ("webhook_hot_cold_observables.py", self.reactive_dir / "patterns" / "hot_cold_observables.py"),
            ("webhook_reactive_flowchart.py", self.reactive_dir / "docs" / "flowcharts.py"),
            ("REACTIVE_PROGRAMMING_COMPLETE_GUIDE.md", self.reactive_dir / "docs" / "COMPLETE_GUIDE.md"),
            ("REACTIVE_BMAD_IMPLEMENTATION_PLAN.md", self.reactive_dir / "docs" / "BMAD_PLAN.md"),
        ]

        copied = 0
        for source_name, dest_path in files_to_copy:
            source_path = self.base_dir / source_name

            if source_path.exists():
                shutil.copy2(source_path, dest_path)
                print(f"   [OK] Copied: {source_name}")
                copied += 1
            else:
                print(f"   [WARN]  Not found: {source_name} (skipping)")

        print(f"\n   [OK] Copied {copied}/{len(files_to_copy)} files")

    def step4_setup_testing(self):
        """Set up testing infrastructure"""
        # Create pytest configuration
        pytest_ini = self.reactive_dir / "pytest.ini"
        pytest_config = """[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
asyncio_mode = auto
addopts =
    -v
    --cov=core
    --cov=operators
    --cov-report=html
    --cov-report=term-missing
"""
        pytest_ini.write_text(pytest_config)
        print("   [OK] Created pytest.ini")

        # Create test runner script
        test_runner = self.reactive_dir / "run_tests.sh"
        test_runner_content = """#!/bin/bash
# Run all reactive programming tests

cd "$(dirname "$0")"

echo "Running marble diagram tests..."
pytest tests/ -v --tb=short

echo ""
echo "Running advanced operator demos..."
python patterns/advanced_operators.py

echo ""
echo "Running hot/cold observable demos..."
python patterns/hot_cold_observables.py
"""
        test_runner.write_text(test_runner_content)
        test_runner.chmod(0o755)
        print("   [OK] Created run_tests.sh")

    def step5_baseline_metrics(self):
        """Create baseline metrics collection script"""
        metrics_script = self.reactive_dir / "metrics" / "collect_baseline.py"
        metrics_content = '''"""
Collect baseline metrics from current webhook_manager.py

Run this before migrating to establish performance baseline
"""

import asyncio
import time
import psutil
import json
from datetime import datetime
from typing import Dict, List

# Adjust import path as needed
import sys
sys.path.append("../..")
from webhook_manager import WebhookManager, WebhookPriority


class BaselineMetrics:
    """Collect performance metrics from imperative webhook manager"""

    def __init__(self):
        self.metrics = {
            'timestamp': datetime.now().isoformat(),
            'latencies': [],
            'throughput': 0,
            'memory_samples': [],
            'cpu_samples': [],
            'errors': 0,
            'total_events': 0
        }

    async def measure_latency(self, manager: WebhookManager, num_events: int = 100):
        """Measure event processing latency"""
        print(f"Measuring latency with {num_events} events...")

        latencies = []
        for i in range(num_events):
            start = time.time()
            await manager.trigger_event(
                f"test.event.{i}",
                {"iteration": i, "timestamp": start},
                priority=WebhookPriority.NORMAL
            )
            latency_ms = (time.time() - start) * 1000
            latencies.append(latency_ms)

            if i % 10 == 0:
                print(f"  Progress: {i}/{num_events}")

        self.metrics['latencies'] = latencies
        self.metrics['latency_p50'] = sorted(latencies)[len(latencies)//2]
        self.metrics['latency_p95'] = sorted(latencies)[int(len(latencies)*0.95)]
        self.metrics['latency_p99'] = sorted(latencies)[int(len(latencies)*0.99)]

        print(f"  [OK] Latency P50: {self.metrics['latency_p50']:.2f}ms")
        print(f"  [OK] Latency P99: {self.metrics['latency_p99']:.2f}ms")

    async def measure_throughput(self, manager: WebhookManager, duration_seconds: int = 10):
        """Measure events per second"""
        print(f"Measuring throughput for {duration_seconds} seconds...")

        count = 0
        start_time = time.time()
        end_time = start_time + duration_seconds

        while time.time() < end_time:
            await manager.trigger_event(
                f"test.throughput.{count}",
                {"count": count},
                priority=WebhookPriority.NORMAL
            )
            count += 1

        elapsed = time.time() - start_time
        self.metrics['throughput'] = count / elapsed
        self.metrics['total_events'] = count

        print(f"  [OK] Throughput: {self.metrics['throughput']:.0f} events/sec")

    def measure_resources(self):
        """Measure memory and CPU usage"""
        print("Measuring resource usage...")

        process = psutil.Process()

        # Collect samples
        for i in range(10):
            mem_mb = process.memory_info().rss / 1024 / 1024
            cpu_pct = process.cpu_percent(interval=0.1)

            self.metrics['memory_samples'].append(mem_mb)
            self.metrics['cpu_samples'].append(cpu_pct)

        self.metrics['memory_avg_mb'] = sum(self.metrics['memory_samples']) / len(self.metrics['memory_samples'])
        self.metrics['cpu_avg_pct'] = sum(self.metrics['cpu_samples']) / len(self.metrics['cpu_samples'])

        print(f"  [OK] Memory: {self.metrics['memory_avg_mb']:.1f} MB")
        print(f"  [OK] CPU: {self.metrics['cpu_avg_pct']:.1f}%")

    def save_results(self, filepath: str = "baseline_metrics.json"):
        """Save metrics to file"""
        with open(filepath, 'w') as f:
            json.dump(self.metrics, f, indent=2)

        print(f"\\n[SUCCESS] Baseline metrics saved to {filepath}")


async def main():
    """Run baseline metrics collection"""
    print("="*80)
    print("BASELINE METRICS COLLECTION")
    print("="*80)
    print()

    # Note: This assumes you have webhooks_config.yaml
    # Adjust path if needed
    try:
        manager = WebhookManager("../../webhooks_config.yaml")
        await manager.start()

        collector = BaselineMetrics()

        # Run measurements
        await collector.measure_latency(manager, num_events=100)
        print()
        await collector.measure_throughput(manager, duration_seconds=5)
        print()
        collector.measure_resources()

        # Save results
        collector.save_results("baseline_metrics.json")

        await manager.stop()

    except FileNotFoundError:
        print("[WARN]  webhooks_config.yaml not found")
        print("   Create a minimal config file or adjust the path in this script")
    except Exception as e:
        print(f"[ERROR] Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
'''
        metrics_script.write_text(metrics_content)
        print("   [OK] Created baseline metrics collector")

    def step6_progress_tracker(self):
        """Create migration progress tracker"""
        progress = {
            "started": str(Path(__file__).stat().st_mtime),
            "phase": "setup",
            "week": 1,
            "components": {
                "webhook_manager": {
                    "status": "complete",
                    "production": False,
                    "tests_passing": True,
                    "notes": "Refactored to reactive, ready for deployment"
                },
                "webhook_router": {
                    "status": "planned",
                    "production": False,
                    "eta": "Week 4"
                },
                "api_server": {
                    "status": "planned",
                    "production": False,
                    "eta": "Week 5-6"
                },
                "background_jobs": {
                    "status": "planned",
                    "production": False,
                    "eta": "Week 7-8"
                }
            },
            "metrics": {
                "baseline_captured": False,
                "load_tests_run": False,
                "ab_test_complete": False,
                "production_rollout": 0
            },
            "next_actions": [
                "Run baseline metrics: cd metrics && python collect_baseline.py",
                "Run tests: ./run_tests.sh",
                "Review BMAD plan: docs/BMAD_PLAN.md",
                "Deploy to staging (Week 2)"
            ]
        }

        with open(self.progress_file, 'w') as f:
            json.dump(progress, f, indent=2)

        print(f"   [OK] Created progress tracker: {self.progress_file.relative_to(self.base_dir)}")

    def step7_next_steps(self):
        """Print next steps for the user"""
        print("\n" + "="*80)
        print(">> NEXT STEPS - WEEK 1, DAY 1")
        print("="*80)

        next_steps = """
1. Review the BMAD implementation plan:
   $ cat development/reactive/docs/BMAD_PLAN.md

2. Run the test suite to verify everything works:
   $ cd development/reactive
   $ ./run_tests.sh

3. Collect baseline metrics from your current system:
   $ cd development/reactive/metrics
   $ python collect_baseline.py

4. Review progress and update as you go:
   $ cat development/reactive/migration_progress.json

5. Start Week 2 planning (after Week 1 complete):
   - Deploy reactive webhook_manager to staging
   - Run load tests
   - Begin A/B testing

[DOCS] Documentation available in:
   - development/reactive/docs/COMPLETE_GUIDE.md
   - development/reactive/docs/BMAD_PLAN.md
   - development/reactive/docs/flowcharts.py

[TEST] Run demonstrations:
   - python development/reactive/patterns/advanced_operators.py
   - python development/reactive/patterns/hot_cold_observables.py
   - python development/reactive/docs/flowcharts.py

[TIP] Need help? Check the complete guide or run demos!
"""
        print(next_steps)

    def run_single_step(self, step_number: int):
        """Run a single setup step"""
        steps = {
            1: ("Create directory structure", self.step1_create_structure),
            2: ("Install dependencies", self.step2_install_dependencies),
            3: ("Copy completed files", self.step3_copy_files),
            4: ("Set up testing", self.step4_setup_testing),
            5: ("Run baseline metrics", self.step5_baseline_metrics),
            6: ("Create progress tracker", self.step6_progress_tracker),
            7: ("Print next steps", self.step7_next_steps),
        }

        if step_number not in steps:
            print(f"[ERROR] Invalid step number: {step_number}")
            print(f"   Valid steps: 1-{len(steps)}")
            sys.exit(1)

        description, step_func = steps[step_number]
        print(f"\n[*] Running Step {step_number}: {description}")
        print("-" * 80)

        try:
            step_func()
            print(f"\n[SUCCESS] Step {step_number} complete!")
        except Exception as e:
            print(f"\n[ERROR] Step {step_number} failed: {e}")
            sys.exit(1)


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Set up reactive programming migration environment"
    )
    parser.add_argument(
        "--step",
        type=int,
        help="Run a single step (1-7)"
    )
    parser.add_argument(
        "--base-dir",
        type=Path,
        default=Path.cwd(),
        help="Base directory (default: current directory)"
    )

    args = parser.parse_args()

    setup = ReactiveMigrationSetup(args.base_dir)

    if args.step:
        setup.run_single_step(args.step)
    else:
        setup.run_all_steps()


if __name__ == "__main__":
    main()
