#!/usr/bin/env python3
"""
Auto-Scaling Agent for Catalytic Lattice API Service
Manages intelligent scaling decisions based on workload patterns and predictions
"""

import subprocess
import json
import time
import math
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import logging
from collections import deque


class ScalingDecision(Enum):
    SCALE_UP = "scale_up"
    SCALE_DOWN = "scale_down"
    NO_ACTION = "no_action"
    SCALE_UP_URGENT = "scale_up_urgent"


@dataclass
class WorkloadMetrics:
    timestamp: datetime
    cpu_usage: float
    memory_usage: float
    request_rate: float
    response_time: float
    error_rate: float
    pod_count: int
    queue_depth: int


@dataclass
class ScalingPolicy:
    min_replicas: int = 3
    max_replicas: int = 20
    target_cpu: float = 70.0
    target_memory: float = 70.0
    target_response_time: float = 500.0  # ms
    scale_up_threshold: float = 80.0
    scale_down_threshold: float = 30.0
    scale_up_increment: int = 2
    scale_down_increment: int = 1
    cooldown_period: int = 300  # seconds
    prediction_window: int = 600  # seconds


class AutoScalingAgent:
    def __init__(self, namespace: str = "catalytic-lattice", policy: ScalingPolicy = None):
        self.namespace = namespace
        self.kubectl_cmd = "kubectl"
        self.policy = policy or ScalingPolicy()
        self.metrics_history = deque(maxlen=100)
        self.last_scaling_action = None
        self.last_scaling_time = None

        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def _run_command(self, cmd: List[str]) -> Dict:
        """Execute kubectl command and return result"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr
            }
        except Exception as e:
            return {
                "success": False,
                "output": "",
                "error": str(e)
            }

    def collect_current_metrics(self) -> Optional[WorkloadMetrics]:
        """Collect current workload metrics"""
        try:
            # Get current replica count
            cmd = [
                self.kubectl_cmd, "get", "deployment",
                "catalytic-api",
                "-n", self.namespace,
                "-o", "json"
            ]

            result = self._run_command(cmd)
            if not result["success"]:
                return None

            deployment = json.loads(result["output"])
            current_replicas = deployment["status"].get("readyReplicas", 0)

            # Get pod metrics
            cmd = [
                self.kubectl_cmd, "top", "pods",
                "-l", "app=catalytic-api",
                "-n", self.namespace,
                "--no-headers"
            ]

            result = self._run_command(cmd)

            cpu_usages = []
            memory_usages = []

            if result["success"]:
                lines = result["output"].strip().split('\n')
                for line in lines:
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) >= 3:
                        cpu_str = parts[1].rstrip('m')
                        memory_str = parts[2].rstrip('Mi')
                        try:
                            cpu_usages.append(float(cpu_str) / 10)
                            memory_usages.append(float(memory_str))
                        except ValueError:
                            continue

            # Calculate averages (with simulated data for demo)
            import random
            avg_cpu = sum(cpu_usages) / len(cpu_usages) if cpu_usages else random.uniform(40, 80)
            avg_memory = sum(memory_usages) / len(memory_usages) if memory_usages else random.uniform(1000, 3000)

            # Simulate other metrics (in production, these would come from Prometheus or app metrics)
            request_rate = random.uniform(100, 1000)
            response_time = random.uniform(100, 800)
            error_rate = random.uniform(0, 5)
            queue_depth = random.randint(0, 100)

            return WorkloadMetrics(
                timestamp=datetime.now(),
                cpu_usage=avg_cpu,
                memory_usage=(avg_memory / 64000) * 100,  # Convert to percentage
                request_rate=request_rate,
                response_time=response_time,
                error_rate=error_rate,
                pod_count=current_replicas,
                queue_depth=queue_depth
            )

        except Exception as e:
            self.logger.error(f"Error collecting metrics: {e}")
            return None

    def predict_future_load(self, window_minutes: int = 10) -> Dict[str, float]:
        """Predict future load based on historical patterns"""
        if len(self.metrics_history) < 5:
            return {
                "predicted_cpu": 0,
                "predicted_memory": 0,
                "predicted_requests": 0,
                "confidence": 0
            }

        # Simple linear regression for prediction
        recent_metrics = list(self.metrics_history)[-min(20, len(self.metrics_history)):]

        # Calculate trends
        cpu_values = [m.cpu_usage for m in recent_metrics]
        memory_values = [m.memory_usage for m in recent_metrics]
        request_values = [m.request_rate for m in recent_metrics]

        # Calculate moving averages
        cpu_trend = self._calculate_trend(cpu_values)
        memory_trend = self._calculate_trend(memory_values)
        request_trend = self._calculate_trend(request_values)

        # Project forward
        last_cpu = cpu_values[-1] if cpu_values else 0
        last_memory = memory_values[-1] if memory_values else 0
        last_requests = request_values[-1] if request_values else 0

        predicted_cpu = last_cpu + (cpu_trend * window_minutes)
        predicted_memory = last_memory + (memory_trend * window_minutes)
        predicted_requests = last_requests + (request_trend * window_minutes)

        # Calculate confidence based on variance
        cpu_variance = self._calculate_variance(cpu_values) if cpu_values else 100
        confidence = max(0, min(100, 100 - cpu_variance))

        return {
            "predicted_cpu": max(0, min(100, predicted_cpu)),
            "predicted_memory": max(0, min(100, predicted_memory)),
            "predicted_requests": max(0, predicted_requests),
            "confidence": confidence
        }

    def _calculate_trend(self, values: List[float]) -> float:
        """Calculate trend using simple linear regression"""
        if len(values) < 2:
            return 0

        n = len(values)
        x = list(range(n))

        x_mean = sum(x) / n
        y_mean = sum(values) / n

        numerator = sum((x[i] - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(n))

        if denominator == 0:
            return 0

        return numerator / denominator

    def _calculate_variance(self, values: List[float]) -> float:
        """Calculate variance of values"""
        if not values:
            return 0

        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return math.sqrt(variance)

    def analyze_scaling_need(self, metrics: WorkloadMetrics, predictions: Dict[str, float]) -> ScalingDecision:
        """Analyze if scaling is needed based on current metrics and predictions"""

        # Check if in cooldown period
        if self.last_scaling_time:
            time_since_scaling = (datetime.now() - self.last_scaling_time).total_seconds()
            if time_since_scaling < self.policy.cooldown_period:
                self.logger.debug(f"In cooldown period ({time_since_scaling:.0f}s < {self.policy.cooldown_period}s)")
                return ScalingDecision.NO_ACTION

        # Urgent scale up conditions
        if (metrics.cpu_usage > 90 or
            metrics.memory_usage > 90 or
            metrics.response_time > 2000 or
            metrics.error_rate > 10 or
            metrics.queue_depth > 500):
            return ScalingDecision.SCALE_UP_URGENT

        # Regular scale up conditions
        scale_up_score = 0

        if metrics.cpu_usage > self.policy.scale_up_threshold:
            scale_up_score += 2
        elif metrics.cpu_usage > self.policy.target_cpu:
            scale_up_score += 1

        if metrics.memory_usage > self.policy.scale_up_threshold:
            scale_up_score += 2
        elif metrics.memory_usage > self.policy.target_memory:
            scale_up_score += 1

        if metrics.response_time > self.policy.target_response_time * 1.5:
            scale_up_score += 2
        elif metrics.response_time > self.policy.target_response_time:
            scale_up_score += 1

        # Consider predictions
        if predictions["confidence"] > 70:
            if predictions["predicted_cpu"] > self.policy.scale_up_threshold:
                scale_up_score += 1
            if predictions["predicted_memory"] > self.policy.scale_up_threshold:
                scale_up_score += 1

        # Scale down conditions
        scale_down_score = 0

        if (metrics.cpu_usage < self.policy.scale_down_threshold and
            metrics.memory_usage < self.policy.scale_down_threshold):
            scale_down_score += 2

        if metrics.response_time < self.policy.target_response_time * 0.5:
            scale_down_score += 1

        if metrics.request_rate < 100 and metrics.pod_count > self.policy.min_replicas:
            scale_down_score += 1

        # Make decision
        if scale_up_score >= 3:
            return ScalingDecision.SCALE_UP
        elif scale_down_score >= 3 and metrics.pod_count > self.policy.min_replicas:
            return ScalingDecision.SCALE_DOWN
        else:
            return ScalingDecision.NO_ACTION

    def calculate_optimal_replicas(self, metrics: WorkloadMetrics, decision: ScalingDecision) -> int:
        """Calculate the optimal number of replicas"""
        current_replicas = metrics.pod_count

        if decision == ScalingDecision.SCALE_UP_URGENT:
            # Aggressive scaling for urgent situations
            target_replicas = min(
                current_replicas + self.policy.scale_up_increment * 2,
                self.policy.max_replicas
            )

        elif decision == ScalingDecision.SCALE_UP:
            # Calculate based on resource utilization
            cpu_based_replicas = math.ceil(
                current_replicas * (metrics.cpu_usage / self.policy.target_cpu)
            )
            memory_based_replicas = math.ceil(
                current_replicas * (metrics.memory_usage / self.policy.target_memory)
            )

            # Use the higher requirement
            target_replicas = max(cpu_based_replicas, memory_based_replicas)

            # Apply increment policy
            target_replicas = min(
                current_replicas + self.policy.scale_up_increment,
                target_replicas,
                self.policy.max_replicas
            )

        elif decision == ScalingDecision.SCALE_DOWN:
            # Conservative scale down
            target_replicas = max(
                current_replicas - self.policy.scale_down_increment,
                self.policy.min_replicas
            )

        else:
            target_replicas = current_replicas

        return int(target_replicas)

    def execute_scaling(self, target_replicas: int) -> bool:
        """Execute scaling action"""
        self.logger.info(f"Scaling deployment to {target_replicas} replicas")

        cmd = [
            self.kubectl_cmd, "scale",
            "deployment/catalytic-api",
            f"--replicas={target_replicas}",
            "-n", self.namespace
        ]

        result = self._run_command(cmd)

        if result["success"]:
            self.logger.info(f"[OK] Successfully scaled to {target_replicas} replicas")
            self.last_scaling_action = target_replicas
            self.last_scaling_time = datetime.now()
            return True
        else:
            self.logger.error(f"[FAIL] Failed to scale: {result['error']}")
            return False

    def verify_scaling(self, expected_replicas: int, timeout: int = 120) -> bool:
        """Verify that scaling completed successfully"""
        start_time = time.time()

        while time.time() - start_time < timeout:
            cmd = [
                self.kubectl_cmd, "get", "deployment",
                "catalytic-api",
                "-n", self.namespace,
                "-o", "json"
            ]

            result = self._run_command(cmd)

            if result["success"]:
                try:
                    deployment = json.loads(result["output"])
                    ready_replicas = deployment["status"].get("readyReplicas", 0)

                    if ready_replicas == expected_replicas:
                        self.logger.info(f"[OK] Scaling verified: {ready_replicas} replicas ready")
                        return True

                    self.logger.debug(f"Waiting for scaling: {ready_replicas}/{expected_replicas} replicas ready")

                except Exception as e:
                    self.logger.error(f"Error checking scaling status: {e}")

            time.sleep(5)

        self.logger.warning(f"[WARNING] Scaling verification timeout after {timeout}s")
        return False

    def get_scaling_recommendations(self) -> List[str]:
        """Generate scaling recommendations based on historical data"""
        recommendations = []

        if len(self.metrics_history) < 10:
            recommendations.append("Insufficient data for recommendations. Continue monitoring.")
            return recommendations

        # Analyze recent metrics
        recent_metrics = list(self.metrics_history)[-20:]

        # CPU analysis
        avg_cpu = sum(m.cpu_usage for m in recent_metrics) / len(recent_metrics)
        max_cpu = max(m.cpu_usage for m in recent_metrics)

        if avg_cpu > 75:
            recommendations.append(f"High average CPU usage ({avg_cpu:.1f}%). Consider increasing CPU limits or base replica count.")
        elif avg_cpu < 30:
            recommendations.append(f"Low average CPU usage ({avg_cpu:.1f}%). Consider reducing minimum replicas to save resources.")

        # Response time analysis
        avg_response = sum(m.response_time for m in recent_metrics) / len(recent_metrics)

        if avg_response > self.policy.target_response_time:
            recommendations.append(f"Response time ({avg_response:.0f}ms) exceeds target. Consider optimizing application or increasing resources.")

        # Scaling frequency analysis
        replica_changes = []
        for i in range(1, len(recent_metrics)):
            if recent_metrics[i].pod_count != recent_metrics[i-1].pod_count:
                replica_changes.append(recent_metrics[i].timestamp)

        if len(replica_changes) > 5:
            recommendations.append("Frequent scaling detected. Consider adjusting thresholds to reduce flapping.")

        # Pattern detection
        hour_of_day = datetime.now().hour

        if 9 <= hour_of_day <= 17:  # Business hours
            recommendations.append("Business hours detected. Consider scheduled scaling for predictable patterns.")
        elif hour_of_day < 6 or hour_of_day > 22:  # Off hours
            recommendations.append("Off-peak hours. Consider reducing minimum replicas during this period.")

        return recommendations

    def run_scaling_cycle(self) -> Dict:
        """Run a single scaling decision cycle"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "decision": ScalingDecision.NO_ACTION.value,
            "current_replicas": 0,
            "target_replicas": 0,
            "metrics": {},
            "predictions": {},
            "success": False
        }

        # Collect metrics
        metrics = self.collect_current_metrics()
        if not metrics:
            self.logger.error("Failed to collect metrics")
            return report

        # Add to history
        self.metrics_history.append(metrics)

        # Store current metrics
        report["current_replicas"] = metrics.pod_count
        report["metrics"] = {
            "cpu": metrics.cpu_usage,
            "memory": metrics.memory_usage,
            "response_time": metrics.response_time,
            "request_rate": metrics.request_rate,
            "error_rate": metrics.error_rate,
            "queue_depth": metrics.queue_depth
        }

        # Get predictions
        predictions = self.predict_future_load()
        report["predictions"] = predictions

        # Analyze scaling need
        decision = self.analyze_scaling_need(metrics, predictions)
        report["decision"] = decision.value

        # Execute if needed
        if decision != ScalingDecision.NO_ACTION:
            target_replicas = self.calculate_optimal_replicas(metrics, decision)
            report["target_replicas"] = target_replicas

            if target_replicas != metrics.pod_count:
                self.logger.info(f"Scaling decision: {decision.value} from {metrics.pod_count} to {target_replicas} replicas")

                if self.execute_scaling(target_replicas):
                    report["success"] = True
                    # Verify scaling
                    self.verify_scaling(target_replicas)
            else:
                self.logger.info("No scaling needed - already at optimal replica count")
        else:
            report["target_replicas"] = metrics.pod_count
            self.logger.info("No scaling action required")

        return report

    def start_auto_scaling(self, interval_seconds: int = 60):
        """Start continuous auto-scaling monitoring"""
        self.logger.info(f"Starting auto-scaling agent (interval: {interval_seconds}s)")
        self.logger.info(f"Policy: min={self.policy.min_replicas}, max={self.policy.max_replicas}, "
                        f"target_cpu={self.policy.target_cpu}%, cooldown={self.policy.cooldown_period}s")

        try:
            while True:
                # Run scaling cycle
                report = self.run_scaling_cycle()

                # Log summary
                self.logger.info(
                    f"Scaling cycle: decision={report['decision']}, "
                    f"replicas={report['current_replicas']}->{report['target_replicas']}, "
                    f"cpu={report['metrics']['cpu']:.1f}%, "
                    f"response={report['metrics']['response_time']:.0f}ms"
                )

                # Generate recommendations periodically
                if len(self.metrics_history) % 10 == 0:
                    recommendations = self.get_scaling_recommendations()
                    if recommendations:
                        self.logger.info("Scaling Recommendations:")
                        for rec in recommendations:
                            self.logger.info(f"  - {rec}")

                time.sleep(interval_seconds)

        except KeyboardInterrupt:
            self.logger.info("Auto-scaling stopped by user")
        except Exception as e:
            self.logger.error(f"Auto-scaling error: {e}")


def main():
    """Main entry point for auto-scaling agent"""
    import argparse

    parser = argparse.ArgumentParser(description="Auto-Scaling Agent for Catalytic Lattice")
    parser.add_argument("--namespace", default="catalytic-lattice", help="Kubernetes namespace")
    parser.add_argument("--min-replicas", type=int, default=3, help="Minimum replicas")
    parser.add_argument("--max-replicas", type=int, default=20, help="Maximum replicas")
    parser.add_argument("--target-cpu", type=float, default=70.0, help="Target CPU percentage")
    parser.add_argument("--interval", type=int, default=60, help="Check interval in seconds")
    parser.add_argument("--dry-run", action="store_true", help="Run without executing scaling actions")

    args = parser.parse_args()

    # Create scaling policy
    policy = ScalingPolicy(
        min_replicas=args.min_replicas,
        max_replicas=args.max_replicas,
        target_cpu=args.target_cpu
    )

    # Create agent
    agent = AutoScalingAgent(namespace=args.namespace, policy=policy)

    print("\n" + "=" * 60)
    print("Catalytic Lattice Auto-Scaling Agent")
    print("=" * 60)
    print(f"\nConfiguration:")
    print(f"  Namespace: {args.namespace}")
    print(f"  Replicas: {policy.min_replicas} - {policy.max_replicas}")
    print(f"  Target CPU: {policy.target_cpu}%")
    print(f"  Interval: {args.interval}s")
    print(f"  Dry Run: {args.dry_run}")

    if args.dry_run:
        print("\n[WARNING] DRY RUN MODE - No scaling actions will be executed")

        # Run single cycle for demonstration
        print("\nRunning scaling analysis...")
        report = agent.run_scaling_cycle()

        print(f"\nCurrent Status:")
        print(f"  Replicas: {report['current_replicas']}")
        print(f"  CPU: {report['metrics']['cpu']:.1f}%")
        print(f"  Memory: {report['metrics']['memory']:.1f}%")
        print(f"  Response Time: {report['metrics']['response_time']:.0f}ms")

        print(f"\nScaling Decision: {report['decision']}")
        if report['decision'] != "no_action":
            print(f"  Target Replicas: {report['target_replicas']}")

        print(f"\nPredictions (confidence: {report['predictions']['confidence']:.0f}%):")
        print(f"  Predicted CPU: {report['predictions']['predicted_cpu']:.1f}%")
        print(f"  Predicted Memory: {report['predictions']['predicted_memory']:.1f}%")

    else:
        print("\n[STARTING] Starting auto-scaling agent...")
        print("Press Ctrl+C to stop\n")

        agent.start_auto_scaling(interval_seconds=args.interval)


if __name__ == "__main__":
    main()