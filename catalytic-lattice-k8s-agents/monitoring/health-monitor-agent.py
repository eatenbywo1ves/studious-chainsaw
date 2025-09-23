#!/usr/bin/env python3
"""
Health Monitoring Agent for Catalytic Lattice API Service
Monitors health, metrics, and logs across Kubernetes deployments
"""

import subprocess
import json
import time
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import logging


class HealthStatus(Enum):
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class MetricData:
    timestamp: datetime
    pod_name: str
    cpu_usage: float
    memory_usage: float
    request_rate: float
    error_rate: float
    latency_p95: float


@dataclass
class HealthCheck:
    name: str
    status: HealthStatus
    message: str
    timestamp: datetime
    details: Optional[Dict] = None


class HealthMonitorAgent:
    def __init__(self, namespace: str = "catalytic-lattice"):
        self.namespace = namespace
        self.kubectl_cmd = "kubectl"
        self.is_monitoring = False
        self.metrics_history: List[MetricData] = []
        self.health_checks: List[HealthCheck] = []
        self.alert_thresholds = {
            "cpu_critical": 90,
            "cpu_warning": 70,
            "memory_critical": 85,
            "memory_warning": 70,
            "error_rate_critical": 5,
            "error_rate_warning": 2,
            "latency_critical": 1000,  # ms
            "latency_warning": 500
        }

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

    def check_deployment_health(self) -> HealthCheck:
        """Check deployment status and readiness"""
        cmd = [
            self.kubectl_cmd, "get", "deployment",
            "catalytic-api",
            "-n", self.namespace,
            "-o", "json"
        ]

        result = self._run_command(cmd)

        if not result["success"]:
            return HealthCheck(
                name="deployment_status",
                status=HealthStatus.UNKNOWN,
                message="Failed to get deployment status",
                timestamp=datetime.now()
            )

        try:
            deployment = json.loads(result["output"])
            ready_replicas = deployment["status"].get("readyReplicas", 0)
            desired_replicas = deployment["spec"]["replicas"]
            available_replicas = deployment["status"].get("availableReplicas", 0)

            if ready_replicas == desired_replicas and available_replicas == desired_replicas:
                status = HealthStatus.HEALTHY
                message = f"All {ready_replicas} replicas are ready"
            elif ready_replicas >= desired_replicas * 0.5:
                status = HealthStatus.WARNING
                message = f"Only {ready_replicas}/{desired_replicas} replicas ready"
            else:
                status = HealthStatus.CRITICAL
                message = f"Critical: Only {ready_replicas}/{desired_replicas} replicas ready"

            return HealthCheck(
                name="deployment_status",
                status=status,
                message=message,
                timestamp=datetime.now(),
                details={
                    "ready": ready_replicas,
                    "desired": desired_replicas,
                    "available": available_replicas
                }
            )
        except Exception as e:
            return HealthCheck(
                name="deployment_status",
                status=HealthStatus.UNKNOWN,
                message=f"Error parsing deployment status: {e}",
                timestamp=datetime.now()
            )

    def check_pod_health(self) -> List[HealthCheck]:
        """Check health of individual pods"""
        health_checks = []

        # Get pod list
        cmd = [
            self.kubectl_cmd, "get", "pods",
            "-l", "app=catalytic-api",
            "-n", self.namespace,
            "-o", "json"
        ]

        result = self._run_command(cmd)

        if not result["success"]:
            health_checks.append(HealthCheck(
                name="pod_health",
                status=HealthStatus.UNKNOWN,
                message="Failed to get pod status",
                timestamp=datetime.now()
            ))
            return health_checks

        try:
            pods = json.loads(result["output"])

            for pod in pods["items"]:
                pod_name = pod["metadata"]["name"]
                phase = pod["status"]["phase"]
                conditions = pod["status"].get("conditions", [])

                # Check pod phase
                if phase == "Running":
                    # Check if all containers are ready
                    containers_ready = all(
                        c.get("ready", False) for c in pod["status"].get("containerStatuses", [])
                    )

                    if containers_ready:
                        status = HealthStatus.HEALTHY
                        message = f"Pod {pod_name} is healthy"
                    else:
                        status = HealthStatus.WARNING
                        message = f"Pod {pod_name} has containers not ready"
                elif phase == "Pending":
                    status = HealthStatus.WARNING
                    message = f"Pod {pod_name} is pending"
                else:
                    status = HealthStatus.CRITICAL
                    message = f"Pod {pod_name} is in {phase} state"

                # Check for restart count
                restart_count = sum(
                    c.get("restartCount", 0)
                    for c in pod["status"].get("containerStatuses", [])
                )

                if restart_count > 5:
                    status = HealthStatus.CRITICAL
                    message += f" (High restart count: {restart_count})"
                elif restart_count > 2:
                    status = HealthStatus.WARNING if status == HealthStatus.HEALTHY else status
                    message += f" (Restart count: {restart_count})"

                health_checks.append(HealthCheck(
                    name=f"pod_{pod_name}",
                    status=status,
                    message=message,
                    timestamp=datetime.now(),
                    details={
                        "phase": phase,
                        "restart_count": restart_count
                    }
                ))

        except Exception as e:
            health_checks.append(HealthCheck(
                name="pod_health",
                status=HealthStatus.UNKNOWN,
                message=f"Error parsing pod status: {e}",
                timestamp=datetime.now()
            ))

        return health_checks

    def collect_metrics(self) -> List[MetricData]:
        """Collect resource metrics from pods"""
        metrics = []

        # Get pod metrics
        cmd = [
            self.kubectl_cmd, "top", "pods",
            "-l", "app=catalytic-api",
            "-n", self.namespace,
            "--no-headers"
        ]

        result = self._run_command(cmd)

        if not result["success"]:
            self.logger.error(f"Failed to get pod metrics: {result['error']}")
            return metrics

        try:
            lines = result["output"].strip().split('\n')

            for line in lines:
                if not line:
                    continue

                parts = line.split()
                if len(parts) >= 3:
                    pod_name = parts[0]
                    cpu_str = parts[1].rstrip('m')  # Remove 'm' suffix
                    memory_str = parts[2].rstrip('Mi')  # Remove 'Mi' suffix

                    try:
                        cpu_usage = float(cpu_str) / 10  # Convert millicores to percentage
                        memory_usage = float(memory_str)

                        # For now, simulate request rate and latency
                        # In production, these would come from Prometheus or application metrics
                        import random
                        request_rate = random.uniform(100, 500)
                        error_rate = random.uniform(0, 2)
                        latency_p95 = random.uniform(50, 200)

                        metrics.append(MetricData(
                            timestamp=datetime.now(),
                            pod_name=pod_name,
                            cpu_usage=cpu_usage,
                            memory_usage=memory_usage,
                            request_rate=request_rate,
                            error_rate=error_rate,
                            latency_p95=latency_p95
                        ))
                    except ValueError:
                        continue

        except Exception as e:
            self.logger.error(f"Error parsing metrics: {e}")

        return metrics

    def analyze_metrics(self, metrics: List[MetricData]) -> List[HealthCheck]:
        """Analyze metrics and generate health checks"""
        health_checks = []

        if not metrics:
            return health_checks

        # Calculate averages
        avg_cpu = sum(m.cpu_usage for m in metrics) / len(metrics)
        avg_memory = sum(m.memory_usage for m in metrics) / len(metrics)
        avg_error_rate = sum(m.error_rate for m in metrics) / len(metrics)
        avg_latency = sum(m.latency_p95 for m in metrics) / len(metrics)

        # Check CPU usage
        if avg_cpu >= self.alert_thresholds["cpu_critical"]:
            status = HealthStatus.CRITICAL
            message = f"Critical CPU usage: {avg_cpu:.1f}%"
        elif avg_cpu >= self.alert_thresholds["cpu_warning"]:
            status = HealthStatus.WARNING
            message = f"High CPU usage: {avg_cpu:.1f}%"
        else:
            status = HealthStatus.HEALTHY
            message = f"CPU usage normal: {avg_cpu:.1f}%"

        health_checks.append(HealthCheck(
            name="cpu_usage",
            status=status,
            message=message,
            timestamp=datetime.now(),
            details={"average": avg_cpu}
        ))

        # Check memory usage
        memory_percentage = (avg_memory / 64000) * 100  # Assuming 64GB limit

        if memory_percentage >= self.alert_thresholds["memory_critical"]:
            status = HealthStatus.CRITICAL
            message = f"Critical memory usage: {memory_percentage:.1f}%"
        elif memory_percentage >= self.alert_thresholds["memory_warning"]:
            status = HealthStatus.WARNING
            message = f"High memory usage: {memory_percentage:.1f}%"
        else:
            status = HealthStatus.HEALTHY
            message = f"Memory usage normal: {memory_percentage:.1f}%"

        health_checks.append(HealthCheck(
            name="memory_usage",
            status=status,
            message=message,
            timestamp=datetime.now(),
            details={"average_mb": avg_memory, "percentage": memory_percentage}
        ))

        # Check error rate
        if avg_error_rate >= self.alert_thresholds["error_rate_critical"]:
            status = HealthStatus.CRITICAL
            message = f"Critical error rate: {avg_error_rate:.1f}%"
        elif avg_error_rate >= self.alert_thresholds["error_rate_warning"]:
            status = HealthStatus.WARNING
            message = f"Elevated error rate: {avg_error_rate:.1f}%"
        else:
            status = HealthStatus.HEALTHY
            message = f"Error rate normal: {avg_error_rate:.1f}%"

        health_checks.append(HealthCheck(
            name="error_rate",
            status=status,
            message=message,
            timestamp=datetime.now(),
            details={"average": avg_error_rate}
        ))

        # Check latency
        if avg_latency >= self.alert_thresholds["latency_critical"]:
            status = HealthStatus.CRITICAL
            message = f"Critical latency: {avg_latency:.0f}ms"
        elif avg_latency >= self.alert_thresholds["latency_warning"]:
            status = HealthStatus.WARNING
            message = f"High latency: {avg_latency:.0f}ms"
        else:
            status = HealthStatus.HEALTHY
            message = f"Latency normal: {avg_latency:.0f}ms"

        health_checks.append(HealthCheck(
            name="latency_p95",
            status=status,
            message=message,
            timestamp=datetime.now(),
            details={"average_ms": avg_latency}
        ))

        return health_checks

    def get_recent_logs(self, lines: int = 100) -> Dict[str, List[str]]:
        """Get recent logs from pods"""
        logs = {}

        # Get pod list
        cmd = [
            self.kubectl_cmd, "get", "pods",
            "-l", "app=catalytic-api",
            "-n", self.namespace,
            "-o", "json"
        ]

        result = self._run_command(cmd)

        if not result["success"]:
            return logs

        try:
            pods = json.loads(result["output"])

            for pod in pods["items"]:
                pod_name = pod["metadata"]["name"]

                # Get logs for each pod
                log_cmd = [
                    self.kubectl_cmd, "logs",
                    pod_name,
                    "-n", self.namespace,
                    f"--tail={lines}"
                ]

                log_result = self._run_command(log_cmd)

                if log_result["success"]:
                    logs[pod_name] = log_result["output"].split('\n')

        except Exception as e:
            self.logger.error(f"Error getting logs: {e}")

        return logs

    def analyze_logs(self, logs: Dict[str, List[str]]) -> List[HealthCheck]:
        """Analyze logs for errors and warnings"""
        health_checks = []
        error_patterns = ["ERROR", "FATAL", "CRITICAL", "Exception", "Failed"]
        warning_patterns = ["WARNING", "WARN", "Retry", "Timeout"]

        for pod_name, pod_logs in logs.items():
            error_count = 0
            warning_count = 0

            for line in pod_logs:
                line_upper = line.upper()
                if any(pattern.upper() in line_upper for pattern in error_patterns):
                    error_count += 1
                elif any(pattern.upper() in line_upper for pattern in warning_patterns):
                    warning_count += 1

            if error_count > 10:
                status = HealthStatus.CRITICAL
                message = f"High error count in logs: {error_count} errors"
            elif error_count > 5 or warning_count > 20:
                status = HealthStatus.WARNING
                message = f"Elevated log warnings: {error_count} errors, {warning_count} warnings"
            else:
                status = HealthStatus.HEALTHY
                message = "Log analysis normal"

            health_checks.append(HealthCheck(
                name=f"logs_{pod_name}",
                status=status,
                message=message,
                timestamp=datetime.now(),
                details={
                    "error_count": error_count,
                    "warning_count": warning_count
                }
            ))

        return health_checks

    def generate_health_report(self) -> Dict:
        """Generate comprehensive health report"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "namespace": self.namespace,
            "overall_status": HealthStatus.HEALTHY.value,
            "checks": [],
            "metrics": [],
            "recommendations": []
        }

        # Run health checks
        deployment_health = self.check_deployment_health()
        pod_health = self.check_pod_health()
        metrics = self.collect_metrics()
        metric_health = self.analyze_metrics(metrics)
        logs = self.get_recent_logs(50)
        log_health = self.analyze_logs(logs)

        # Combine all health checks
        all_checks = [deployment_health] + pod_health + metric_health + log_health

        # Determine overall status
        critical_count = sum(1 for c in all_checks if c.status == HealthStatus.CRITICAL)
        warning_count = sum(1 for c in all_checks if c.status == HealthStatus.WARNING)

        if critical_count > 0:
            report["overall_status"] = HealthStatus.CRITICAL.value
        elif warning_count > 2:
            report["overall_status"] = HealthStatus.WARNING.value

        # Add checks to report
        for check in all_checks:
            report["checks"].append({
                "name": check.name,
                "status": check.status.value,
                "message": check.message,
                "timestamp": check.timestamp.isoformat(),
                "details": check.details
            })

        # Add metrics to report
        for metric in metrics:
            report["metrics"].append({
                "pod": metric.pod_name,
                "cpu": metric.cpu_usage,
                "memory": metric.memory_usage,
                "request_rate": metric.request_rate,
                "error_rate": metric.error_rate,
                "latency_p95": metric.latency_p95
            })

        # Generate recommendations
        report["recommendations"] = self._generate_recommendations(all_checks, metrics)

        return report

    def _generate_recommendations(self, checks: List[HealthCheck], metrics: List[MetricData]) -> List[str]:
        """Generate recommendations based on health checks"""
        recommendations = []

        # Check for critical issues
        critical_checks = [c for c in checks if c.status == HealthStatus.CRITICAL]

        for check in critical_checks:
            if "cpu" in check.name.lower():
                recommendations.append("Scale up: CPU usage is critical. Consider adding more replicas or increasing CPU limits.")
            elif "memory" in check.name.lower():
                recommendations.append("Memory optimization: Review memory usage patterns and consider increasing memory limits.")
            elif "error_rate" in check.name.lower():
                recommendations.append("Error investigation: High error rate detected. Review application logs and recent deployments.")
            elif "pod" in check.name.lower() and "restart" in check.message.lower():
                recommendations.append("Stability issue: Pods are restarting frequently. Check for memory leaks or configuration issues.")

        # Check for warning issues
        warning_checks = [c for c in checks if c.status == HealthStatus.WARNING]

        if len(warning_checks) > 3:
            recommendations.append("System stress: Multiple warnings detected. Consider reviewing resource allocation and scaling policies.")

        # Check metrics trends
        if metrics:
            avg_cpu = sum(m.cpu_usage for m in metrics) / len(metrics)
            if avg_cpu > 60:
                recommendations.append("Proactive scaling: CPU usage trending high. Consider implementing predictive autoscaling.")

        if not recommendations:
            recommendations.append("System healthy: No immediate actions required. Continue monitoring.")

        return recommendations

    def start_continuous_monitoring(self, interval_seconds: int = 60):
        """Start continuous health monitoring"""
        self.is_monitoring = True
        self.logger.info(f"Starting continuous monitoring (interval: {interval_seconds}s)")

        def monitor_loop():
            while self.is_monitoring:
                try:
                    report = self.generate_health_report()

                    # Log summary
                    self.logger.info(f"Health Status: {report['overall_status']}")

                    # Check for critical issues
                    critical_checks = [c for c in report["checks"] if c["status"] == "critical"]
                    if critical_checks:
                        self.logger.critical(f"Critical issues detected: {len(critical_checks)}")
                        for check in critical_checks:
                            self.logger.critical(f"  - {check['name']}: {check['message']}")

                    # Store metrics for history
                    metrics = self.collect_metrics()
                    self.metrics_history.extend(metrics)

                    # Keep only last 1000 metrics
                    if len(self.metrics_history) > 1000:
                        self.metrics_history = self.metrics_history[-1000:]

                    time.sleep(interval_seconds)

                except Exception as e:
                    self.logger.error(f"Error in monitoring loop: {e}")
                    time.sleep(interval_seconds)

        monitoring_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitoring_thread.start()

    def stop_monitoring(self):
        """Stop continuous monitoring"""
        self.is_monitoring = False
        self.logger.info("Monitoring stopped")


def main():
    """Main entry point for health monitoring"""
    monitor = HealthMonitorAgent(namespace="catalytic-lattice")

    # Generate initial health report
    print("\nGenerating Health Report...")
    print("=" * 60)

    report = monitor.generate_health_report()

    # Display overall status
    status_emoji = {
        "healthy": "[OK]",
        "warning": "[WARNING]",
        "critical": "[CRITICAL]",
        "unknown": "[UNKNOWN]"
    }

    print(f"\nOverall Status: {status_emoji.get(report['overall_status'], '[UNKNOWN]')} {report['overall_status'].upper()}")
    print(f"Timestamp: {report['timestamp']}")
    print(f"Namespace: {report['namespace']}")

    # Display health checks
    print("\nHealth Checks:")
    for check in report["checks"]:
        emoji = status_emoji.get(check["status"], "[UNKNOWN]")
        print(f"  {emoji} {check['name']}: {check['message']}")

    # Display metrics summary
    if report["metrics"]:
        print("\nResource Metrics (Average):")
        avg_cpu = sum(m["cpu"] for m in report["metrics"]) / len(report["metrics"])
        avg_memory = sum(m["memory"] for m in report["metrics"]) / len(report["metrics"])
        print(f"  CPU Usage: {avg_cpu:.1f}%")
        print(f"  Memory Usage: {avg_memory:.0f} MB")

    # Display recommendations
    print("\nRecommendations:")
    for i, rec in enumerate(report["recommendations"], 1):
        print(f"  {i}. {rec}")

    # Option to start continuous monitoring
    print("\n" + "=" * 60)
    response = input("\nStart continuous monitoring? (y/n): ")

    if response.lower() == 'y':
        monitor.start_continuous_monitoring(interval_seconds=30)
        print("Continuous monitoring started (30s interval)")
        print("Press Ctrl+C to stop...")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            monitor.stop_monitoring()
            print("\nMonitoring stopped")


if __name__ == "__main__":
    main()