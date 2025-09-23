#!/usr/bin/env python3
"""
Orchestrator - Coordinates all agents for complete K8s management
"""

import threading
import time
import logging
from datetime import datetime
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AgentOrchestrator:
    """Coordinates deployment, monitoring, and scaling agents"""

    def __init__(self):
        self.deployment_status = "pending"
        self.health_status = "unknown"
        self.scaling_active = False
        self.is_running = False

    def deploy_application(self):
        """Simulate deployment process"""
        logger.info("Starting deployment process...")
        self.deployment_status = "deploying"

        steps = [
            ("Checking prerequisites", 2),
            ("Creating namespace", 1),
            ("Deploying application", 3),
            ("Configuring services", 2),
            ("Setting up autoscaling", 1)
        ]

        for step, duration in steps:
            logger.info(f"Deployment: {step}")
            time.sleep(duration)

        self.deployment_status = "deployed"
        logger.info("[SUCCESS] Application deployed successfully")

    def monitor_health(self):
        """Continuous health monitoring"""
        logger.info("Starting health monitoring...")

        while self.is_running:
            # Simulate health checks
            import random

            metrics = {
                "cpu": random.uniform(40, 80),
                "memory": random.uniform(50, 70),
                "error_rate": random.uniform(0, 3),
                "response_time": random.uniform(100, 500)
            }

            # Determine health status
            if metrics["cpu"] > 75 or metrics["error_rate"] > 2:
                self.health_status = "warning"
                logger.warning(f"Health Warning - CPU: {metrics['cpu']:.1f}%, Errors: {metrics['error_rate']:.1f}%")
            else:
                self.health_status = "healthy"
                logger.info(f"Health OK - CPU: {metrics['cpu']:.1f}%, Memory: {metrics['memory']:.1f}%")

            time.sleep(10)  # Check every 10 seconds

    def manage_scaling(self):
        """Auto-scaling management"""
        logger.info("Starting auto-scaling management...")
        self.scaling_active = True

        import random
        current_replicas = 3

        while self.is_running:
            # Simulate scaling decisions
            cpu_load = random.uniform(30, 85)

            if cpu_load > 70 and current_replicas < 20:
                new_replicas = min(current_replicas + 2, 20)
                logger.info(f"Scaling UP: {current_replicas} -> {new_replicas} replicas (CPU: {cpu_load:.1f}%)")
                current_replicas = new_replicas

            elif cpu_load < 40 and current_replicas > 3:
                new_replicas = max(current_replicas - 1, 3)
                logger.info(f"Scaling DOWN: {current_replicas} -> {new_replicas} replicas (CPU: {cpu_load:.1f}%)")
                current_replicas = new_replicas

            else:
                logger.debug(f"No scaling needed: {current_replicas} replicas (CPU: {cpu_load:.1f}%)")

            time.sleep(15)  # Check every 15 seconds

    def start(self):
        """Start all agents"""
        self.is_running = True

        print("\n" + "=" * 60)
        print("  CATALYTIC LATTICE K8S ORCHESTRATOR")
        print("=" * 60)
        print("\nOrchestrating deployment, monitoring, and scaling...")
        print("Press Ctrl+C to stop\n")

        # Phase 1: Deploy
        deploy_thread = threading.Thread(target=self.deploy_application)
        deploy_thread.start()
        deploy_thread.join()  # Wait for deployment to complete

        # Phase 2: Start monitoring and scaling
        monitor_thread = threading.Thread(target=self.monitor_health, daemon=True)
        scaling_thread = threading.Thread(target=self.manage_scaling, daemon=True)

        monitor_thread.start()
        time.sleep(2)  # Small delay
        scaling_thread.start()

        # Keep running
        try:
            while True:
                time.sleep(1)

                # Print status summary every 20 seconds
                if int(time.time()) % 20 == 0:
                    self.print_status_summary()

        except KeyboardInterrupt:
            logger.info("Shutdown requested...")
            self.stop()

    def print_status_summary(self):
        """Print current system status"""
        print("\n" + "-" * 40)
        print(f"STATUS SUMMARY [{datetime.now().strftime('%H:%M:%S')}]")
        print(f"  Deployment: {self.deployment_status}")
        print(f"  Health: {self.health_status}")
        print(f"  Auto-scaling: {'active' if self.scaling_active else 'inactive'}")
        print("-" * 40)

    def stop(self):
        """Stop all agents"""
        self.is_running = False
        logger.info("Orchestrator stopped")
        print("\nAll agents stopped. Goodbye!")


def main():
    """Main entry point"""
    orchestrator = AgentOrchestrator()
    orchestrator.start()


if __name__ == "__main__":
    main()