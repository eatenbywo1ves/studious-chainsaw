"""
Enhanced Agent Registry with Performance Optimization
Extends the original registry with performance-based load balancing and optimization
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from enum import Enum
import uuid
from dataclasses import dataclass, field

# Import original components
from agent_registry import AgentRegistry, AgentInfo, AgentStatus
from redis_communication import RedisCommunicator, RedisConfig, MessageType
from performance_optimizer import PerformanceOptimizer, PerformanceMetric, PerformanceMetricType

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EnhancedAgentRegistry(AgentRegistry):
    """Enhanced Agent Registry with performance optimization capabilities"""

    def __init__(self, redis_config: RedisConfig = None):
        super().__init__(redis_config)
        self.performance_optimizer = PerformanceOptimizer(self)
        self.performance_monitoring_enabled = True
        self.auto_optimization_enabled = True
        self.performance_metrics_interval = 30  # seconds

        # Performance tracking
        self.agent_performance_history: Dict[str, List[Dict[str, Any]]] = {}
        self.optimization_actions_taken: List[Dict[str, Any]] = []

    async def start(self):
        """Start the enhanced agent registry with performance monitoring"""
        logger.info("Starting Enhanced Agent Registry with Performance Optimization")

        # Start the original registry
        started = await super().start()
        if not started:
            return False

        # Start performance monitoring
        if self.performance_monitoring_enabled:
            asyncio.create_task(self.performance_monitoring_loop())
            logger.info("Performance monitoring enabled")

        # Start auto-optimization
        if self.auto_optimization_enabled:
            asyncio.create_task(self.auto_optimization_loop())
            logger.info("Auto-optimization enabled")

        return True

    async def register_agent_with_performance(self, agent_info: AgentInfo,
                                            initial_metrics: Optional[Dict[str, float]] = None):
        """Register an agent with initial performance metrics"""

        # Register with original method
        await self.handle_agent_registration({
            'payload': {
                'agent_id': agent_info.id,
                'agent_type': agent_info.type
            }
        })

        # Record initial performance metrics if provided
        if initial_metrics:
            current_time = datetime.now()

            for metric_name, value in initial_metrics.items():
                try:
                    metric_type = PerformanceMetricType(metric_name)
                    metric = PerformanceMetric(
                        metric_type=metric_type,
                        value=value,
                        timestamp=current_time,
                        agent_id=agent_info.id
                    )
                    await self.performance_optimizer.record_performance_metric(metric)
                except ValueError:
                    logger.warning(f"Unknown metric type: {metric_name}")

        logger.info(f"Agent {agent_info.id} registered with performance tracking")

    async def get_best_agent_enhanced(self, agent_type: str,
                                    task_requirements: Dict[str, Any] = None,
                                    performance_weight: float = 0.6) -> Optional[AgentInfo]:
        """Enhanced agent selection using performance optimization"""

        if self.performance_monitoring_enabled:
            # Use performance optimizer for selection
            best_agent_id = await self.performance_optimizer.select_optimal_agent(
                agent_type, task_requirements or {}
            )

            if best_agent_id and best_agent_id in self.agents:
                return self.agents[best_agent_id]

        # Fallback to original method
        return self.get_best_agent(agent_type, task_requirements.get('required_capabilities', []) if task_requirements else [])

    async def record_agent_performance(self, agent_id: str, metrics: Dict[str, float]):
        """Record performance metrics for an agent"""
        current_time = datetime.now()

        for metric_name, value in metrics.items():
            try:
                metric_type = PerformanceMetricType(metric_name)
                metric = PerformanceMetric(
                    metric_type=metric_type,
                    value=value,
                    timestamp=current_time,
                    agent_id=agent_id
                )
                await self.performance_optimizer.record_performance_metric(metric)
            except ValueError:
                logger.warning(f"Unknown metric type: {metric_name}")

        # Update agent's performance history
        if agent_id not in self.agent_performance_history:
            self.agent_performance_history[agent_id] = []

        self.agent_performance_history[agent_id].append({
            'timestamp': current_time.isoformat(),
            'metrics': metrics
        })

        # Keep only last 100 performance records per agent
        if len(self.agent_performance_history[agent_id]) > 100:
            self.agent_performance_history[agent_id] = self.agent_performance_history[agent_id][-100:]

    async def get_agent_performance_summary(self, agent_id: str) -> Dict[str, Any]:
        """Get comprehensive performance summary for an agent"""
        if agent_id not in self.agents:
            return {"error": "Agent not found"}

        agent = self.agents[agent_id]
        performance_score = await self.performance_optimizer.get_agent_performance_score(agent_id)

        # Get recent performance history
        recent_history = self.agent_performance_history.get(agent_id, [])[-10:]

        # Calculate trends
        trends = {}
        if len(recent_history) >= 2:
            for metric_name in ['cpu_usage', 'memory_usage', 'task_latency']:
                values = []
                for record in recent_history:
                    if metric_name in record['metrics']:
                        values.append(record['metrics'][metric_name])

                if len(values) >= 2:
                    trend = "increasing" if values[-1] > values[0] else "decreasing"
                    trends[metric_name] = {
                        'trend': trend,
                        'change': values[-1] - values[0],
                        'current': values[-1]
                    }

        return {
            'agent_id': agent_id,
            'agent_type': agent.type,
            'status': agent.status.value,
            'performance_score': performance_score,
            'capacity': agent.capacity,
            'tasks_completed': agent.tasks_completed,
            'tasks_failed': agent.tasks_failed,
            'success_rate': (agent.tasks_completed / (agent.tasks_completed + agent.tasks_failed)) * 100
                           if (agent.tasks_completed + agent.tasks_failed) > 0 else 100,
            'average_task_time': agent.average_task_time,
            'last_heartbeat': agent.last_heartbeat.isoformat(),
            'trends': trends,
            'recent_performance_history': recent_history
        }

    async def get_system_performance_overview(self) -> Dict[str, Any]:
        """Get system-wide performance overview"""
        dashboard_data = await self.performance_optimizer.get_performance_dashboard_data()

        # Add registry-specific information
        registry_stats = self.get_registry_stats()

        overview = {
            'timestamp': datetime.now().isoformat(),
            'system_health': dashboard_data['system_health'],
            'registry_stats': registry_stats,
            'agent_performance': dashboard_data['agent_summary'],
            'optimization_recommendations': dashboard_data['recommendations'],
            'summary': dashboard_data['summary_stats'],
            'recent_optimizations': self.optimization_actions_taken[-5:],  # Last 5 optimizations
            'performance_targets': self.performance_optimizer.performance_targets
        }

        return overview

    async def apply_optimization_recommendation(self, recommendation_data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply an optimization recommendation"""
        action = recommendation_data.get('action')
        agent_id = recommendation_data.get('agent_id')

        if not action or not agent_id:
            return {"success": False, "error": "Missing action or agent_id"}

        result = {"success": False, "action_taken": None, "details": {}}

        try:
            if action == "scale_up":
                result = await self._handle_scale_up(agent_id)
            elif action == "scale_down":
                result = await self._handle_scale_down(agent_id)
            elif action == "redistribute_load":
                result = await self._handle_redistribute_load(agent_id)
            elif action == "restart_agent":
                result = await self._handle_restart_agent(agent_id)
            elif action == "optimize_resources":
                result = await self._handle_optimize_resources(agent_id)
            else:
                result = {"success": False, "error": f"Unknown action: {action}"}

            # Record the optimization action
            if result["success"]:
                self.optimization_actions_taken.append({
                    'timestamp': datetime.now().isoformat(),
                    'action': action,
                    'agent_id': agent_id,
                    'result': result,
                    'recommendation': recommendation_data
                })

                # Keep only last 50 optimization actions
                if len(self.optimization_actions_taken) > 50:
                    self.optimization_actions_taken = self.optimization_actions_taken[-50:]

        except Exception as e:
            logger.error(f"Error applying optimization {action} for {agent_id}: {e}")
            result = {"success": False, "error": str(e)}

        return result

    async def performance_monitoring_loop(self):
        """Background loop for collecting performance metrics"""
        while self.running:
            try:
                await self._collect_agent_performance_metrics()
                await asyncio.sleep(self.performance_metrics_interval)
            except Exception as e:
                logger.error(f"Performance monitoring error: {e}")
                await asyncio.sleep(self.performance_metrics_interval)

    async def auto_optimization_loop(self):
        """Background loop for automated optimization"""
        while self.running:
            try:
                await self._run_auto_optimization()
                await asyncio.sleep(300)  # Run every 5 minutes
            except Exception as e:
                logger.error(f"Auto-optimization error: {e}")
                await asyncio.sleep(300)

    async def _collect_agent_performance_metrics(self):
        """Collect performance metrics from all registered agents"""
        for agent_id, agent in self.agents.items():
            if agent.status == AgentStatus.ONLINE:
                # Simulate performance metrics collection
                # In a real implementation, this would query the agent directly

                simulated_metrics = {
                    'cpu_usage': min(100, max(0, agent.capacity + (hash(agent_id) % 20 - 10))),
                    'memory_usage': min(100, max(0, agent.capacity * 0.8 + (hash(agent_id) % 15 - 7))),
                    'task_latency': agent.average_task_time,
                    'error_rate': (agent.tasks_failed / max(1, agent.tasks_completed + agent.tasks_failed)) * 100
                }

                await self.record_agent_performance(agent_id, simulated_metrics)

    async def _run_auto_optimization(self):
        """Run automated optimization based on current performance"""
        if not self.auto_optimization_enabled:
            return

        recommendations = await self.performance_optimizer.get_optimization_recommendations()

        # Apply high-priority recommendations automatically
        for rec in recommendations:
            if rec.priority >= 8:  # High priority
                logger.info(f"Auto-applying optimization: {rec.action.value} for {rec.agent_id}")

                result = await self.apply_optimization_recommendation({
                    'action': rec.action.value,
                    'agent_id': rec.agent_id,
                    'reasoning': rec.reasoning
                })

                if result["success"]:
                    logger.info(f"Auto-optimization successful: {result}")
                else:
                    logger.warning(f"Auto-optimization failed: {result}")

    # Optimization action handlers
    async def _handle_scale_up(self, agent_id: str) -> Dict[str, Any]:
        """Handle scaling up an agent"""
        if agent_id in self.agents:
            # In a real system, this would trigger actual scaling
            logger.info(f"Scaling up agent {agent_id}")
            return {"success": True, "action_taken": "scale_up", "details": "Agent marked for scaling"}
        return {"success": False, "error": "Agent not found"}

    async def _handle_scale_down(self, agent_id: str) -> Dict[str, Any]:
        """Handle scaling down an agent"""
        if agent_id in self.agents:
            logger.info(f"Scaling down agent {agent_id}")
            return {"success": True, "action_taken": "scale_down", "details": "Agent marked for scaling down"}
        return {"success": False, "error": "Agent not found"}

    async def _handle_redistribute_load(self, agent_id: str) -> Dict[str, Any]:
        """Handle redistributing load away from an agent"""
        if agent_id in self.agents:
            # Reduce agent capacity temporarily
            self.agents[agent_id].capacity = max(10, self.agents[agent_id].capacity - 30)
            logger.info(f"Redistributing load for agent {agent_id}")
            return {"success": True, "action_taken": "redistribute_load",
                   "details": f"Reduced capacity to {self.agents[agent_id].capacity}"}
        return {"success": False, "error": "Agent not found"}

    async def _handle_restart_agent(self, agent_id: str) -> Dict[str, Any]:
        """Handle restarting an agent"""
        if agent_id in self.agents:
            # Mark agent for restart
            self.agents[agent_id].status = AgentStatus.MAINTENANCE
            logger.info(f"Agent {agent_id} marked for restart")
            return {"success": True, "action_taken": "restart_agent",
                   "details": "Agent marked for restart"}
        return {"success": False, "error": "Agent not found"}

    async def _handle_optimize_resources(self, agent_id: str) -> Dict[str, Any]:
        """Handle resource optimization for an agent"""
        if agent_id in self.agents:
            logger.info(f"Optimizing resources for agent {agent_id}")
            return {"success": True, "action_taken": "optimize_resources",
                   "details": "Resource optimization triggered"}
        return {"success": False, "error": "Agent not found"}

# Test and example usage
async def test_enhanced_registry():
    """Test the enhanced agent registry"""

    registry = EnhancedAgentRegistry()

    # Start the registry
    started = await registry.start()
    if not started:
        print("❌ Failed to start enhanced registry")
        return

    print("✅ Enhanced Agent Registry started")

    # Wait a bit for startup
    await asyncio.sleep(2)

    # Simulate agent registration with performance metrics
    test_agent = AgentInfo(
        id="test-agent-001",
        type="performance-test",
        status=AgentStatus.ONLINE,
        capabilities=["test", "performance"],
        capacity=75,
        registered_at=datetime.now(),
        last_heartbeat=datetime.now()
    )

    await registry.register_agent_with_performance(
        test_agent,
        initial_metrics={
            'cpu_usage': 45.0,
            'memory_usage': 60.0,
            'task_latency': 1500.0,
            'error_rate': 2.0
        }
    )

    # Test performance tracking
    await registry.record_agent_performance("test-agent-001", {
        'cpu_usage': 50.0,
        'memory_usage': 65.0,
        'task_latency': 1400.0,
        'error_rate': 1.5
    })

    # Get performance summary
    summary = await registry.get_agent_performance_summary("test-agent-001")
    print("📊 Agent Performance Summary:")
    print(json.dumps(summary, indent=2))

    # Get system overview
    overview = await registry.get_system_performance_overview()
    print("\n🌐 System Performance Overview:")
    print(json.dumps(overview, indent=2))

    await registry.stop()
    print("✅ Enhanced Agent Registry stopped")

if __name__ == "__main__":
    asyncio.run(test_enhanced_registry())