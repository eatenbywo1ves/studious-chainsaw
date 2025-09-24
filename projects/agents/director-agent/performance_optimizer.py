"""
Performance Optimizer for Director Agent
Handles performance-based load balancing and optimization decisions
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import statistics

logger = logging.getLogger(__name__)

class PerformanceMetricType(Enum):
    CPU_USAGE = "cpu_usage"
    MEMORY_USAGE = "memory_usage"
    NETWORK_IO = "network_io"
    TASK_LATENCY = "task_latency"
    THROUGHPUT = "throughput"
    ERROR_RATE = "error_rate"

class OptimizationAction(Enum):
    SCALE_UP = "scale_up"
    SCALE_DOWN = "scale_down"
    REDISTRIBUTE_LOAD = "redistribute_load"
    OPTIMIZE_RESOURCES = "optimize_resources"
    RESTART_AGENT = "restart_agent"
    NO_ACTION = "no_action"

@dataclass
class PerformanceMetric:
    metric_type: PerformanceMetricType
    value: float
    timestamp: datetime
    agent_id: str
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class PerformanceThreshold:
    metric_type: PerformanceMetricType
    warning_threshold: float
    critical_threshold: float
    optimization_threshold: float

@dataclass
class OptimizationRecommendation:
    action: OptimizationAction
    agent_id: str
    reasoning: str
    priority: int  # 1-10, higher is more urgent
    estimated_impact: str
    metadata: Dict[str, Any] = field(default_factory=dict)

class PerformanceOptimizer:
    """Enhanced performance optimization for Director Agent Registry"""

    def __init__(self, registry_instance):
        self.registry = registry_instance
        self.metrics_history: Dict[str, List[PerformanceMetric]] = {}
        self.thresholds = self._initialize_thresholds()
        self.optimization_rules = self._initialize_optimization_rules()
        self.performance_targets = {
            'max_cpu_utilization': 70.0,
            'max_memory_utilization': 80.0,
            'max_task_latency_ms': 5000.0,
            'min_throughput_tasks_sec': 1.0,
            'max_error_rate_percent': 5.0
        }

    def _initialize_thresholds(self) -> Dict[PerformanceMetricType, PerformanceThreshold]:
        """Initialize performance thresholds for different metrics"""
        return {
            PerformanceMetricType.CPU_USAGE: PerformanceThreshold(
                PerformanceMetricType.CPU_USAGE,
                warning_threshold=60.0,
                critical_threshold=85.0,
                optimization_threshold=70.0
            ),
            PerformanceMetricType.MEMORY_USAGE: PerformanceThreshold(
                PerformanceMetricType.MEMORY_USAGE,
                warning_threshold=70.0,
                critical_threshold=90.0,
                optimization_threshold=80.0
            ),
            PerformanceMetricType.TASK_LATENCY: PerformanceThreshold(
                PerformanceMetricType.TASK_LATENCY,
                warning_threshold=3000.0,  # 3 seconds
                critical_threshold=10000.0,  # 10 seconds
                optimization_threshold=5000.0  # 5 seconds
            ),
            PerformanceMetricType.ERROR_RATE: PerformanceThreshold(
                PerformanceMetricType.ERROR_RATE,
                warning_threshold=2.0,  # 2%
                critical_threshold=10.0,  # 10%
                optimization_threshold=5.0  # 5%
            ),
            PerformanceMetricType.THROUGHPUT: PerformanceThreshold(
                PerformanceMetricType.THROUGHPUT,
                warning_threshold=0.5,  # tasks/sec
                critical_threshold=0.1,  # tasks/sec
                optimization_threshold=1.0  # tasks/sec
            )
        }

    def _initialize_optimization_rules(self) -> List[Dict[str, Any]]:
        """Initialize optimization rules for automated decisions"""
        return [
            {
                'name': 'high_cpu_scale_up',
                'condition': lambda metrics: self._check_sustained_high_cpu(metrics),
                'action': OptimizationAction.SCALE_UP,
                'priority': 8,
                'reasoning': 'Sustained high CPU usage requires additional capacity'
            },
            {
                'name': 'low_utilization_scale_down',
                'condition': lambda metrics: self._check_sustained_low_utilization(metrics),
                'action': OptimizationAction.SCALE_DOWN,
                'priority': 4,
                'reasoning': 'Low resource utilization suggests over-provisioning'
            },
            {
                'name': 'high_error_rate_restart',
                'condition': lambda metrics: self._check_high_error_rate(metrics),
                'action': OptimizationAction.RESTART_AGENT,
                'priority': 9,
                'reasoning': 'High error rate may indicate agent instability'
            },
            {
                'name': 'uneven_load_redistribute',
                'condition': lambda metrics: self._check_uneven_load_distribution(metrics),
                'action': OptimizationAction.REDISTRIBUTE_LOAD,
                'priority': 6,
                'reasoning': 'Load imbalance detected across agents'
            }
        ]

    async def record_performance_metric(self, metric: PerformanceMetric):
        """Record a performance metric for an agent"""
        agent_id = metric.agent_id

        if agent_id not in self.metrics_history:
            self.metrics_history[agent_id] = []

        self.metrics_history[agent_id].append(metric)

        # Keep only last 1000 metrics per agent to manage memory
        if len(self.metrics_history[agent_id]) > 1000:
            self.metrics_history[agent_id] = self.metrics_history[agent_id][-1000:]

        # Trigger real-time optimization check
        await self._evaluate_optimization_opportunity(agent_id, metric)

    async def get_agent_performance_score(self, agent_id: str) -> float:
        """Calculate comprehensive performance score for an agent (0-100)"""
        if agent_id not in self.metrics_history:
            return 50.0  # Default neutral score

        recent_metrics = self._get_recent_metrics(agent_id, minutes=15)
        if not recent_metrics:
            return 50.0

        scores = []

        # CPU score (lower usage = higher score)
        cpu_metrics = [m for m in recent_metrics if m.metric_type == PerformanceMetricType.CPU_USAGE]
        if cpu_metrics:
            avg_cpu = statistics.mean([m.value for m in cpu_metrics])
            cpu_score = max(0, 100 - avg_cpu)
            scores.append(cpu_score)

        # Memory score (lower usage = higher score)
        memory_metrics = [m for m in recent_metrics if m.metric_type == PerformanceMetricType.MEMORY_USAGE]
        if memory_metrics:
            avg_memory = statistics.mean([m.value for m in memory_metrics])
            memory_score = max(0, 100 - avg_memory)
            scores.append(memory_score)

        # Latency score (lower latency = higher score)
        latency_metrics = [m for m in recent_metrics if m.metric_type == PerformanceMetricType.TASK_LATENCY]
        if latency_metrics:
            avg_latency = statistics.mean([m.value for m in latency_metrics])
            latency_score = max(0, 100 - (avg_latency / 100))  # Scale for scoring
            scores.append(latency_score)

        # Error rate score (lower errors = higher score)
        error_metrics = [m for m in recent_metrics if m.metric_type == PerformanceMetricType.ERROR_RATE]
        if error_metrics:
            avg_error_rate = statistics.mean([m.value for m in error_metrics])
            error_score = max(0, 100 - (avg_error_rate * 10))
            scores.append(error_score)

        # Throughput score (higher throughput = higher score)
        throughput_metrics = [m for m in recent_metrics if m.metric_type == PerformanceMetricType.THROUGHPUT]
        if throughput_metrics:
            avg_throughput = statistics.mean([m.value for m in throughput_metrics])
            throughput_score = min(100, avg_throughput * 50)  # Scale for scoring
            scores.append(throughput_score)

        # Calculate weighted average
        if scores:
            return statistics.mean(scores)

        return 50.0

    async def get_optimization_recommendations(self, agent_id: Optional[str] = None) -> List[OptimizationRecommendation]:
        """Get optimization recommendations for specific agent or all agents"""
        recommendations = []

        agent_ids = [agent_id] if agent_id else list(self.metrics_history.keys())

        for aid in agent_ids:
            if aid not in self.metrics_history:
                continue

            recent_metrics = self._get_recent_metrics(aid, minutes=30)

            for rule in self.optimization_rules:
                if rule['condition'](recent_metrics):
                    recommendation = OptimizationRecommendation(
                        action=rule['action'],
                        agent_id=aid,
                        reasoning=rule['reasoning'],
                        priority=rule['priority'],
                        estimated_impact=self._estimate_optimization_impact(rule['action'], aid),
                        metadata={'rule_name': rule['name']}
                    )
                    recommendations.append(recommendation)

        # Sort by priority (highest first)
        recommendations.sort(key=lambda r: r.priority, reverse=True)

        return recommendations

    async def select_optimal_agent(self, agent_type: str, task_requirements: Dict[str, Any]) -> Optional[str]:
        """Enhanced agent selection based on performance metrics"""
        # Get available agents of the requested type
        available_agents = self.registry.get_available_agents(agent_type)

        if not available_agents:
            return None

        # Calculate performance scores for each agent
        agent_scores = []

        for agent in available_agents:
            performance_score = await self.get_agent_performance_score(agent.id)

            # Factor in current capacity
            capacity_score = agent.capacity

            # Factor in task success rate
            if agent.tasks_completed > 0:
                success_rate = (agent.tasks_completed /
                              (agent.tasks_completed + agent.tasks_failed)) * 100
            else:
                success_rate = 100  # No history, assume good

            # Factor in average task time (lower is better)
            latency_score = max(0, 100 - (agent.average_task_time / 100))

            # Composite score with weights
            composite_score = (
                performance_score * 0.4 +
                capacity_score * 0.3 +
                success_rate * 0.2 +
                latency_score * 0.1
            )

            agent_scores.append((agent.id, composite_score, agent))

        # Sort by composite score (highest first)
        agent_scores.sort(key=lambda x: x[1], reverse=True)

        # Return the best agent
        return agent_scores[0][0] if agent_scores else None

    def _get_recent_metrics(self, agent_id: str, minutes: int = 15) -> List[PerformanceMetric]:
        """Get metrics from the last N minutes"""
        if agent_id not in self.metrics_history:
            return []

        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        return [m for m in self.metrics_history[agent_id] if m.timestamp > cutoff_time]

    def _check_sustained_high_cpu(self, metrics: List[PerformanceMetric]) -> bool:
        """Check if agent has sustained high CPU usage"""
        cpu_metrics = [m for m in metrics if m.metric_type == PerformanceMetricType.CPU_USAGE]
        if len(cpu_metrics) < 5:  # Need at least 5 data points
            return False

        high_cpu_count = sum(1 for m in cpu_metrics[-10:] if m.value > 80)
        return high_cpu_count >= 7  # 70% of recent metrics show high CPU

    def _check_sustained_low_utilization(self, metrics: List[PerformanceMetric]) -> bool:
        """Check if agent has sustained low resource utilization"""
        cpu_metrics = [m for m in metrics if m.metric_type == PerformanceMetricType.CPU_USAGE]
        memory_metrics = [m for m in metrics if m.metric_type == PerformanceMetricType.MEMORY_USAGE]

        if len(cpu_metrics) < 10 or len(memory_metrics) < 10:
            return False

        avg_cpu = statistics.mean([m.value for m in cpu_metrics[-20:]])
        avg_memory = statistics.mean([m.value for m in memory_metrics[-20:]])

        return avg_cpu < 10 and avg_memory < 30  # Very low utilization

    def _check_high_error_rate(self, metrics: List[PerformanceMetric]) -> bool:
        """Check if agent has high error rate"""
        error_metrics = [m for m in metrics if m.metric_type == PerformanceMetricType.ERROR_RATE]
        if len(error_metrics) < 5:
            return False

        recent_error_rate = statistics.mean([m.value for m in error_metrics[-10:]])
        return recent_error_rate > 10  # More than 10% error rate

    def _check_uneven_load_distribution(self, metrics: List[PerformanceMetric]) -> bool:
        """Check if there's uneven load distribution across agents"""
        # This would need to compare across multiple agents
        # For now, return False as this requires global analysis
        return False

    def _estimate_optimization_impact(self, action: OptimizationAction, agent_id: str) -> str:
        """Estimate the impact of an optimization action"""
        impact_estimates = {
            OptimizationAction.SCALE_UP: "15-25% performance improvement, higher resource cost",
            OptimizationAction.SCALE_DOWN: "5-10% cost reduction, minimal performance impact",
            OptimizationAction.REDISTRIBUTE_LOAD: "10-20% overall efficiency improvement",
            OptimizationAction.OPTIMIZE_RESOURCES: "5-15% resource efficiency improvement",
            OptimizationAction.RESTART_AGENT: "50-90% error rate reduction, temporary downtime",
            OptimizationAction.NO_ACTION: "No change expected"
        }

        return impact_estimates.get(action, "Impact unknown")

    async def _evaluate_optimization_opportunity(self, agent_id: str, metric: PerformanceMetric):
        """Evaluate if immediate optimization is needed based on new metric"""
        threshold = self.thresholds.get(metric.metric_type)
        if not threshold:
            return

        # Check for critical thresholds
        if metric.value > threshold.critical_threshold:
            logger.warning(
                f"Critical threshold exceeded for {agent_id}: "
                f"{metric.metric_type.value} = {metric.value}"
            )

            # Trigger immediate optimization
            await self._trigger_emergency_optimization(agent_id, metric)

    async def _trigger_emergency_optimization(self, agent_id: str, metric: PerformanceMetric):
        """Trigger emergency optimization for critical metrics"""
        logger.info(f"Triggering emergency optimization for agent {agent_id}")

        # This could integrate with the Director Agent's task assignment system
        # to immediately redistribute load or take corrective action

        # For now, just log the action
        if metric.metric_type == PerformanceMetricType.CPU_USAGE:
            logger.info(f"Recommendation: Scale up or redistribute load for {agent_id}")
        elif metric.metric_type == PerformanceMetricType.MEMORY_USAGE:
            logger.info(f"Recommendation: Check for memory leaks in {agent_id}")
        elif metric.metric_type == PerformanceMetricType.ERROR_RATE:
            logger.info(f"Recommendation: Restart agent {agent_id}")

    async def get_performance_dashboard_data(self) -> Dict[str, Any]:
        """Get comprehensive performance data for dashboard display"""
        dashboard_data = {
            'timestamp': datetime.now().isoformat(),
            'agent_summary': {},
            'system_health': 'HEALTHY',
            'recommendations': [],
            'performance_trends': {}
        }

        total_agents = len(self.metrics_history)
        healthy_agents = 0
        warning_agents = 0
        critical_agents = 0

        for agent_id in self.metrics_history.keys():
            score = await self.get_agent_performance_score(agent_id)
            recent_metrics = self._get_recent_metrics(agent_id, minutes=15)

            if score > 80:
                status = 'HEALTHY'
                healthy_agents += 1
            elif score > 60:
                status = 'WARNING'
                warning_agents += 1
            else:
                status = 'CRITICAL'
                critical_agents += 1

            dashboard_data['agent_summary'][agent_id] = {
                'performance_score': score,
                'status': status,
                'metrics_count': len(recent_metrics),
                'last_update': recent_metrics[-1].timestamp.isoformat() if recent_metrics else None
            }

        # Overall system health
        if critical_agents > 0:
            dashboard_data['system_health'] = 'CRITICAL'
        elif warning_agents > total_agents * 0.3:  # More than 30% in warning
            dashboard_data['system_health'] = 'WARNING'

        # Get top recommendations
        recommendations = await self.get_optimization_recommendations()
        dashboard_data['recommendations'] = [
            {
                'action': rec.action.value,
                'agent_id': rec.agent_id,
                'reasoning': rec.reasoning,
                'priority': rec.priority
            }
            for rec in recommendations[:5]  # Top 5 recommendations
        ]

        dashboard_data['summary_stats'] = {
            'total_agents': total_agents,
            'healthy_agents': healthy_agents,
            'warning_agents': warning_agents,
            'critical_agents': critical_agents,
            'top_recommendations': len(recommendations)
        }

        return dashboard_data

# Example usage and integration
async def integrate_with_registry(registry_instance):
    """Example of how to integrate PerformanceOptimizer with existing registry"""

    optimizer = PerformanceOptimizer(registry_instance)

    # Example: Record some performance metrics
    await optimizer.record_performance_metric(
        PerformanceMetric(
            PerformanceMetricType.CPU_USAGE,
            75.5,
            datetime.now(),
            "agent-123"
        )
    )

    # Example: Get optimization recommendations
    recommendations = await optimizer.get_optimization_recommendations()
    for rec in recommendations:
        logger.info(f"Optimization: {rec.action.value} for {rec.agent_id} - {rec.reasoning}")

    # Example: Enhanced agent selection
    best_agent = await optimizer.select_optimal_agent("visual", {"complexity": "high"})
    if best_agent:
        logger.info(f"Selected optimal agent: {best_agent}")

    return optimizer