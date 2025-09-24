#!/usr/bin/env python3
"""
Predictive Capacity Planning Agent for Multi-Agent System
Uses stochastic modeling to predict infrastructure capacity needs and scaling requirements
"""

import asyncio
import json
import logging
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import uuid
import math
import statistics

# Import communication layer
from redis_communication import RedisCommunicator, RedisConfig, MessageType

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CapacityMetricType(Enum):
    CPU_UTILIZATION = "cpu_utilization"
    MEMORY_UTILIZATION = "memory_utilization"
    DISK_UTILIZATION = "disk_utilization"
    NETWORK_THROUGHPUT = "network_throughput"
    REQUEST_RATE = "request_rate"
    RESPONSE_TIME = "response_time"
    CONNECTION_COUNT = "connection_count"
    QUEUE_LENGTH = "queue_length"

class PredictionModel(Enum):
    LINEAR_REGRESSION = "linear_regression"
    EXPONENTIAL_SMOOTHING = "exponential_smoothing"
    ARIMA = "arima"
    GEOMETRIC_BROWNIAN_MOTION = "gbm"
    MEAN_REVERSION = "mean_reversion"

class ScalingRecommendation(Enum):
    SCALE_UP = "scale_up"
    SCALE_DOWN = "scale_down"
    SCALE_OUT = "scale_out"
    SCALE_IN = "scale_in"
    MAINTAIN = "maintain"
    OPTIMIZE_CONFIG = "optimize_config"

@dataclass
class CapacityMetric:
    metric_type: CapacityMetricType
    value: float
    timestamp: datetime
    source: str  # service, container, or resource name
    confidence: float = 1.0  # 0-1 confidence in the measurement

@dataclass
class CapacityPrediction:
    metric_type: CapacityMetricType
    source: str
    predicted_value: float
    prediction_time: datetime
    confidence_interval: Tuple[float, float]
    model_used: PredictionModel
    accuracy_score: float
    time_horizon_hours: int

@dataclass
class ScalingAction:
    recommendation: ScalingRecommendation
    resource: str
    priority: str  # low, medium, high, critical
    estimated_impact: str
    cost_estimate: float
    timeline: str
    reasoning: str
    prerequisites: List[str] = field(default_factory=list)

class PredictiveCapacityAgent:
    """Agent for predictive capacity planning using stochastic modeling"""

    def __init__(self, redis_config: RedisConfig = None):
        self.agent_id = f"capacity-predictor-{uuid.uuid4().hex[:8]}"
        self.redis_config = redis_config or RedisConfig()
        self.communicator = None
        self.running = False

        # Prediction configuration
        self.prediction_interval = 300  # 5 minutes
        self.data_collection_interval = 60  # 1 minute
        self.prediction_horizons = [1, 6, 24, 72, 168]  # hours: 1h, 6h, 1d, 3d, 1w

        # Historical data storage
        self.capacity_metrics: Dict[str, List[CapacityMetric]] = {}
        self.predictions: Dict[str, List[CapacityPrediction]] = {}
        self.scaling_actions: List[ScalingAction] = []

        # Model parameters
        self.model_parameters = {
            PredictionModel.GEOMETRIC_BROWNIAN_MOTION: {
                'drift': 0.05,  # Expected growth rate
                'volatility': 0.2,  # Volatility factor
                'time_step': 1/24  # 1 hour
            },
            PredictionModel.MEAN_REVERSION: {
                'mean_reversion_speed': 0.1,
                'long_term_mean': 50.0,  # 50% utilization
                'volatility': 0.15
            },
            PredictionModel.EXPONENTIAL_SMOOTHING: {
                'alpha': 0.3,  # Level smoothing
                'beta': 0.1,   # Trend smoothing
                'gamma': 0.05  # Seasonal smoothing
            }
        }

        # Capacity thresholds
        self.thresholds = {
            'cpu_warning': 70.0,
            'cpu_critical': 85.0,
            'memory_warning': 75.0,
            'memory_critical': 90.0,
            'disk_warning': 80.0,
            'disk_critical': 95.0,
            'response_time_warning': 2000.0,  # ms
            'response_time_critical': 5000.0  # ms
        }

        logger.info("Predictive Capacity Agent initialized")

    async def start(self):
        """Start the predictive capacity agent"""
        try:
            logger.info("Starting Predictive Capacity Agent")

            # Initialize Redis communication
            self.communicator = RedisCommunicator(self.redis_config, self.agent_id)
            await self.communicator.connect()

            # Subscribe to relevant channels
            await self.communicator.subscribe_to_channels([
                'agent:broadcast',
                f'agent:{self.agent_id}',
                'agent_type:capacity'
            ])

            # Register message handlers
            self.communicator.register_handler(MessageType.TASK_ASSIGNMENT, self.handle_task_assignment)
            self.communicator.register_handler(MessageType.PROJECT_UPDATE, self.handle_project_update)

            self.running = True

            # Start monitoring and prediction tasks
            asyncio.create_task(self.data_collection_loop())
            asyncio.create_task(self.prediction_loop())
            asyncio.create_task(self.scaling_analysis_loop())

            logger.info("Predictive Capacity Agent started successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to start Predictive Capacity Agent: {e}")
            return False

    async def stop(self):
        """Stop the predictive capacity agent"""
        logger.info("Stopping Predictive Capacity Agent")
        self.running = False

        if self.communicator:
            await self.communicator.disconnect()

    async def handle_task_assignment(self, message):
        """Handle task assignment messages"""
        payload = message.get('payload', {})
        task_type = payload.get('task_type')

        logger.info(f"Received task assignment: {task_type}")

        if task_type == 'predict_capacity':
            resource = payload.get('resource', 'system')
            horizon = payload.get('time_horizon_hours', 24)
            await self.generate_capacity_prediction(resource, horizon)

        elif task_type == 'analyze_scaling_needs':
            await self.analyze_scaling_requirements()

        elif task_type == 'forecast_demand':
            service = payload.get('service')
            await self.forecast_service_demand(service)

    async def handle_project_update(self, message):
        """Handle project update messages"""
        payload = message.get('payload', {})
        logger.info(f"Capacity agent received project update: {payload.get('update_type', 'unknown')}")

        # Update capacity planning based on project changes
        if payload.get('update_type') == 'deployment':
            await self.adjust_capacity_planning_for_deployment(payload)

    async def data_collection_loop(self):
        """Main loop for collecting capacity metrics"""
        while self.running:
            try:
                await self.collect_capacity_metrics()
                await asyncio.sleep(self.data_collection_interval)
            except Exception as e:
                logger.error(f"Data collection error: {e}")
                await asyncio.sleep(self.data_collection_interval)

    async def prediction_loop(self):
        """Main loop for generating capacity predictions"""
        while self.running:
            try:
                await self.generate_all_predictions()
                await asyncio.sleep(self.prediction_interval)
            except Exception as e:
                logger.error(f"Prediction error: {e}")
                await asyncio.sleep(self.prediction_interval)

    async def scaling_analysis_loop(self):
        """Main loop for scaling analysis"""
        while self.running:
            try:
                await self.analyze_scaling_requirements()
                await asyncio.sleep(600)  # Every 10 minutes
            except Exception as e:
                logger.error(f"Scaling analysis error: {e}")
                await asyncio.sleep(600)

    async def collect_capacity_metrics(self):
        """Collect capacity metrics from various sources"""
        timestamp = datetime.now()

        # Simulate capacity metrics collection
        # In a real implementation, this would integrate with monitoring systems
        simulated_sources = [
            'api-server',
            'database',
            'redis-cache',
            'file-server',
            'load-balancer'
        ]

        for source in simulated_sources:
            # Simulate realistic capacity metrics with some variance
            base_cpu = 45 + (hash(source + str(timestamp.hour)) % 30)
            base_memory = 60 + (hash(source + str(timestamp.minute)) % 25)

            # Add some realistic patterns
            cpu_utilization = base_cpu + 10 * math.sin(timestamp.hour * math.pi / 12)
            memory_utilization = base_memory + 5 * math.cos(timestamp.hour * math.pi / 8)

            # Add random variance
            cpu_utilization += np.random.normal(0, 5)
            memory_utilization += np.random.normal(0, 3)

            # Ensure valid ranges
            cpu_utilization = max(0, min(100, cpu_utilization))
            memory_utilization = max(0, min(100, memory_utilization))

            # Create capacity metrics
            cpu_metric = CapacityMetric(
                metric_type=CapacityMetricType.CPU_UTILIZATION,
                value=cpu_utilization,
                timestamp=timestamp,
                source=source,
                confidence=0.95
            )

            memory_metric = CapacityMetric(
                metric_type=CapacityMetricType.MEMORY_UTILIZATION,
                value=memory_utilization,
                timestamp=timestamp,
                source=source,
                confidence=0.95
            )

            # Store metrics
            source_key = f"{source}_{CapacityMetricType.CPU_UTILIZATION.value}"
            if source_key not in self.capacity_metrics:
                self.capacity_metrics[source_key] = []
            self.capacity_metrics[source_key].append(cpu_metric)

            source_key = f"{source}_{CapacityMetricType.MEMORY_UTILIZATION.value}"
            if source_key not in self.capacity_metrics:
                self.capacity_metrics[source_key] = []
            self.capacity_metrics[source_key].append(memory_metric)

        # Keep only last 1000 metrics per source
        for key in self.capacity_metrics:
            if len(self.capacity_metrics[key]) > 1000:
                self.capacity_metrics[key] = self.capacity_metrics[key][-1000:]

        logger.debug(f"Collected capacity metrics for {len(simulated_sources)} sources")

    async def generate_all_predictions(self):
        """Generate predictions for all monitored resources"""
        for source_key, metrics in self.capacity_metrics.items():
            if len(metrics) >= 10:  # Need at least 10 data points
                for horizon in self.prediction_horizons:
                    await self.generate_prediction_for_metric(source_key, metrics, horizon)

    async def generate_prediction_for_metric(self, source_key: str, metrics: List[CapacityMetric],
                                           time_horizon_hours: int):
        """Generate prediction for a specific metric"""
        if len(metrics) < 5:
            return

        # Extract values and timestamps
        values = [m.value for m in metrics[-50:]]  # Use last 50 points
        timestamps = [m.timestamp for m in metrics[-50:]]

        # Choose prediction model based on data characteristics
        model = self.choose_prediction_model(values)

        # Generate prediction
        predicted_value, confidence_interval = await self.apply_prediction_model(
            values, model, time_horizon_hours
        )

        # Calculate accuracy based on recent predictions
        accuracy = await self.calculate_model_accuracy(source_key, model)

        # Create prediction
        prediction = CapacityPrediction(
            metric_type=metrics[0].metric_type,
            source=metrics[0].source,
            predicted_value=predicted_value,
            prediction_time=datetime.now() + timedelta(hours=time_horizon_hours),
            confidence_interval=confidence_interval,
            model_used=model,
            accuracy_score=accuracy,
            time_horizon_hours=time_horizon_hours
        )

        # Store prediction
        pred_key = f"{source_key}_{time_horizon_hours}h"
        if pred_key not in self.predictions:
            self.predictions[pred_key] = []
        self.predictions[pred_key].append(prediction)

        # Keep only last 100 predictions per key
        if len(self.predictions[pred_key]) > 100:
            self.predictions[pred_key] = self.predictions[pred_key][-100:]

    def choose_prediction_model(self, values: List[float]) -> PredictionModel:
        """Choose the best prediction model based on data characteristics"""
        if len(values) < 5:
            return PredictionModel.LINEAR_REGRESSION

        # Calculate data characteristics
        mean_val = statistics.mean(values)
        std_val = statistics.stdev(values) if len(values) > 1 else 0

        # Calculate trend
        x = list(range(len(values)))
        if len(values) > 2:
            correlation = np.corrcoef(x, values)[0, 1] if not np.isnan(np.corrcoef(x, values)[0, 1]) else 0
        else:
            correlation = 0

        # Choose model based on characteristics
        if abs(correlation) > 0.7:  # Strong trend
            return PredictionModel.LINEAR_REGRESSION
        elif std_val / mean_val > 0.3:  # High volatility
            return PredictionModel.GEOMETRIC_BROWNIAN_MOTION
        elif mean_val > 20 and mean_val < 80:  # Bounded values
            return PredictionModel.MEAN_REVERSION
        else:
            return PredictionModel.EXPONENTIAL_SMOOTHING

    async def apply_prediction_model(self, values: List[float], model: PredictionModel,
                                   time_horizon_hours: int) -> Tuple[float, Tuple[float, float]]:
        """Apply the selected prediction model"""
        try:
            if model == PredictionModel.LINEAR_REGRESSION:
                return await self.linear_regression_prediction(values, time_horizon_hours)

            elif model == PredictionModel.GEOMETRIC_BROWNIAN_MOTION:
                return await self.gbm_prediction(values, time_horizon_hours)

            elif model == PredictionModel.MEAN_REVERSION:
                return await self.mean_reversion_prediction(values, time_horizon_hours)

            elif model == PredictionModel.EXPONENTIAL_SMOOTHING:
                return await self.exponential_smoothing_prediction(values, time_horizon_hours)

            else:
                # Fallback to simple average
                avg = statistics.mean(values[-5:])
                return avg, (avg * 0.9, avg * 1.1)

        except Exception as e:
            logger.warning(f"Prediction model {model} failed: {e}, using fallback")
            avg = statistics.mean(values[-5:])
            return avg, (avg * 0.9, avg * 1.1)

    async def linear_regression_prediction(self, values: List[float],
                                         time_horizon_hours: int) -> Tuple[float, Tuple[float, float]]:
        """Simple linear regression prediction"""
        n = len(values)
        x = np.array(range(n))
        y = np.array(values)

        # Calculate slope and intercept
        x_mean, y_mean = np.mean(x), np.mean(y)
        slope = np.sum((x - x_mean) * (y - y_mean)) / np.sum((x - x_mean) ** 2)
        intercept = y_mean - slope * x_mean

        # Predict future value
        future_x = n + time_horizon_hours
        predicted_value = slope * future_x + intercept

        # Estimate confidence interval
        residuals = y - (slope * x + intercept)
        std_error = np.std(residuals)
        confidence_interval = (
            predicted_value - 2 * std_error,
            predicted_value + 2 * std_error
        )

        return float(predicted_value), confidence_interval

    async def gbm_prediction(self, values: List[float],
                           time_horizon_hours: int) -> Tuple[float, Tuple[float, float]]:
        """Geometric Brownian Motion prediction"""
        params = self.model_parameters[PredictionModel.GEOMETRIC_BROWNIAN_MOTION]

        current_value = values[-1]
        dt = params['time_step'] * time_horizon_hours
        drift = params['drift']
        volatility = params['volatility']

        # GBM formula: S(t) = S(0) * exp((μ - σ²/2) * t + σ * W(t))
        drift_term = (drift - 0.5 * volatility**2) * dt
        random_term = volatility * np.sqrt(dt) * np.random.normal(0, 1)

        predicted_value = current_value * np.exp(drift_term + random_term)

        # Confidence interval using volatility
        lower_bound = current_value * np.exp(drift_term - 2 * volatility * np.sqrt(dt))
        upper_bound = current_value * np.exp(drift_term + 2 * volatility * np.sqrt(dt))

        return float(predicted_value), (float(lower_bound), float(upper_bound))

    async def mean_reversion_prediction(self, values: List[float],
                                      time_horizon_hours: int) -> Tuple[float, Tuple[float, float]]:
        """Mean reversion prediction (Ornstein-Uhlenbeck process)"""
        params = self.model_parameters[PredictionModel.MEAN_REVERSION]

        current_value = values[-1]
        long_term_mean = params['long_term_mean']
        speed = params['mean_reversion_speed']
        volatility = params['volatility']

        dt = time_horizon_hours / 24.0  # Convert to days

        # Mean reversion formula
        predicted_value = long_term_mean + (current_value - long_term_mean) * np.exp(-speed * dt)

        # Confidence interval
        variance = (volatility**2 / (2 * speed)) * (1 - np.exp(-2 * speed * dt))
        std_dev = np.sqrt(variance)

        confidence_interval = (
            predicted_value - 2 * std_dev,
            predicted_value + 2 * std_dev
        )

        return float(predicted_value), confidence_interval

    async def exponential_smoothing_prediction(self, values: List[float],
                                             time_horizon_hours: int) -> Tuple[float, Tuple[float, float]]:
        """Exponential smoothing prediction"""
        params = self.model_parameters[PredictionModel.EXPONENTIAL_SMOOTHING]
        alpha = params['alpha']

        # Simple exponential smoothing
        smoothed_values = [values[0]]
        for i in range(1, len(values)):
            smoothed = alpha * values[i] + (1 - alpha) * smoothed_values[i-1]
            smoothed_values.append(smoothed)

        predicted_value = smoothed_values[-1]

        # Estimate error and confidence interval
        errors = [abs(values[i] - smoothed_values[i]) for i in range(len(values))]
        avg_error = statistics.mean(errors) if errors else 0

        confidence_interval = (
            predicted_value - 2 * avg_error,
            predicted_value + 2 * avg_error
        )

        return float(predicted_value), confidence_interval

    async def calculate_model_accuracy(self, source_key: str, model: PredictionModel) -> float:
        """Calculate accuracy of a prediction model for a specific metric"""
        # This would compare recent predictions with actual values
        # For now, return a simulated accuracy score
        base_accuracy = {
            PredictionModel.LINEAR_REGRESSION: 0.75,
            PredictionModel.GEOMETRIC_BROWNIAN_MOTION: 0.70,
            PredictionModel.MEAN_REVERSION: 0.80,
            PredictionModel.EXPONENTIAL_SMOOTHING: 0.78
        }.get(model, 0.70)

        # Add some variance
        return max(0.5, min(0.95, base_accuracy + np.random.normal(0, 0.05)))

    async def analyze_scaling_requirements(self):
        """Analyze current and predicted capacity to generate scaling recommendations"""
        scaling_actions = []

        for source_key, predictions in self.predictions.items():
            if not predictions:
                continue

            latest_prediction = predictions[-1]

            # Analyze CPU utilization predictions
            if latest_prediction.metric_type == CapacityMetricType.CPU_UTILIZATION:
                actions = await self.analyze_cpu_scaling(latest_prediction)
                scaling_actions.extend(actions)

            # Analyze memory utilization predictions
            elif latest_prediction.metric_type == CapacityMetricType.MEMORY_UTILIZATION:
                actions = await self.analyze_memory_scaling(latest_prediction)
                scaling_actions.extend(actions)

        # Store scaling actions
        self.scaling_actions.extend(scaling_actions)

        # Keep only last 50 actions
        if len(self.scaling_actions) > 50:
            self.scaling_actions = self.scaling_actions[-50:]

        logger.info(f"Generated {len(scaling_actions)} scaling recommendations")

    async def analyze_cpu_scaling(self, prediction: CapacityPrediction) -> List[ScalingAction]:
        """Analyze CPU utilization and generate scaling recommendations"""
        actions = []

        predicted_cpu = prediction.predicted_value
        upper_bound = prediction.confidence_interval[1]

        if upper_bound > self.thresholds['cpu_critical']:
            actions.append(ScalingAction(
                recommendation=ScalingRecommendation.SCALE_UP,
                resource=prediction.source,
                priority="critical",
                estimated_impact=f"Prevent CPU bottleneck (predicted: {predicted_cpu:.1f}%)",
                cost_estimate=500.0,  # Monthly cost increase
                timeline="immediate",
                reasoning=f"CPU utilization predicted to reach {predicted_cpu:.1f}% with upper bound {upper_bound:.1f}%",
                prerequisites=["capacity_approval", "maintenance_window"]
            ))

        elif upper_bound > self.thresholds['cpu_warning']:
            actions.append(ScalingAction(
                recommendation=ScalingRecommendation.SCALE_OUT,
                resource=prediction.source,
                priority="high",
                estimated_impact=f"Distribute load (predicted: {predicted_cpu:.1f}%)",
                cost_estimate=300.0,
                timeline="within_24h",
                reasoning=f"CPU utilization approaching warning threshold",
                prerequisites=["load_balancer_config"]
            ))

        elif predicted_cpu < 30:  # Under-utilized
            actions.append(ScalingAction(
                recommendation=ScalingRecommendation.SCALE_DOWN,
                resource=prediction.source,
                priority="low",
                estimated_impact=f"Reduce resource costs (predicted: {predicted_cpu:.1f}%)",
                cost_estimate=-200.0,  # Cost savings
                timeline="within_week",
                reasoning=f"CPU utilization consistently low",
                prerequisites=["performance_testing"]
            ))

        return actions

    async def analyze_memory_scaling(self, prediction: CapacityPrediction) -> List[ScalingAction]:
        """Analyze memory utilization and generate scaling recommendations"""
        actions = []

        predicted_memory = prediction.predicted_value
        upper_bound = prediction.confidence_interval[1]

        if upper_bound > self.thresholds['memory_critical']:
            actions.append(ScalingAction(
                recommendation=ScalingRecommendation.SCALE_UP,
                resource=prediction.source,
                priority="critical",
                estimated_impact=f"Prevent memory exhaustion (predicted: {predicted_memory:.1f}%)",
                cost_estimate=400.0,
                timeline="immediate",
                reasoning=f"Memory utilization predicted to reach critical levels",
                prerequisites=["capacity_approval"]
            ))

        elif upper_bound > self.thresholds['memory_warning']:
            actions.append(ScalingAction(
                recommendation=ScalingRecommendation.OPTIMIZE_CONFIG,
                resource=prediction.source,
                priority="medium",
                estimated_impact=f"Optimize memory usage (predicted: {predicted_memory:.1f}%)",
                cost_estimate=0.0,
                timeline="within_48h",
                reasoning=f"Memory utilization approaching warning threshold",
                prerequisites=["memory_profiling"]
            ))

        return actions

    async def generate_capacity_prediction(self, resource: str, time_horizon_hours: int):
        """Generate capacity prediction for a specific resource"""
        logger.info(f"Generating capacity prediction for {resource} ({time_horizon_hours}h horizon)")

        # Find relevant metrics for the resource
        relevant_metrics = {}
        for key, metrics in self.capacity_metrics.items():
            if resource in key or resource == 'system':
                if metrics:
                    relevant_metrics[key] = metrics

        if not relevant_metrics:
            logger.warning(f"No metrics found for resource: {resource}")
            return

        predictions = {}
        for key, metrics in relevant_metrics.items():
            if len(metrics) >= 5:
                model = self.choose_prediction_model([m.value for m in metrics[-20:]])
                predicted_value, confidence_interval = await self.apply_prediction_model(
                    [m.value for m in metrics[-20:]], model, time_horizon_hours
                )

                predictions[key] = {
                    'predicted_value': predicted_value,
                    'confidence_interval': confidence_interval,
                    'model_used': model.value,
                    'metric_type': metrics[0].metric_type.value
                }

        # Send prediction results via Redis
        if self.communicator:
            await self.communicator.send_message(
                MessageType.TASK_COMPLETE,
                'director-agent',
                {
                    'task_type': 'capacity_prediction',
                    'agent_id': self.agent_id,
                    'resource': resource,
                    'time_horizon_hours': time_horizon_hours,
                    'predictions': predictions,
                    'timestamp': datetime.now().isoformat()
                }
            )

    async def forecast_service_demand(self, service: str):
        """Forecast demand for a specific service"""
        logger.info(f"Forecasting demand for service: {service}")

        # This would integrate with service-specific metrics
        # For now, provide a simulated forecast
        forecast = {
            'service': service,
            'forecast_period': '7_days',
            'demand_predictions': [
                {'day': 1, 'predicted_load': 75.2, 'confidence': 0.85},
                {'day': 2, 'predicted_load': 68.1, 'confidence': 0.82},
                {'day': 3, 'predicted_load': 89.7, 'confidence': 0.78},
                {'day': 7, 'predicted_load': 95.3, 'confidence': 0.70}
            ],
            'peak_periods': [
                {'start': '09:00', 'end': '11:00', 'expected_load': 90},
                {'start': '14:00', 'end': '16:00', 'expected_load': 85}
            ],
            'scaling_recommendations': [
                'Consider auto-scaling during peak periods',
                'Pre-warm instances before 09:00',
                'Monitor cache hit ratios during high load'
            ]
        }

        if self.communicator:
            await self.communicator.send_message(
                MessageType.TASK_COMPLETE,
                'director-agent',
                {
                    'task_type': 'service_demand_forecast',
                    'agent_id': self.agent_id,
                    'forecast': forecast,
                    'timestamp': datetime.now().isoformat()
                }
            )

    async def adjust_capacity_planning_for_deployment(self, deployment_info: Dict[str, Any]):
        """Adjust capacity planning based on deployment information"""
        logger.info(f"Adjusting capacity planning for deployment: {deployment_info.get('service', 'unknown')}")

        # This would adjust predictions based on expected deployment impact
        adjustment = {
            'deployment_service': deployment_info.get('service'),
            'expected_impact': 'increased_load',
            'capacity_adjustments': [
                'Increased CPU requirements by 20%',
                'Additional memory allocation needed',
                'Network bandwidth may spike during deployment'
            ],
            'monitoring_priorities': [
                'Watch deployment metrics closely',
                'Monitor rollback triggers',
                'Track performance degradation'
            ]
        }

        logger.info(f"Capacity planning adjusted: {adjustment}")

    async def get_prediction_status(self) -> Dict[str, Any]:
        """Get current prediction status and statistics"""
        current_time = datetime.now()

        # Calculate statistics
        total_metrics = sum(len(metrics) for metrics in self.capacity_metrics.values())
        total_predictions = sum(len(preds) for preds in self.predictions.values())

        # Get recent predictions accuracy
        recent_predictions = []
        for preds in self.predictions.values():
            recent_predictions.extend(preds[-5:])  # Last 5 per metric

        avg_accuracy = (
            statistics.mean(p.accuracy_score for p in recent_predictions)
            if recent_predictions else 0.0
        )

        # Count scaling actions by priority
        scaling_by_priority = {}
        for action in self.scaling_actions:
            priority = action.priority
            scaling_by_priority[priority] = scaling_by_priority.get(priority, 0) + 1

        status = {
            'agent_id': self.agent_id,
            'status': 'running' if self.running else 'stopped',
            'timestamp': current_time.isoformat(),

            'metrics_summary': {
                'total_metrics_collected': total_metrics,
                'monitored_sources': len(self.capacity_metrics),
                'data_collection_interval_seconds': self.data_collection_interval
            },

            'prediction_summary': {
                'total_predictions_generated': total_predictions,
                'prediction_horizons_hours': self.prediction_horizons,
                'average_accuracy': round(avg_accuracy, 3),
                'prediction_interval_seconds': self.prediction_interval
            },

            'scaling_summary': {
                'total_scaling_actions': len(self.scaling_actions),
                'actions_by_priority': scaling_by_priority,
                'thresholds': self.thresholds
            },

            'model_configuration': {
                'available_models': [model.value for model in PredictionModel],
                'model_parameters': {
                    model.value: params for model, params in self.model_parameters.items()
                }
            }
        }

        return status

# Test and example usage
async def test_predictive_capacity_agent():
    """Test the predictive capacity agent"""

    redis_config = RedisConfig(
        host='localhost',
        port=6380,  # Using catalytic-redis port
        db=0
    )

    agent = PredictiveCapacityAgent(redis_config)

    # Start the agent
    started = await agent.start()
    if not started:
        print("Failed to start Predictive Capacity Agent")
        return False

    print("Predictive Capacity Agent started")

    # Wait for some data collection and prediction cycles
    print("Running capacity monitoring and prediction for 20 seconds...")
    await asyncio.sleep(20)

    # Get prediction status
    try:
        status = await agent.get_prediction_status()
        print("Prediction Status:")
        print(f"  - Agent ID: {status.get('agent_id', 'N/A')}")
        print(f"  - Status: {status.get('status', 'N/A')}")
        print(f"  - Metrics collected: {status.get('metrics_summary', {}).get('total_metrics_collected', 0)}")
        print(f"  - Predictions generated: {status.get('prediction_summary', {}).get('total_predictions_generated', 0)}")
        print(f"  - Average accuracy: {status.get('prediction_summary', {}).get('average_accuracy', 0)}")
        print(f"  - Scaling actions: {status.get('scaling_summary', {}).get('total_scaling_actions', 0)}")
    except Exception as e:
        print(f"Error getting status: {e}")

    await agent.stop()
    print("Predictive Capacity Agent stopped")
    return True

if __name__ == "__main__":
    asyncio.run(test_predictive_capacity_agent())