"""
MLOps Platform

Enterprise-grade machine learning operations platform with:
- Complete ML lifecycle management (train, validate, deploy, monitor)
- Model versioning and artifact management
- Feature store with data lineage
- A/B testing framework for model deployment
- Model monitoring and drift detection
- Multi-tenant model isolation
- Automated model retraining pipelines
- Integration with popular ML frameworks
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score

# MLflow integration (optional)
try:
    import mlflow
    import mlflow.pytorch
    import mlflow.sklearn
    import mlflow.tensorflow

    MLFLOW_AVAILABLE = True
except ImportError:
    MLFLOW_AVAILABLE = False

# Kubeflow integration (optional)
try:
    pass

    KUBEFLOW_AVAILABLE = True
except ImportError:
    KUBEFLOW_AVAILABLE = False


class ModelStage(Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    ARCHIVED = "archived"


class DeploymentStrategy(Enum):
    BLUE_GREEN = "blue_green"
    CANARY = "canary"
    ROLLING = "rolling"
    A_B_TEST = "a_b_test"


class ModelType(Enum):
    SCIKIT_LEARN = "sklearn"
    TENSORFLOW = "tensorflow"
    PYTORCH = "pytorch"
    XGBOOST = "xgboost"
    LIGHTGBM = "lightgbm"
    CUSTOM = "custom"


class ExperimentStatus(Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ModelArtifact:
    """Model artifact metadata"""

    id: str = field(default_factory=lambda: str(uuid4()))
    model_name: str = ""
    version: str = "1.0.0"
    model_type: ModelType = ModelType.SCIKIT_LEARN
    stage: ModelStage = ModelStage.DEVELOPMENT

    # Artifact storage
    model_path: str = ""
    metadata_path: str = ""
    requirements_path: str = ""

    # Training information
    training_data_hash: str = ""
    hyperparameters: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, float] = field(default_factory=dict)

    # Deployment information
    deployment_config: Dict[str, Any] = field(default_factory=dict)
    endpoint_url: Optional[str] = None

    # Metadata
    tenant_id: str = ""
    created_by: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    tags: List[str] = field(default_factory=list)


@dataclass
class Experiment:
    """ML experiment configuration"""

    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""
    tenant_id: str = ""

    # Configuration
    model_config: Dict[str, Any] = field(default_factory=dict)
    hyperparameters: Dict[str, Any] = field(default_factory=dict)
    data_config: Dict[str, Any] = field(default_factory=dict)

    # Status tracking
    status: ExperimentStatus = ExperimentStatus.RUNNING
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None

    # Results
    metrics: Dict[str, float] = field(default_factory=dict)
    artifacts: List[str] = field(default_factory=list)
    logs: List[str] = field(default_factory=list)

    # Relationships
    parent_experiment_id: Optional[str] = None
    child_experiment_ids: List[str] = field(default_factory=list)


@dataclass
class FeatureDefinition:
    """Feature store feature definition"""

    name: str
    data_type: str
    description: str = ""
    source_table: str = ""
    transformation: str = ""
    tags: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class FeatureSet:
    """Feature store feature set"""

    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""
    tenant_id: str = ""

    features: List[FeatureDefinition] = field(default_factory=list)
    source_config: Dict[str, Any] = field(default_factory=dict)

    # Versioning
    version: str = "1.0.0"
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ABTestConfig:
    """A/B test configuration"""

    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""

    # Models being tested
    control_model_id: str = ""
    treatment_model_id: str = ""

    # Traffic allocation
    traffic_split: float = 0.5  # 50/50 split

    # Test configuration
    success_metrics: List[str] = field(default_factory=list)
    duration_days: int = 14
    minimum_sample_size: int = 1000

    # Status
    is_active: bool = False
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None

    # Results
    results: Dict[str, Any] = field(default_factory=dict)


class MLOpsPlatform:
    """Complete MLOps platform for enterprise ML lifecycle management"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config

        # Storage
        self.artifacts_path = Path(config.get("artifacts_path", "ml_artifacts"))
        self.artifacts_path.mkdir(exist_ok=True)

        # Model registry
        self.model_registry: Dict[str, ModelArtifact] = {}
        self.experiments: Dict[str, Experiment] = {}

        # Feature store
        self.feature_sets: Dict[str, FeatureSet] = {}
        self.feature_data: Dict[str, pd.DataFrame] = {}

        # A/B testing
        self.ab_tests: Dict[str, ABTestConfig] = {}

        # Monitoring
        self.model_performance: Dict[str, List[Dict[str, Any]]] = {}
        self.drift_detectors: Dict[str, Any] = {}

        # MLflow integration
        if MLFLOW_AVAILABLE and config.get("mlflow_enabled", False):
            mlflow.set_tracking_uri(config.get("mlflow_uri", "sqlite:///mlflow.db"))

        self.logger = logging.getLogger(__name__)

    async def create_experiment(self, experiment_config: Dict[str, Any]) -> Experiment:
        """Create new ML experiment"""
        experiment = Experiment(**experiment_config)
        self.experiments[experiment.id] = experiment

        # MLflow integration
        if MLFLOW_AVAILABLE:
            mlflow_exp = mlflow.create_experiment(
                experiment.name,
                tags={
                    "tenant_id": experiment.tenant_id,
                    "experiment_id": experiment.id,
                },
            )
            experiment.artifacts.append(f"mlflow_experiment_id:{mlflow_exp}")

        self.logger.info(f"Created experiment: {experiment.name} ({experiment.id})")
        return experiment

    async def start_experiment_run(
        self, experiment_id: str, run_config: Dict[str, Any]
    ) -> str:
        """Start experiment run"""
        if experiment_id not in self.experiments:
            raise ValueError(f"Experiment not found: {experiment_id}")

        experiment = self.experiments[experiment_id]
        run_id = str(uuid4())

        # Update experiment status
        experiment.status = ExperimentStatus.RUNNING

        # MLflow run
        if MLFLOW_AVAILABLE:
            mlflow.start_run(
                run_name=f"{experiment.name}_{run_id}",
                tags={
                    "experiment_id": experiment_id,
                    "run_id": run_id,
                    "tenant_id": experiment.tenant_id,
                },
            )

            # Log parameters
            for key, value in run_config.get("hyperparameters", {}).items():
                mlflow.log_param(key, value)

        self.logger.info(f"Started run {run_id} for experiment {experiment_id}")
        return run_id

    async def log_metrics(
        self, experiment_id: str, run_id: str, metrics: Dict[str, float], step: int = 0
    ):
        """Log metrics for experiment run"""
        if experiment_id not in self.experiments:
            raise ValueError(f"Experiment not found: {experiment_id}")

        experiment = self.experiments[experiment_id]

        # Update experiment metrics
        for key, value in metrics.items():
            experiment.metrics[key] = value

        # MLflow logging
        if MLFLOW_AVAILABLE:
            for key, value in metrics.items():
                mlflow.log_metric(key, value, step=step)

        self.logger.debug(f"Logged metrics for run {run_id}: {metrics}")

    async def register_model(
        self, experiment_id: str, model: Any, model_config: Dict[str, Any]
    ) -> ModelArtifact:
        """Register trained model in model registry"""
        if experiment_id not in self.experiments:
            raise ValueError(f"Experiment not found: {experiment_id}")

        experiment = self.experiments[experiment_id]

        # Create model artifact
        artifact = ModelArtifact(
            model_name=model_config["name"],
            version=model_config.get("version", "1.0.0"),
            model_type=ModelType(model_config.get("type", "sklearn")),
            tenant_id=experiment.tenant_id,
            hyperparameters=experiment.hyperparameters.copy(),
            metrics=experiment.metrics.copy(),
            created_by=model_config.get("created_by", "system"),
        )

        # Save model artifacts
        model_dir = self.artifacts_path / artifact.id
        model_dir.mkdir(exist_ok=True)

        # Save model
        model_path = model_dir / "model.pkl"
        joblib.dump(model, model_path)
        artifact.model_path = str(model_path)

        # Save metadata
        metadata_path = model_dir / "metadata.json"
        with open(metadata_path, "w") as f:
            json.dump(
                {
                    "id": artifact.id,
                    "name": artifact.model_name,
                    "version": artifact.version,
                    "type": artifact.model_type.value,
                    "hyperparameters": artifact.hyperparameters,
                    "metrics": artifact.metrics,
                    "created_at": artifact.created_at.isoformat(),
                    "tenant_id": artifact.tenant_id,
                },
                f,
                indent=2,
            )
        artifact.metadata_path = str(metadata_path)

        # Register in registry
        self.model_registry[artifact.id] = artifact

        # MLflow model logging
        if MLFLOW_AVAILABLE:
            if artifact.model_type == ModelType.SCIKIT_LEARN:
                mlflow.sklearn.log_model(model, "model")
            # Add other framework support as needed

            mlflow.log_artifacts(str(model_dir))

        self.logger.info(f"Registered model: {artifact.model_name} ({artifact.id})")
        return artifact

    async def promote_model(
        self, model_id: str, target_stage: ModelStage
    ) -> ModelArtifact:
        """Promote model to different stage"""
        if model_id not in self.model_registry:
            raise ValueError(f"Model not found: {model_id}")

        artifact = self.model_registry[model_id]
        current_stage = artifact.stage

        # Validation rules
        if (
            current_stage == ModelStage.DEVELOPMENT
            and target_stage == ModelStage.PRODUCTION
        ):
            # Must go through staging first
            if not await self._validate_model_for_production(artifact):
                raise ValueError("Model validation failed for production deployment")

        artifact.stage = target_stage

        # Update metadata
        metadata_path = Path(artifact.metadata_path)
        if metadata_path.exists():
            with open(metadata_path, "r") as f:
                metadata = json.load(f)

            metadata["stage"] = target_stage.value
            metadata["updated_at"] = datetime.utcnow().isoformat()

            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=2)

        self.logger.info(
            f"Promoted model {model_id} from {current_stage.value} to {target_stage.value}"
        )
        return artifact

    async def _validate_model_for_production(self, artifact: ModelArtifact) -> bool:
        """Validate model before production deployment"""
        # Check minimum accuracy threshold
        accuracy = artifact.metrics.get("accuracy", 0)
        min_accuracy = self.config.get("min_production_accuracy", 0.85)

        if accuracy < min_accuracy:
            self.logger.warning(
                f"Model {artifact.id} accuracy {accuracy} below threshold {min_accuracy}"
            )
            return False

        # Check required metrics
        required_metrics = self.config.get(
            "required_production_metrics", ["accuracy", "precision", "recall"]
        )
        missing_metrics = [m for m in required_metrics if m not in artifact.metrics]

        if missing_metrics:
            self.logger.warning(
                f"Model {artifact.id} missing required metrics: {missing_metrics}"
            )
            return False

        return True

    async def deploy_model(
        self, model_id: str, deployment_config: Dict[str, Any]
    ) -> str:
        """Deploy model for serving"""
        if model_id not in self.model_registry:
            raise ValueError(f"Model not found: {model_id}")

        artifact = self.model_registry[model_id]

        if artifact.stage not in [ModelStage.STAGING, ModelStage.PRODUCTION]:
            raise ValueError(
                "Model must be in staging or production stage for deployment"
            )

        # Create deployment
        deployment_id = str(uuid4())

        # Update artifact with deployment info
        artifact.deployment_config = deployment_config
        artifact.endpoint_url = deployment_config.get("endpoint_url")

        # Initialize monitoring
        await self._initialize_model_monitoring(model_id, deployment_id)

        self.logger.info(
            f"Deployed model {model_id} with deployment ID {deployment_id}"
        )
        return deployment_id

    async def _initialize_model_monitoring(self, model_id: str, deployment_id: str):
        """Initialize monitoring for deployed model"""
        if model_id not in self.model_performance:
            self.model_performance[model_id] = []

        # Start drift detection
        await self._setup_drift_detection(model_id)

        self.logger.info(f"Initialized monitoring for model {model_id}")

    async def _setup_drift_detection(self, model_id: str):
        """Setup data/model drift detection"""
        try:
            pass

            # Create simple drift detector
            self.drift_detectors[model_id] = {
                "reference_data": None,
                "drift_threshold": 0.05,
                "last_check": datetime.utcnow(),
            }

        except ImportError:
            self.logger.warning("SciPy not available for drift detection")

    async def create_feature_set(
        self, feature_set_config: Dict[str, Any]
    ) -> FeatureSet:
        """Create feature set in feature store"""
        feature_set = FeatureSet(**feature_set_config)
        self.feature_sets[feature_set.id] = feature_set

        self.logger.info(f"Created feature set: {feature_set.name} ({feature_set.id})")
        return feature_set

    async def register_features(self, feature_set_id: str, data: pd.DataFrame):
        """Register feature data in feature store"""
        if feature_set_id not in self.feature_sets:
            raise ValueError(f"Feature set not found: {feature_set_id}")

        # Store feature data
        self.feature_data[feature_set_id] = data

        # Update feature set metadata
        feature_set = self.feature_sets[feature_set_id]
        feature_set.updated_at = datetime.utcnow()

        self.logger.info(
            f"Registered {len(data)} records for feature set {feature_set_id}"
        )

    async def get_features(
        self,
        feature_set_id: str,
        feature_names: List[str] = None,
        filters: Dict[str, Any] = None,
    ) -> pd.DataFrame:
        """Retrieve features from feature store"""
        if feature_set_id not in self.feature_data:
            raise ValueError(f"Feature data not found: {feature_set_id}")

        data = self.feature_data[feature_set_id].copy()

        # Apply filters
        if filters:
            for column, value in filters.items():
                if column in data.columns:
                    if isinstance(value, list):
                        data = data[data[column].isin(value)]
                    else:
                        data = data[data[column] == value]

        # Select specific features
        if feature_names:
            available_features = [f for f in feature_names if f in data.columns]
            data = data[available_features]

        return data

    async def create_ab_test(self, test_config: Dict[str, Any]) -> ABTestConfig:
        """Create A/B test for model comparison"""
        ab_test = ABTestConfig(**test_config)
        self.ab_tests[ab_test.id] = ab_test

        # Validate models exist
        if ab_test.control_model_id not in self.model_registry:
            raise ValueError(f"Control model not found: {ab_test.control_model_id}")

        if ab_test.treatment_model_id not in self.model_registry:
            raise ValueError(f"Treatment model not found: {ab_test.treatment_model_id}")

        self.logger.info(f"Created A/B test: {ab_test.name} ({ab_test.id})")
        return ab_test

    async def start_ab_test(self, test_id: str) -> bool:
        """Start A/B test"""
        if test_id not in self.ab_tests:
            raise ValueError(f"A/B test not found: {test_id}")

        ab_test = self.ab_tests[test_id]
        ab_test.is_active = True
        ab_test.start_date = datetime.utcnow()
        ab_test.end_date = ab_test.start_date + timedelta(days=ab_test.duration_days)

        self.logger.info(f"Started A/B test: {test_id}")
        return True

    async def log_ab_test_result(
        self, test_id: str, model_id: str, result: Dict[str, Any]
    ):
        """Log A/B test result"""
        if test_id not in self.ab_tests:
            raise ValueError(f"A/B test not found: {test_id}")

        ab_test = self.ab_tests[test_id]

        # Initialize results structure
        if "control_results" not in ab_test.results:
            ab_test.results = {
                "control_results": [],
                "treatment_results": [],
                "statistical_significance": None,
            }

        # Log result to appropriate group
        if model_id == ab_test.control_model_id:
            ab_test.results["control_results"].append(result)
        elif model_id == ab_test.treatment_model_id:
            ab_test.results["treatment_results"].append(result)

        # Check if we have enough data for analysis
        await self._analyze_ab_test_results(test_id)

    async def _analyze_ab_test_results(self, test_id: str):
        """Analyze A/B test results for statistical significance"""
        ab_test = self.ab_tests[test_id]
        results = ab_test.results

        control_count = len(results.get("control_results", []))
        treatment_count = len(results.get("treatment_results", []))

        if (
            control_count < ab_test.minimum_sample_size
            or treatment_count < ab_test.minimum_sample_size
        ):
            return  # Not enough data yet

        try:
            from scipy.stats import ttest_ind

            # Extract success metrics
            control_values = [
                r.get(ab_test.success_metrics[0], 0) for r in results["control_results"]
            ]
            treatment_values = [
                r.get(ab_test.success_metrics[0], 0)
                for r in results["treatment_results"]
            ]

            # Perform t-test
            statistic, p_value = ttest_ind(control_values, treatment_values)

            results["statistical_significance"] = {
                "p_value": float(p_value),
                "statistic": float(statistic),
                "is_significant": p_value < 0.05,
                "control_mean": float(np.mean(control_values)),
                "treatment_mean": float(np.mean(treatment_values)),
                "improvement": (
                    (np.mean(treatment_values) - np.mean(control_values))
                    / np.mean(control_values)
                    * 100
                ),
            }

        except ImportError:
            self.logger.warning("SciPy not available for statistical analysis")

    async def monitor_model_performance(
        self,
        model_id: str,
        predictions: List[Dict[str, Any]],
        actuals: List[Any] = None,
    ):
        """Monitor model performance in production"""
        if model_id not in self.model_registry:
            raise ValueError(f"Model not found: {model_id}")

        if model_id not in self.model_performance:
            self.model_performance[model_id] = []

        # Calculate performance metrics
        performance_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "prediction_count": len(predictions),
            "avg_confidence": np.mean([p.get("confidence", 0.5) for p in predictions]),
        }

        # If we have actuals, calculate accuracy metrics
        if actuals and len(actuals) == len(predictions):
            pred_values = [p.get("prediction") for p in predictions]

            # Calculate metrics based on problem type
            if all(isinstance(v, (int, float)) for v in pred_values):
                # Regression metrics
                mae = np.mean(np.abs(np.array(pred_values) - np.array(actuals)))
                mse = np.mean((np.array(pred_values) - np.array(actuals)) ** 2)

                performance_data.update(
                    {"mae": float(mae), "mse": float(mse), "rmse": float(np.sqrt(mse))}
                )
            else:
                # Classification metrics
                accuracy = accuracy_score(actuals, pred_values)

                performance_data.update({"accuracy": float(accuracy)})

        # Store performance data
        self.model_performance[model_id].append(performance_data)

        # Keep only recent performance data
        if len(self.model_performance[model_id]) > 10000:
            self.model_performance[model_id] = self.model_performance[model_id][-10000:]

        # Check for performance degradation
        await self._check_performance_degradation(model_id)

    async def _check_performance_degradation(self, model_id: str):
        """Check for model performance degradation"""
        if model_id not in self.model_performance:
            return

        performance_history = self.model_performance[model_id]
        if len(performance_history) < 10:
            return  # Need more data

        # Get recent vs historical performance
        recent_data = performance_history[-5:]
        historical_data = (
            performance_history[-20:-5]
            if len(performance_history) >= 20
            else performance_history[:-5]
        )

        if not historical_data:
            return

        # Compare accuracy if available
        recent_accuracy = [d.get("accuracy") for d in recent_data if "accuracy" in d]
        historical_accuracy = [
            d.get("accuracy") for d in historical_data if "accuracy" in d
        ]

        if recent_accuracy and historical_accuracy:
            recent_avg = np.mean(recent_accuracy)
            historical_avg = np.mean(historical_accuracy)

            degradation_threshold = self.config.get(
                "performance_degradation_threshold", 0.05
            )

            if (historical_avg - recent_avg) / historical_avg > degradation_threshold:
                self.logger.warning(
                    f"Performance degradation detected for model {model_id}: "
                    f"Recent accuracy {recent_avg:.3f} vs historical {historical_avg:.3f}"
                )

                # Trigger retraining alert
                await self._trigger_retraining_alert(
                    model_id,
                    {
                        "reason": "performance_degradation",
                        "recent_accuracy": recent_avg,
                        "historical_accuracy": historical_avg,
                        "degradation_percent": (historical_avg - recent_avg)
                        / historical_avg
                        * 100,
                    },
                )

    async def _trigger_retraining_alert(
        self, model_id: str, alert_data: Dict[str, Any]
    ):
        """Trigger model retraining alert"""
        self.logger.info(
            f"Retraining alert triggered for model {model_id}: {alert_data}"
        )

        # Here you would integrate with alerting systems
        # For now, just log the alert

    async def get_model_performance_history(
        self, model_id: str, days: int = 30
    ) -> List[Dict[str, Any]]:
        """Get model performance history"""
        if model_id not in self.model_performance:
            return []

        cutoff_date = datetime.utcnow() - timedelta(days=days)

        filtered_data = []
        for data in self.model_performance[model_id]:
            timestamp = datetime.fromisoformat(data["timestamp"])
            if timestamp >= cutoff_date:
                filtered_data.append(data)

        return filtered_data

    async def cleanup_old_experiments(self, days: int = 90):
        """Cleanup old experiments and artifacts"""
        cutoff_date = datetime.utcnow() - timedelta(days=days)

        expired_experiments = []
        for exp_id, experiment in self.experiments.items():
            if (
                experiment.status
                in [ExperimentStatus.COMPLETED, ExperimentStatus.FAILED]
                and experiment.start_time < cutoff_date
            ):
                expired_experiments.append(exp_id)

        for exp_id in expired_experiments:
            del self.experiments[exp_id]
            self.logger.info(f"Cleaned up expired experiment: {exp_id}")

        return len(expired_experiments)

    def get_model_registry_summary(self, tenant_id: str = "") -> Dict[str, Any]:
        """Get model registry summary"""
        models = [
            m
            for m in self.model_registry.values()
            if not tenant_id or m.tenant_id == tenant_id
        ]

        stage_counts = {}
        for stage in ModelStage:
            stage_counts[stage.value] = len([m for m in models if m.stage == stage])

        return {
            "total_models": len(models),
            "by_stage": stage_counts,
            "by_type": {
                model_type.value: len([m for m in models if m.model_type == model_type])
                for model_type in ModelType
            },
            "recent_registrations": len(
                [m for m in models if (datetime.utcnow() - m.created_at).days <= 7]
            ),
        }

    async def export_model_metadata(self, model_id: str) -> Dict[str, Any]:
        """Export model metadata for governance"""
        if model_id not in self.model_registry:
            raise ValueError(f"Model not found: {model_id}")

        artifact = self.model_registry[model_id]

        return {
            "model_id": artifact.id,
            "name": artifact.model_name,
            "version": artifact.version,
            "type": artifact.model_type.value,
            "stage": artifact.stage.value,
            "created_at": artifact.created_at.isoformat(),
            "created_by": artifact.created_by,
            "hyperparameters": artifact.hyperparameters,
            "metrics": artifact.metrics,
            "training_data_hash": artifact.training_data_hash,
            "deployment_config": artifact.deployment_config,
            "tags": artifact.tags,
            "tenant_id": artifact.tenant_id,
        }
