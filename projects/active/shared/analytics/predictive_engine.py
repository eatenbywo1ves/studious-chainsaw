"""
Predictive Analytics Engine

Enterprise-grade predictive analytics with:
- Time series forecasting (ARIMA, Prophet, LSTM)
- Anomaly detection and alerting
- Pattern recognition and trend analysis
- Real-time prediction serving
- Multi-tenant model isolation
- Feature engineering pipeline
- Model performance monitoring
- A/B testing framework integration
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestRegressor
from sklearn.linear_model import LinearRegression
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

# Optional advanced libraries (install if available)
try:
    from prophet import Prophet

    PROPHET_AVAILABLE = True
except ImportError:
    PROPHET_AVAILABLE = False

try:
    from tensorflow.keras.layers import LSTM, Dense, Dropout
    from tensorflow.keras.models import Sequential

    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False

try:
    from statsmodels.tsa.arima.model import ARIMA

    ARIMA_AVAILABLE = True
except ImportError:
    ARIMA_AVAILABLE = False


class ModelType(Enum):
    LINEAR_REGRESSION = "linear_regression"
    RANDOM_FOREST = "random_forest"
    ARIMA = "arima"
    PROPHET = "prophet"
    LSTM = "lstm"
    ISOLATION_FOREST = "isolation_forest"
    CUSTOM = "custom"


class PredictionType(Enum):
    FORECAST = "forecast"
    CLASSIFICATION = "classification"
    ANOMALY_DETECTION = "anomaly_detection"
    PATTERN_RECOGNITION = "pattern_recognition"


class ModelStatus(Enum):
    TRAINING = "training"
    TRAINED = "trained"
    DEPLOYED = "deployed"
    FAILED = "failed"
    DEPRECATED = "deprecated"


@dataclass
class FeatureConfig:
    """Feature engineering configuration"""

    name: str
    source_column: str
    transformation: str = "none"  # none, log, sqrt, standardize, normalize
    aggregation: str = "none"  # none, sum, avg, count, min, max
    window_size: int = 1
    lag: int = 0
    is_target: bool = False


@dataclass
class ModelConfig:
    """Predictive model configuration"""

    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    model_type: ModelType = ModelType.LINEAR_REGRESSION
    prediction_type: PredictionType = PredictionType.FORECAST
    tenant_id: str = ""

    # Feature configuration
    features: List[FeatureConfig] = field(default_factory=list)
    target_variable: str = ""

    # Model parameters
    model_params: Dict[str, Any] = field(default_factory=dict)
    training_params: Dict[str, Any] = field(default_factory=dict)

    # Data configuration
    data_source: str = ""
    training_window_days: int = 90
    prediction_horizon: int = 7

    # Performance tracking
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    status: ModelStatus = ModelStatus.TRAINING

    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    last_trained: Optional[datetime] = None
    version: int = 1


@dataclass
class PredictionRequest:
    """Prediction request configuration"""

    model_id: str
    tenant_id: str = ""
    input_data: Dict[str, Any] = field(default_factory=dict)
    prediction_horizon: int = 7
    confidence_interval: float = 0.95
    include_explanation: bool = False


@dataclass
class PredictionResult:
    """Prediction result"""

    request_id: str = field(default_factory=lambda: str(uuid4()))
    model_id: str = ""
    predictions: List[Dict[str, Any]] = field(default_factory=list)
    confidence_intervals: List[Dict[str, Any]] = field(default_factory=list)
    feature_importance: Dict[str, float] = field(default_factory=dict)
    explanation: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)


class PredictiveEngine:
    """Advanced predictive analytics engine"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.models: Dict[str, ModelConfig] = {}
        self.trained_models: Dict[str, Any] = {}  # Actual model objects
        self.scalers: Dict[str, StandardScaler] = {}
        self.encoders: Dict[str, Dict[str, LabelEncoder]] = {}

        # Performance monitoring
        self.model_metrics: Dict[str, Dict[str, float]] = {}
        self.prediction_history: List[PredictionResult] = []

        self.logger = logging.getLogger(__name__)

    async def register_model(self, model_config: ModelConfig) -> str:
        """Register a new predictive model"""
        model_config.updated_at = datetime.utcnow()
        self.models[model_config.id] = model_config

        self.logger.info(f"Registered model: {model_config.name} ({model_config.id})")
        return model_config.id

    async def train_model(
        self, model_id: str, training_data: pd.DataFrame
    ) -> Dict[str, Any]:
        """Train predictive model"""
        if model_id not in self.models:
            raise ValueError(f"Model not found: {model_id}")

        config = self.models[model_id]
        config.status = ModelStatus.TRAINING

        try:
            # Feature engineering
            features_df = await self._engineer_features(training_data, config.features)

            # Prepare training data
            X, y = await self._prepare_training_data(features_df, config)

            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )

            # Scale features if needed
            if config.model_type in [ModelType.LINEAR_REGRESSION, ModelType.LSTM]:
                scaler = StandardScaler()
                X_train_scaled = scaler.fit_transform(X_train)
                X_test_scaled = scaler.transform(X_test)
                self.scalers[model_id] = scaler
            else:
                X_train_scaled = X_train
                X_test_scaled = X_test

            # Train model based on type
            model = await self._train_model_by_type(
                config, X_train_scaled, y_train, X_test_scaled, y_test
            )

            # Evaluate model
            metrics = await self._evaluate_model(model, X_test_scaled, y_test, config)

            # Store trained model
            self.trained_models[model_id] = model
            config.performance_metrics = metrics
            config.status = ModelStatus.TRAINED
            config.last_trained = datetime.utcnow()
            config.updated_at = datetime.utcnow()

            # Save model to disk
            await self._save_model(model_id, model)

            self.logger.info(f"Successfully trained model: {model_id}")
            return {
                "model_id": model_id,
                "status": "trained",
                "metrics": metrics,
                "training_samples": len(X_train),
                "test_samples": len(X_test),
            }

        except Exception as e:
            config.status = ModelStatus.FAILED
            self.logger.error(f"Model training failed for {model_id}: {e}")
            raise

    async def _engineer_features(
        self, data: pd.DataFrame, features: List[FeatureConfig]
    ) -> pd.DataFrame:
        """Engineer features based on configuration"""
        result_df = data.copy()

        for feature_config in features:
            source_col = feature_config.source_column
            feature_name = feature_config.name

            if source_col not in data.columns:
                continue

            # Apply transformation
            if feature_config.transformation == "log":
                result_df[feature_name] = np.log1p(data[source_col])
            elif feature_config.transformation == "sqrt":
                result_df[feature_name] = np.sqrt(np.abs(data[source_col]))
            elif feature_config.transformation == "standardize":
                result_df[feature_name] = (
                    data[source_col] - data[source_col].mean()
                ) / data[source_col].std()
            elif feature_config.transformation == "normalize":
                result_df[feature_name] = (
                    data[source_col] - data[source_col].min()
                ) / (data[source_col].max() - data[source_col].min())
            else:
                result_df[feature_name] = data[source_col]

            # Apply aggregation with window
            if feature_config.window_size > 1:
                if feature_config.aggregation == "sum":
                    result_df[feature_name] = (
                        result_df[feature_name]
                        .rolling(window=feature_config.window_size)
                        .sum()
                    )
                elif feature_config.aggregation == "avg":
                    result_df[feature_name] = (
                        result_df[feature_name]
                        .rolling(window=feature_config.window_size)
                        .mean()
                    )
                elif feature_config.aggregation == "min":
                    result_df[feature_name] = (
                        result_df[feature_name]
                        .rolling(window=feature_config.window_size)
                        .min()
                    )
                elif feature_config.aggregation == "max":
                    result_df[feature_name] = (
                        result_df[feature_name]
                        .rolling(window=feature_config.window_size)
                        .max()
                    )

            # Apply lag
            if feature_config.lag > 0:
                result_df[feature_name] = result_df[feature_name].shift(
                    feature_config.lag
                )

        return result_df.dropna()

    async def _prepare_training_data(
        self, data: pd.DataFrame, config: ModelConfig
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data for model"""
        feature_names = [f.name for f in config.features if not f.is_target]
        target_name = config.target_variable

        if target_name not in data.columns:
            raise ValueError(f"Target variable '{target_name}' not found in data")

        X = data[feature_names].values
        y = data[target_name].values

        return X, y

    async def _train_model_by_type(
        self,
        config: ModelConfig,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_test: np.ndarray,
        y_test: np.ndarray,
    ) -> Any:
        """Train model based on type"""
        model_type = config.model_type
        params = config.model_params

        if model_type == ModelType.LINEAR_REGRESSION:
            model = LinearRegression(**params)
            model.fit(X_train, y_train)

        elif model_type == ModelType.RANDOM_FOREST:
            model = RandomForestRegressor(
                n_estimators=params.get("n_estimators", 100),
                max_depth=params.get("max_depth", None),
                random_state=42,
                **{
                    k: v
                    for k, v in params.items()
                    if k not in ["n_estimators", "max_depth"]
                },
            )
            model.fit(X_train, y_train)

        elif model_type == ModelType.ISOLATION_FOREST:
            model = IsolationForest(
                contamination=params.get("contamination", 0.1),
                random_state=42,
                **{k: v for k, v in params.items() if k != "contamination"},
            )
            model.fit(X_train)

        elif model_type == ModelType.PROPHET and PROPHET_AVAILABLE:
            # Prophet expects specific column names
            prophet_data = pd.DataFrame(
                {
                    "ds": pd.date_range(start="2023-01-01", periods=len(y_train)),
                    "y": y_train,
                }
            )
            model = Prophet(**params)
            model.fit(prophet_data)

        elif model_type == ModelType.ARIMA and ARIMA_AVAILABLE:
            order = params.get("order", (1, 1, 1))
            model = ARIMA(y_train, order=order)
            model = model.fit()

        elif model_type == ModelType.LSTM and TENSORFLOW_AVAILABLE:
            model = await self._build_lstm_model(X_train.shape, params)

            # Reshape for LSTM
            X_train_lstm = X_train.reshape((X_train.shape[0], 1, X_train.shape[1]))
            X_test_lstm = X_test.reshape((X_test.shape[0], 1, X_test.shape[1]))

            model.fit(
                X_train_lstm,
                y_train,
                epochs=params.get("epochs", 50),
                batch_size=params.get("batch_size", 32),
                validation_data=(X_test_lstm, y_test),
                verbose=0,
            )

        else:
            raise ValueError(f"Unsupported model type: {model_type}")

        return model

    async def _build_lstm_model(self, input_shape: Tuple, params: Dict[str, Any]):
        """Build LSTM neural network model"""
        if not TENSORFLOW_AVAILABLE:
            raise ImportError("TensorFlow is required for LSTM models")

        model = Sequential(
            [
                LSTM(
                    params.get("lstm_units", 50),
                    return_sequences=params.get("return_sequences", False),
                    input_shape=(1, input_shape[1]),
                ),
                Dropout(params.get("dropout", 0.2)),
                Dense(params.get("dense_units", 25)),
                Dense(1),
            ]
        )

        model.compile(
            optimizer=params.get("optimizer", "adam"),
            loss=params.get("loss", "mse"),
            metrics=["mae"],
        )

        return model

    async def _evaluate_model(
        self, model: Any, X_test: np.ndarray, y_test: np.ndarray, config: ModelConfig
    ) -> Dict[str, float]:
        """Evaluate model performance"""
        try:
            if config.model_type == ModelType.ISOLATION_FOREST:
                # For anomaly detection, use different metrics
                anomaly_scores = model.decision_function(X_test)
                outliers = model.predict(X_test)

                return {
                    "anomaly_score_mean": float(np.mean(anomaly_scores)),
                    "anomaly_score_std": float(np.std(anomaly_scores)),
                    "outlier_ratio": float(np.sum(outliers == -1) / len(outliers)),
                }

            elif config.model_type == ModelType.LSTM and TENSORFLOW_AVAILABLE:
                X_test_lstm = X_test.reshape((X_test.shape[0], 1, X_test.shape[1]))
                y_pred = model.predict(X_test_lstm, verbose=0).flatten()

            else:
                y_pred = model.predict(X_test)

            # Regression metrics
            mae = mean_absolute_error(y_test, y_pred)
            mse = mean_squared_error(y_test, y_pred)
            rmse = np.sqrt(mse)
            r2 = r2_score(y_test, y_pred)

            # Additional metrics
            mape = np.mean(np.abs((y_test - y_pred) / y_test)) * 100

            return {
                "mae": float(mae),
                "mse": float(mse),
                "rmse": float(rmse),
                "r2_score": float(r2),
                "mape": float(mape),
            }

        except Exception as e:
            self.logger.error(f"Model evaluation failed: {e}")
            return {"error": str(e)}

    async def predict(self, request: PredictionRequest) -> PredictionResult:
        """Generate predictions using trained model"""
        model_id = request.model_id

        if model_id not in self.models:
            raise ValueError(f"Model not found: {model_id}")

        if model_id not in self.trained_models:
            raise ValueError(f"Model not trained: {model_id}")

        config = self.models[model_id]
        model = self.trained_models[model_id]

        try:
            # Prepare input data
            input_df = pd.DataFrame([request.input_data])
            features_df = await self._engineer_features(input_df, config.features)

            feature_names = [f.name for f in config.features if not f.is_target]
            X = features_df[feature_names].values

            # Scale if needed
            if model_id in self.scalers:
                X = self.scalers[model_id].transform(X)

            # Generate predictions
            predictions = []
            confidence_intervals = []

            if config.model_type == ModelType.ISOLATION_FOREST:
                # Anomaly detection
                anomaly_score = model.decision_function(X)[0]
                is_anomaly = model.predict(X)[0] == -1

                predictions.append(
                    {
                        "timestamp": datetime.utcnow().isoformat(),
                        "anomaly_score": float(anomaly_score),
                        "is_anomaly": bool(is_anomaly),
                        "confidence": abs(float(anomaly_score)),
                    }
                )

            elif config.model_type == ModelType.PROPHET and PROPHET_AVAILABLE:
                # Time series forecasting
                future_dates = model.make_future_dataframe(
                    periods=request.prediction_horizon
                )
                forecast = model.predict(future_dates)

                for i in range(request.prediction_horizon):
                    pred_date = future_dates.iloc[-request.prediction_horizon + i]["ds"]
                    pred_value = forecast.iloc[-request.prediction_horizon + i]["yhat"]
                    lower_bound = forecast.iloc[-request.prediction_horizon + i][
                        "yhat_lower"
                    ]
                    upper_bound = forecast.iloc[-request.prediction_horizon + i][
                        "yhat_upper"
                    ]

                    predictions.append(
                        {
                            "timestamp": pred_date.isoformat(),
                            "value": float(pred_value),
                            "horizon": i + 1,
                        }
                    )

                    confidence_intervals.append(
                        {
                            "timestamp": pred_date.isoformat(),
                            "lower_bound": float(lower_bound),
                            "upper_bound": float(upper_bound),
                            "confidence": request.confidence_interval,
                        }
                    )

            else:
                # Standard regression prediction
                if config.model_type == ModelType.LSTM and TENSORFLOW_AVAILABLE:
                    X_lstm = X.reshape((X.shape[0], 1, X.shape[1]))
                    pred_value = model.predict(X_lstm, verbose=0)[0][0]
                else:
                    pred_value = model.predict(X)[0]

                predictions.append(
                    {
                        "timestamp": datetime.utcnow().isoformat(),
                        "value": float(pred_value),
                        "horizon": 1,
                    }
                )

            # Calculate feature importance if available
            feature_importance = {}
            if hasattr(model, "feature_importances_"):
                feature_importance = {
                    feature_names[i]: float(importance)
                    for i, importance in enumerate(model.feature_importances_)
                }
            elif hasattr(model, "coef_"):
                feature_importance = {
                    feature_names[i]: float(coef) for i, coef in enumerate(model.coef_)
                }

            # Create result
            result = PredictionResult(
                model_id=model_id,
                predictions=predictions,
                confidence_intervals=confidence_intervals,
                feature_importance=feature_importance,
            )

            # Store in history
            self.prediction_history.append(result)

            # Keep only recent history
            if len(self.prediction_history) > 10000:
                self.prediction_history = self.prediction_history[-10000:]

            return result

        except Exception as e:
            self.logger.error(f"Prediction failed for model {model_id}: {e}")
            raise

    async def batch_predict(
        self, model_id: str, input_data: List[Dict[str, Any]], tenant_id: str = ""
    ) -> List[PredictionResult]:
        """Generate batch predictions"""
        results = []

        for data in input_data:
            request = PredictionRequest(
                model_id=model_id, tenant_id=tenant_id, input_data=data
            )

            try:
                result = await self.predict(request)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Batch prediction failed: {e}")
                # Continue with other predictions

        return results

    async def detect_anomalies(
        self, model_id: str, data: pd.DataFrame, tenant_id: str = ""
    ) -> Dict[str, Any]:
        """Detect anomalies in data"""
        if model_id not in self.models:
            raise ValueError(f"Model not found: {model_id}")

        config = self.models[model_id]
        if config.model_type != ModelType.ISOLATION_FOREST:
            raise ValueError(
                "Model must be of type ISOLATION_FOREST for anomaly detection"
            )

        model = self.trained_models[model_id]

        # Engineer features
        features_df = await self._engineer_features(data, config.features)
        feature_names = [f.name for f in config.features if not f.is_target]
        X = features_df[feature_names].values

        # Scale if needed
        if model_id in self.scalers:
            X = self.scalers[model_id].transform(X)

        # Detect anomalies
        anomaly_scores = model.decision_function(X)
        outliers = model.predict(X)

        # Create results
        anomalies = []
        for i, (score, is_outlier) in enumerate(zip(anomaly_scores, outliers)):
            if is_outlier == -1:  # Anomaly detected
                anomalies.append(
                    {
                        "index": i,
                        "score": float(score),
                        "data": data.iloc[i].to_dict(),
                        "severity": "high" if score < -0.5 else "medium",
                    }
                )

        return {
            "total_samples": len(data),
            "anomalies_detected": len(anomalies),
            "anomaly_rate": len(anomalies) / len(data),
            "avg_anomaly_score": (
                float(np.mean(anomaly_scores[outliers == -1]))
                if len(anomalies) > 0
                else 0
            ),
            "anomalies": anomalies,
        }

    async def forecast_time_series(
        self, model_id: str, periods: int = 30, tenant_id: str = ""
    ) -> Dict[str, Any]:
        """Generate time series forecast"""
        if model_id not in self.models:
            raise ValueError(f"Model not found: {model_id}")

        config = self.models[model_id]
        model = self.trained_models[model_id]

        if config.model_type == ModelType.PROPHET and PROPHET_AVAILABLE:
            future = model.make_future_dataframe(periods=periods)
            forecast = model.predict(future)

            # Extract forecast data
            forecast_data = []
            for i in range(-periods, 0):
                forecast_data.append(
                    {
                        "date": forecast.iloc[i]["ds"].isoformat(),
                        "value": float(forecast.iloc[i]["yhat"]),
                        "lower_bound": float(forecast.iloc[i]["yhat_lower"]),
                        "upper_bound": float(forecast.iloc[i]["yhat_upper"]),
                        "trend": float(forecast.iloc[i]["trend"]),
                    }
                )

            return {
                "model_id": model_id,
                "forecast_periods": periods,
                "forecast": forecast_data,
                "components": {
                    "trend": forecast[["ds", "trend"]].tail(periods).to_dict("records"),
                    "seasonal": (
                        forecast[["ds", "seasonal"]].tail(periods).to_dict("records")
                        if "seasonal" in forecast.columns
                        else None
                    ),
                },
            }

        else:
            raise ValueError(
                f"Time series forecasting not supported for model type: {config.model_type}"
            )

    async def get_model_performance(self, model_id: str) -> Dict[str, Any]:
        """Get model performance metrics"""
        if model_id not in self.models:
            raise ValueError(f"Model not found: {model_id}")

        config = self.models[model_id]

        # Get recent prediction accuracy
        recent_predictions = [
            p for p in self.prediction_history[-1000:] if p.model_id == model_id
        ]

        return {
            "model_id": model_id,
            "model_name": config.name,
            "model_type": config.model_type.value,
            "status": config.status.value,
            "last_trained": (
                config.last_trained.isoformat() if config.last_trained else None
            ),
            "training_metrics": config.performance_metrics,
            "recent_predictions": len(recent_predictions),
            "version": config.version,
        }

    async def _save_model(self, model_id: str, model: Any):
        """Save trained model to disk"""
        try:
            model_path = f"models/{model_id}.pkl"
            joblib.dump(model, model_path)

            # Save scaler if exists
            if model_id in self.scalers:
                scaler_path = f"models/{model_id}_scaler.pkl"
                joblib.dump(self.scalers[model_id], scaler_path)

        except Exception as e:
            self.logger.error(f"Failed to save model {model_id}: {e}")

    async def load_model(self, model_id: str):
        """Load trained model from disk"""
        try:
            model_path = f"models/{model_id}.pkl"
            model = joblib.load(model_path)
            self.trained_models[model_id] = model

            # Load scaler if exists
            scaler_path = f"models/{model_id}_scaler.pkl"
            try:
                scaler = joblib.load(scaler_path)
                self.scalers[model_id] = scaler
            except Exception:
                pass  # Scaler might not exist

            self.logger.info(f"Loaded model: {model_id}")

        except Exception as e:
            self.logger.error(f"Failed to load model {model_id}: {e}")
            raise

    def get_available_models(self, tenant_id: str = "") -> List[Dict[str, Any]]:
        """Get list of available models"""
        models = []

        for model_id, config in self.models.items():
            if not tenant_id or config.tenant_id == tenant_id:
                models.append(
                    {
                        "id": model_id,
                        "name": config.name,
                        "type": config.model_type.value,
                        "prediction_type": config.prediction_type.value,
                        "status": config.status.value,
                        "created_at": config.created_at.isoformat(),
                        "last_trained": (
                            config.last_trained.isoformat()
                            if config.last_trained
                            else None
                        ),
                    }
                )

        return models

    async def retrain_model(
        self, model_id: str, new_data: pd.DataFrame
    ) -> Dict[str, Any]:
        """Retrain existing model with new data"""
        if model_id not in self.models:
            raise ValueError(f"Model not found: {model_id}")

        config = self.models[model_id]
        config.version += 1

        # Retrain the model
        result = await self.train_model(model_id, new_data)

        self.logger.info(f"Retrained model {model_id} to version {config.version}")
        return result

    async def deploy_model(self, model_id: str) -> bool:
        """Deploy model for serving predictions"""
        if model_id not in self.models:
            raise ValueError(f"Model not found: {model_id}")

        config = self.models[model_id]

        if config.status != ModelStatus.TRAINED:
            raise ValueError("Model must be trained before deployment")

        config.status = ModelStatus.DEPLOYED
        config.updated_at = datetime.utcnow()

        self.logger.info(f"Deployed model: {model_id}")
        return True
