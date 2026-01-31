"""
MLflow Model Management for Phishing Detection

Provides:
- Model versioning and tracking
- Experiment logging
- Model registry
- Automated metrics tracking
- Model comparison
- A/B testing support

Author: Phishing Guard Team
Version: 2.0.0
"""

import os
import sys
import json
import joblib
import mlflow
import mlflow.sklearn
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ModelManager:
    """
    Manages ML models using MLflow for versioning and tracking.
    
    Features:
    - Experiment tracking
    - Model versioning
    - Metrics logging
    - Model registry
    - Automated comparison
    """
    
    def __init__(self, tracking_uri: str = "./mlruns", experiment_name: str = "phishing_detection"):
        """
        Initialize model manager.
        
        Args:
            tracking_uri: MLflow tracking URI (default: local ./mlruns)
            experiment_name: Name of the experiment
        """
        self.tracking_uri = tracking_uri
        self.experiment_name = experiment_name
        
        # Setup MLflow
        mlflow.set_tracking_uri(tracking_uri)
        mlflow.set_experiment(experiment_name)
        
        # Create directories
        Path(tracking_uri).mkdir(parents=True, exist_ok=True)
        
        logger.info(f"ModelManager initialized: {experiment_name} @ {tracking_uri}")
    
    def log_model_training(
        self,
        model,
        model_name: str,
        metrics: Dict[str, float],
        params: Dict[str, Any],
        X_train_sample=None,
        feature_names: List[str] = None,
        dataset_info: Dict[str, Any] = None
    ) -> str:
        """
        Log model training with MLflow.
        
        Args:
            model: Trained sklearn model
            model_name: Name for the model (e.g., "phishing_classifier_v1")
            metrics: Dictionary of metrics (f1_score, accuracy, etc.)
            params: Dictionary of hyperparameters
            X_train_sample: Sample of training data for signature
            feature_names: List of feature names
            dataset_info: Information about the dataset
            
        Returns:
            run_id: MLflow run ID
        """
        with mlflow.start_run(run_name=f"train_{model_name}") as run:
            run_id = run.info.run_id
            
            # Log parameters
            mlflow.log_params(params)
            
            # Log metrics
            mlflow.log_metrics(metrics)
            
            # Log dataset info
            if dataset_info:
                mlflow.set_tags({
                    "dataset_size": dataset_info.get("size", "unknown"),
                    "dataset_version": dataset_info.get("version", "v1.0"),
                    "phishing_ratio": dataset_info.get("phishing_ratio", "unknown"),
                    "training_date": datetime.now().isoformat()
                })
            
            # Infer signature if sample provided
            signature = None
            if X_train_sample is not None:
                try:
                    from mlflow.models.signature import infer_signature
                    predictions = model.predict(X_train_sample[:5])
                    signature = infer_signature(X_train_sample[:5], predictions)
                except Exception as e:
                    logger.warning(f"Could not infer signature: {e}")
            
            # Log the model (using 'name' instead of deprecated 'artifact_path')
            mlflow.sklearn.log_model(
                model,
                name="model",
                registered_model_name=model_name,
                signature=signature,
                input_example=X_train_sample[:5] if X_train_sample is not None else None
            )
            
            # Log feature importance if available
            if hasattr(model, 'feature_importances_') and feature_names:
                importances = dict(zip(feature_names, model.feature_importances_))
                # Log top 10 features
                top_features = sorted(importances.items(), key=lambda x: x[1], reverse=True)[:10]
                for feature, importance in top_features:
                    mlflow.log_metric(f"feature_importance_{feature}", importance)
            
            logger.info(f"Model logged: {model_name} (run_id: {run_id})")
            logger.info(f"Metrics: {metrics}")
            
            return run_id
    
    def load_model(self, model_name: str, version: Optional[int] = None) -> Any:
        """
        Load a model from MLflow registry.
        
        Args:
            model_name: Registered model name
            version: Specific version (default: latest)
            
        Returns:
            Loaded model
        """
        try:
            if version:
                model_uri = f"models:/{model_name}/{version}"
            else:
                model_uri = f"models:/{model_name}/latest"
            
            model = mlflow.sklearn.load_model(model_uri)
            logger.info(f"Loaded model: {model_uri}")
            return model
            
        except Exception as e:
            logger.error(f"Failed to load model {model_name}: {e}")
            # Fallback to joblib
            return self._load_joblib_fallback(model_name)
    
    def _load_joblib_fallback(self, model_name: str):
        """Fallback to joblib if MLflow loading fails"""
        model_path = f"02_models/{model_name}.joblib"
        if os.path.exists(model_path):
            logger.info(f"Loading from joblib fallback: {model_path}")
            return joblib.load(model_path)
        raise FileNotFoundError(f"Model not found: {model_name}")
    
    def register_model(
        self,
        model_name: str,
        run_id: str,
        tags: Optional[Dict[str, str]] = None,
        description: Optional[str] = None
    ) -> str:
        """
        Register a trained model in MLflow Model Registry.
        
        This creates a versioned model entry that can be loaded by name.
        
        Args:
            model_name: Name to register the model under
            run_id: MLflow run ID from training
            tags: Optional tags for the model version
            description: Optional description
            
        Returns:
            Version string of the registered model
        """
        from mlflow.tracking import MlflowClient
        
        client = MlflowClient()
        
        try:
            # Create or get registered model
            try:
                client.create_registered_model(model_name, description=description or f"Model: {model_name}")
                logger.info(f"Created registered model: {model_name}")
            except mlflow.exceptions.MlflowException:
                # Model already exists
                logger.info(f"Registered model already exists: {model_name}")
            
            # Create model version from run
            model_version = client.create_model_version(
                name=model_name,
                source=f"runs:/{run_id}/model",
                run_id=run_id,
                tags=tags or {}
            )
            
            version_number = model_version.version
            logger.info(f"Registered model version: {model_name} v{version_number}")
            
            # Transition to staging
            client.transition_model_version_stage(
                name=model_name,
                version=version_number,
                stage="Staging"
            )
            logger.info(f"Transitioned to Staging: {model_name} v{version_number}")
            
            return version_number
            
        except Exception as e:
            logger.error(f"Failed to register model {model_name}: {e}")
            raise
    
    def transition_to_production(self, model_name: str, version: int) -> None:
        """
        Transition a model version to Production stage.
        
        Args:
            model_name: Registered model name
            version: Version number to transition
        """
        from mlflow.tracking import MlflowClient
        
        client = MlflowClient()
        
        try:
            client.transition_model_version_stage(
                name=model_name,
                version=version,
                stage="Production"
            )
            logger.info(f"Transitioned to Production: {model_name} v{version}")
        except Exception as e:
            logger.error(f"Failed to transition to production: {e}")
            raise
    
    def compare_models(
        self,
        model_names: List[str],
        metric: str = "f1_score"
    ) -> Dict[str, Any]:
        """
        Compare multiple models by metric.
        
        Args:
            model_names: List of model names to compare
            metric: Metric to compare (default: f1_score)
            
        Returns:
            Dictionary with comparison results
        """
        from mlflow.tracking import MlflowClient
        
        client = MlflowClient()
        results = {}
        
        for model_name in model_names:
            try:
                # Get latest version
                latest_versions = client.get_latest_versions(model_name, stages=["None"])
                if latest_versions:
                    version = latest_versions[0]
                    run_id = version.run_id
                    
                    # Get run metrics
                    run = client.get_run(run_id)
                    metric_value = run.data.metrics.get(metric, 0)
                    
                    results[model_name] = {
                        "version": version.version,
                        "metric": metric,
                        "value": metric_value,
                        "run_id": run_id,
                        "created_at": version.creation_timestamp
                    }
            except Exception as e:
                logger.warning(f"Could not compare {model_name}: {e}")
                results[model_name] = {"error": str(e)}
        
        # Sort by metric value
        sorted_results = dict(sorted(
            results.items(),
            key=lambda x: x[1].get("value", 0) if isinstance(x[1], dict) else 0,
            reverse=True
        ))
        
        return sorted_results
    
    def get_model_versions(self, model_name: str) -> List[Dict[str, Any]]:
        """
        Get all versions of a model.
        
        Args:
            model_name: Registered model name
            
        Returns:
            List of version information
        """
        from mlflow.tracking import MlflowClient
        
        client = MlflowClient()
        versions = []
        
        try:
            model_versions = client.search_model_versions(f"name='{model_name}'")
            for mv in model_versions:
                versions.append({
                    "version": mv.version,
                    "stage": mv.current_stage,
                    "run_id": mv.run_id,
                    "created_at": datetime.fromtimestamp(mv.creation_timestamp / 1000).isoformat(),
                    "metrics": self._get_run_metrics(mv.run_id)
                })
        except Exception as e:
            logger.error(f"Error getting versions: {e}")
        
        return versions
    
    def _get_run_metrics(self, run_id: str) -> Dict[str, float]:
        """Get metrics for a specific run"""
        from mlflow.tracking import MlflowClient
        
        client = MlflowClient()
        try:
            run = client.get_run(run_id)
            return dict(run.data.metrics)
        except:
            return {}
    
    def promote_model(self, model_name: str, version: int, stage: str = "Production"):
        """
        Promote model to a stage (Staging, Production, Archived).
        
        Args:
            model_name: Model name
            version: Version number
            stage: Target stage
        """
        from mlflow.tracking import MlflowClient
        
        client = MlflowClient()
        try:
            client.transition_model_version_stage(
                name=model_name,
                version=version,
                stage=stage
            )
            logger.info(f"Promoted {model_name} v{version} to {stage}")
        except Exception as e:
            logger.error(f"Failed to promote model: {e}")
    
    def export_model_metrics(self, model_name: str, output_file: str):
        """Export model metrics to JSON"""
        versions = self.get_model_versions(model_name)
        
        with open(output_file, 'w') as f:
            json.dump({
                "model_name": model_name,
                "export_date": datetime.now().isoformat(),
                "versions": versions
            }, f, indent=2)
        
        logger.info(f"Exported metrics to {output_file}")


class ModelRetrainingPipeline:
    """
    Automated model retraining pipeline.
    
    Monitors model performance and triggers retraining when needed.
    """
    
    def __init__(self, model_manager: ModelManager, threshold: float = 0.85):
        self.model_manager = model_manager
        self.performance_threshold = threshold
        self.retraining_history = []
    
    def check_model_health(self, model_name: str, current_metrics: Dict[str, float]) -> bool:
        """
        Check if model performance is below threshold.
        
        Returns:
            bool: True if retraining needed
        """
        f1_score = current_metrics.get("f1_score", 0)
        
        if f1_score < self.performance_threshold:
            logger.warning(f"Model performance below threshold: {f1_score:.3f} < {self.performance_threshold}")
            return True
        
        return False
    
    def trigger_retraining(
        self,
        model_name: str,
        new_data_path: str,
        training_function,
        **kwargs
    ):
        """
        Trigger model retraining with new data.
        
        Args:
            model_name: Name for the new model version
            new_data_path: Path to new training data
            training_function: Function to train model
            **kwargs: Additional training parameters
        """
        logger.info(f"Starting retraining for {model_name}")
        
        try:
            # Train new model
            model, metrics, params = training_function(new_data_path, **kwargs)
            
            # Log with MLflow
            run_id = self.model_manager.log_model_training(
                model=model,
                model_name=model_name,
                metrics=metrics,
                params=params,
                dataset_info={
                    "size": "new_data",
                    "retraining": True,
                    "trigger_date": datetime.now().isoformat()
                }
            )
            
            # Record retraining
            self.retraining_history.append({
                "model_name": model_name,
                "run_id": run_id,
                "metrics": metrics,
                "timestamp": datetime.now().isoformat()
            })
            
            logger.info(f"Retraining complete: {run_id}")
            return run_id
            
        except Exception as e:
            logger.error(f"Retraining failed: {e}")
            raise


def demo():
    """Demonstrate model management functionality"""
    print("=" * 70)
    print("MLflow Model Management Demo")
    print("=" * 70)
    
    # Initialize
    manager = ModelManager(
        tracking_uri="./mlruns",
        experiment_name="phishing_detection_demo"
    )
    
    # Example: Log a dummy model
    from sklearn.ensemble import RandomForestClassifier
    import numpy as np
    
    print("\n[1] Creating and logging a model...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    
    # Dummy training data
    X_train = np.random.rand(100, 10)
    y_train = np.random.randint(0, 2, 100)
    model.fit(X_train, y_train)
    
    # Log model
    run_id = manager.log_model_training(
        model=model,
        model_name="phishing_classifier_v2",
        metrics={
            "f1_score": 0.998,
            "accuracy": 0.995,
            "precision": 0.997,
            "recall": 0.999
        },
        params={
            "n_estimators": 100,
            "max_depth": 20,
            "random_state": 42
        },
        X_train_sample=X_train[:5],
        feature_names=[f"feature_{i}" for i in range(10)],
        dataset_info={
            "size": 100,
            "version": "v2.1",
            "phishing_ratio": 0.5
        }
    )
    
    print(f"✓ Model logged: {run_id}")
    
    print("\n[2] Getting model versions...")
    versions = manager.get_model_versions("phishing_classifier_v2")
    print(f"Found {len(versions)} version(s)")
    for v in versions:
        print(f"  Version {v['version']}: F1={v['metrics'].get('f1_score', 0):.3f}")
    
    print("\n[3] Exporting metrics...")
    manager.export_model_metrics("phishing_classifier_v2", "model_metrics.json")
    print("✓ Metrics exported to model_metrics.json")
    
    print("\n" + "=" * 70)
    print("Demo complete!")
    print(f"View results: mlflow ui --backend-store-uri ./mlruns")
    print("=" * 70)


if __name__ == "__main__":
    demo()
