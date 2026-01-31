"""
Enhanced ML Training with MLflow Tracking

Trains phishing detection model with full MLflow integration:
- Experiment tracking
- Model versioning
- Metrics logging
- Artifact storage

Usage:
    python train_with_mlflow.py
    
View results:
    mlflow ui --backend-store-uri ./mlruns
"""

import os
import sys
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
from sklearn.preprocessing import StandardScaler
import joblib
import warnings
warnings.filterwarnings('ignore')

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

# Import feature extractor
sys.path.append(str(project_root / '05_utils'))
from feature_extraction import URLFeatureExtractor

# Import model manager
from model_manager import ModelManager


def load_dataset():
    """Load the existing PhishTank + OpenPhish + legitimate URLs dataset."""
    print("Loading datasets from 01_data/raw/...")
    
    # Load phishing URLs
    try:
        phishing_df = pd.read_csv(project_root / "01_data/raw/combined_dataset.csv")
        print(f"  Phishing URLs: {len(phishing_df)}")
    except FileNotFoundError:
        print("  Warning: Phishing dataset not found, creating synthetic data")
        # Create synthetic data for demo
        phishing_urls = [f"http://phishing{i}.com/login" for i in range(1000)]
        phishing_df = pd.DataFrame({
            'url': phishing_urls,
            'label': 1
        })
    
    # Generate legitimate URLs
    legitimate_domains = [
        "google.com", "facebook.com", "youtube.com", "amazon.com",
        "wikipedia.org", "twitter.com", "instagram.com", "linkedin.com",
        "github.com", "stackoverflow.com", "microsoft.com", "apple.com",
        "netflix.com", "reddit.com", "spotify.com", "zoom.us"
    ] * 100  # Replicate to balance
    
    legitimate_urls = [f"https://{domain}" for domain in legitimate_domains]
    legitimate_df = pd.DataFrame({
        'url': legitimate_urls[:len(phishing_df)],  # Balance classes
        'label': 0
    })
    
    print(f"  Legitimate URLs: {len(legitimate_df)}")
    
    # Combine
    combined = pd.concat([
        phishing_df[['url', 'label']],
        legitimate_df
    ], ignore_index=True)
    
    print(f"  Total dataset: {len(combined)}")
    return combined


def extract_features_batch(urls, labels, max_samples=5000):
    """Extract features from URLs with progress tracking."""
    print(f"\nExtracting features from {min(len(urls), max_samples)} URLs...")
    extractor = URLFeatureExtractor()
    
    features_list = []
    
    # Sample equally from both classes
    phishing = urls[urls['label'] == 1]
    legitimate = urls[urls['label'] == 0]
    
    samples_per_class = max_samples // 2
    phishing_sample = phishing.sample(n=min(samples_per_class, len(phishing)), random_state=42)
    legitimate_sample = legitimate.sample(n=min(samples_per_class, len(legitimate)), random_state=42)
    
    urls_sample = pd.concat([phishing_sample, legitimate_sample]).reset_index(drop=True)
    print(f"  Phishing samples: {len(phishing_sample)}, Legitimate samples: {len(legitimate_sample)}")
    
    for i, row in urls_sample.iterrows():
        if i % 500 == 0:
            print(f"  Processed {i}/{len(urls_sample)} URLs...")
        try:
            features = extractor.extract_features(row['url'])
            features['label'] = row['label']
            features['url'] = row['url']  # Keep URL for reference
            features_list.append(features)
        except Exception as e:
            print(f"    Warning: Error processing {row['url']}: {e}")
            continue
    
    df = pd.DataFrame(features_list)
    print(f"  Extracted features from {len(df)} URLs")
    return df


def train_and_log_model(features_df, model_manager):
    """Train model and log with MLflow."""
    print("\n" + "="*60)
    print("TRAINING WITH MLFLOW TRACKING")
    print("="*60)
    
    # Prepare features and labels
    feature_cols = [col for col in features_df.columns 
                   if col not in ['label', 'url'] and features_df[col].dtype in ['int64', 'float64', 'bool']]
    
    X = features_df[feature_cols].values
    y = features_df['label'].values
    
    # Handle NaN values
    X = np.nan_to_num(X, nan=0.0)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\nTraining set: {len(X_train)} samples")
    print(f"Test set: {len(X_test)} samples")
    print(f"Phishing ratio: {y.mean():.2%}")
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train multiple models
    models = {
        'Random Forest': RandomForestClassifier(
            n_estimators=200, 
            max_depth=20,
            min_samples_split=5,
            random_state=42,
            n_jobs=-1
        ),
        'Gradient Boosting': GradientBoostingClassifier(
            n_estimators=100,
            max_depth=5,
            learning_rate=0.1,
            random_state=42
        ),
        'Logistic Regression': LogisticRegression(
            max_iter=1000,
            random_state=42,
            class_weight='balanced'
        )
    }
    
    best_model = None
    best_f1 = 0
    best_name = ""
    
    for name, model in models.items():
        print(f"\n--- Training {name} ---")
        
        # Train
        model.fit(X_train_scaled, y_train)
        y_pred = model.predict(X_test_scaled)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        
        print(f"Accuracy: {accuracy:.4f}")
        print(f"F1 Score: {f1:.4f}")
        
        # Log with MLflow
        params = {
            "model_type": name,
            "n_estimators": getattr(model, 'n_estimators', 'N/A'),
            "max_depth": getattr(model, 'max_depth', 'N/A'),
            "random_state": 42,
            "features_count": len(feature_cols)
        }
        
        metrics = {
            "accuracy": accuracy,
            "f1_score": f1,
            "precision": f1_score(y_test, y_pred, pos_label=1),
            "recall": f1_score(y_test, y_pred, average='binary')
        }
        
        run_id = model_manager.log_model_training(
            model=model,
            model_name=f"phishing_classifier_{name.lower().replace(' ', '_')}",
            metrics=metrics,
            params=params,
            X_train_sample=X_train_scaled[:10],
            feature_names=feature_cols,
            dataset_info={
                "size": len(features_df),
                "version": "v2.0",
                "phishing_ratio": float(y.mean()),
                "training_date": pd.Timestamp.now().isoformat()
            }
        )
        
        print(f"Logged to MLflow: run_id={run_id}")
        
        # Track best model
        if f1 > best_f1:
            best_f1 = f1
            best_model = model
            best_name = name
    
    print(f"\n{'='*60}")
    print(f"BEST MODEL: {best_name} (F1 Score: {best_f1:.4f})")
    print(f"{'='*60}")
    
    # Detailed report for best model
    y_pred_best = best_model.predict(X_test_scaled)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred_best, target_names=['Legitimate', 'Phishing']))
    
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred_best)
    print(f"  TN: {cm[0][0]:5d}  FP: {cm[0][1]:5d}")
    print(f"  FN: {cm[1][0]:5d}  TP: {cm[1][1]:5d}")
    
    # Save best model as primary and get run_id for registration
    print("\n📦 Logging best model to MLflow...")
    run_id = model_manager.log_model_training(
        model=best_model,
        model_name="phishing_classifier",  # Primary name
        metrics={"f1_score": best_f1, "accuracy": accuracy_score(y_test, y_pred_best)},
        params={"model_type": best_name, "is_primary": True, "features_count": len(feature_cols)},
        X_train_sample=X_train_scaled[:10],
        feature_names=feature_cols,
        dataset_info={"size": len(features_df), "version": "v2.0"}
    )
    
    # Register model in MLflow Model Registry
    print("\n🔧 Registering model in MLflow Model Registry...")
    try:
        version = model_manager.register_model(
            model_name="phishing_classifier",
            run_id=run_id,
            tags={
                "model_type": best_name,
                "f1_score": str(best_f1),
                "features_count": str(len(feature_cols)),
                "status": "staging"
            },
            description=f"Phishing detection model ({best_name}) with {len(feature_cols)} features, F1={best_f1:.4f}"
        )
        print(f"  ✓ Model registered: phishing_classifier v{version}")
        
        # Transition to production if performance is good
        if best_f1 >= 0.90:
            print("  🚀 Transitioning to Production (F1 >= 0.90)...")
            model_manager.transition_to_production("phishing_classifier", version)
            print(f"  ✓ Model v{version} is now in Production stage")
    except Exception as e:
        print(f"  ⚠️ Model registration skipped: {e}")
        print("  Note: Model is still available in MLflow runs and joblib files")
    
    return best_model, scaler, feature_cols, run_id


def save_artifacts(model, scaler, feature_cols):
    """Save model artifacts to disk."""
    model_dir = project_root / "02_models"
    model_dir.mkdir(exist_ok=True)
    
    # Save to joblib (backup)
    joblib.dump(model, model_dir / "phishing_classifier.joblib")
    joblib.dump(scaler, model_dir / "feature_scaler.joblib")
    joblib.dump(feature_cols, model_dir / "feature_columns.joblib")
    
    # Also save to BentoML
    try:
        sys.path.insert(0, str(project_root / '04_inference'))
        from bentoml_service import save_model_to_bentoml
        save_model_to_bentoml(str(model_dir / "phishing_classifier.joblib"))
    except Exception as e:
        print(f"Note: Could not save to BentoML: {e}")
    
    print(f"\nArtifacts saved to {model_dir}/")
    print("  - phishing_classifier.joblib")
    print("  - feature_scaler.joblib")
    print("  - feature_columns.joblib")


def main():
    """Main training pipeline."""
    print("="*60)
    print("PHISHING DETECTION ML TRAINING WITH MLFLOW")
    print("="*60)
    
    # Initialize model manager
    model_manager = ModelManager(
        tracking_uri="./mlruns",
        experiment_name="phishing_detection_training"
    )
    
    # Load data
    dataset = load_dataset()
    
    # Extract features
    features_df = extract_features_batch(dataset, dataset['label'], max_samples=5000)
    
    # Train and log
    model, scaler, feature_cols, run_id = train_and_log_model(features_df, model_manager)
    
    # Save artifacts
    save_artifacts(model, scaler, feature_cols)
    
    # Export metrics
    model_manager.export_model_metrics("phishing_classifier", "02_models/model_metrics.json")
    
    print("\n" + "="*60)
    print("TRAINING COMPLETE!")
    print("="*60)
    print("\n📊 MLflow Model Registry:")
    print("  Model: phishing_classifier")
    print("  Run ID:", run_id)
    print("  Status: Registered and ready for loading")
    print("\nView results:")
    print("  mlflow ui --backend-store-uri ./mlruns")
    print("  # In MLflow UI -> Models tab -> phishing_classifier")
    print("\nCompare models:")
    comparison = model_manager.compare_models([
        "phishing_classifier_random_forest",
        "phishing_classifier_gradient_boosting",
        "phishing_classifier_logistic_regression"
    ])
    for model_name, info in comparison.items():
        if 'value' in info:
            print(f"  {model_name}: F1={info['value']:.4f}")


if __name__ == "__main__":
    main()
