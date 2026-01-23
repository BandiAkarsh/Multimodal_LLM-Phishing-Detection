"""
ML Training Script for Phishing Detection

Uses EXISTING PhishTank dataset (46,000+ URLs) - NO download required.
Trains a lightweight classifier on URL features.
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
import importlib.util
spec = importlib.util.spec_from_file_location("feature_extraction", project_root / "05_utils/feature_extraction.py")
feature_extraction = importlib.util.module_from_spec(spec)
spec.loader.exec_module(feature_extraction)
URLFeatureExtractor = feature_extraction.URLFeatureExtractor

def load_dataset():
    """Load the existing PhishTank + OpenPhish + legitimate URLs dataset."""
    print("Loading datasets from 01_data/raw/...")
    
    # Load phishing URLs
    phishing_df = pd.read_csv(project_root / "01_data/raw/combined_dataset.csv")
    print(f"  Phishing URLs: {len(phishing_df)}")
    
    # For legitimate URLs, we'll use a list of known safe domains
    # In production, you'd have a proper legitimate dataset
    legitimate_urls = [
        "https://google.com", "https://facebook.com", "https://youtube.com",
        "https://amazon.com", "https://wikipedia.org", "https://twitter.com",
        "https://instagram.com", "https://linkedin.com", "https://reddit.com",
        "https://netflix.com", "https://microsoft.com", "https://apple.com",
        "https://github.com", "https://stackoverflow.com", "https://medium.com",
        "https://nytimes.com", "https://bbc.com", "https://cnn.com",
        "https://walmart.com", "https://ebay.com", "https://target.com",
        "https://bestbuy.com", "https://homedepot.com", "https://lowes.com",
        "https://costco.com", "https://macys.com", "https://nordstrom.com",
        "https://chase.com", "https://bankofamerica.com", "https://wellsfargo.com",
        "https://capitalone.com", "https://americanexpress.com", "https://discover.com",
        "https://paypal.com", "https://venmo.com", "https://stripe.com",
        "https://dropbox.com", "https://box.com", "https://onedrive.com",
        "https://drive.google.com", "https://icloud.com", "https://mega.nz",
        "https://zoom.us", "https://slack.com", "https://discord.com",
        "https://twitch.tv", "https://spotify.com", "https://soundcloud.com",
        "https://airbnb.com", "https://booking.com", "https://expedia.com",
        "https://uber.com", "https://lyft.com", "https://doordash.com",
        "https://grubhub.com", "https://instacart.com", "https://postmates.com",
    ] * 100  # Replicate to balance dataset somewhat
    
    legitimate_df = pd.DataFrame({
        'url': legitimate_urls,
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

def extract_features_batch(urls, max_samples=5000):
    """Extract features from URLs."""
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
            features_list.append(features)
        except Exception as e:
            continue
    
    df = pd.DataFrame(features_list)
    print(f"  Extracted features from {len(df)} URLs")
    return df

def train_model(features_df):
    """Train and evaluate multiple models."""
    print("\n" + "="*60)
    print("TRAINING PHISHING DETECTION MODEL")
    print("="*60)
    
    # Prepare features and labels
    feature_cols = [col for col in features_df.columns if col != 'label']
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
        'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
        'Gradient Boosting': GradientBoostingClassifier(n_estimators=100, random_state=42),
        'Logistic Regression': LogisticRegression(max_iter=1000, random_state=42)
    }
    
    best_model = None
    best_f1 = 0
    best_name = ""
    
    for name, model in models.items():
        print(f"\n--- Training {name} ---")
        model.fit(X_train_scaled, y_train)
        y_pred = model.predict(X_test_scaled)
        
        accuracy = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        
        print(f"Accuracy: {accuracy:.4f}")
        print(f"F1 Score: {f1:.4f}")
        
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
    
    return best_model, scaler, feature_cols

def save_model(model, scaler, feature_cols):
    """Save the trained model."""
    model_dir = project_root / "02_models"
    model_dir.mkdir(exist_ok=True)
    
    # Save model
    joblib.dump(model, model_dir / "phishing_classifier.joblib")
    joblib.dump(scaler, model_dir / "feature_scaler.joblib")
    joblib.dump(feature_cols, model_dir / "feature_columns.joblib")
    
    print(f"\nModel saved to {model_dir}/")
    print("  - phishing_classifier.joblib")
    print("  - feature_scaler.joblib")
    print("  - feature_columns.joblib")

def main():
    print("="*60)
    print("PHISHING DETECTION ML TRAINING")
    print("Using existing PhishTank dataset - NO download required")
    print("="*60)
    
    # Load data
    dataset = load_dataset()
    
    # Extract features
    features_df = extract_features_batch(dataset, max_samples=5000)
    
    # Train model
    model, scaler, feature_cols = train_model(features_df)
    
    # Save model
    save_model(model, scaler, feature_cols)
    
    print("\n" + "="*60)
    print("TRAINING COMPLETE!")
    print("="*60)

if __name__ == "__main__":
    main()
