# 03_training Folder Documentation

## Overview

The `03_training/` folder contains all scripts for training machine learning models. These scripts take raw data and produce trained models that can classify URLs as phishing or legitimate.

## Folder Structure

```
03_training/
├── train_ml.py           # Main training script (Random Forest)
├── train.py              # BERT-based training (text features)
├── train_classifier.py   # Alternative BERT training
└── dataset.py            # PyTorch Dataset for MLLM features
```

---

## File Explanations

### 1. `train_ml.py` - Main Training Script

This is the **primary** training script used by the project. It trains a Random Forest classifier on URL features.

#### Line-by-Line Explanation

```python
"""
ML Training Script for Phishing Detection

Uses EXISTING PhishTank dataset (46,000+ URLs) - NO download required.
Trains a lightweight classifier on URL features.
"""
```
**Lines 1-6:** Documentation explaining what the script does.

```python
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
```
**Lines 8-20:** Import necessary libraries:
- `pandas`: For loading and manipulating CSV data
- `numpy`: For numerical operations
- `sklearn`: Machine learning library with classifiers and metrics
- `joblib`: For saving trained models
- `warnings`: To suppress unnecessary warnings

```python
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))
```
**Lines 22-23:** Set up the project path so we can import modules from other folders.

```python
import importlib.util
spec = importlib.util.spec_from_file_location("feature_extraction", project_root / "05_utils/feature_extraction.py")
feature_extraction = importlib.util.module_from_spec(spec)
spec.loader.exec_module(feature_extraction)
URLFeatureExtractor = feature_extraction.URLFeatureExtractor
```
**Lines 25-31:** Dynamically import the `URLFeatureExtractor` class from `05_utils/`. This is needed because the folder has a number prefix (`05_`).

```python
def load_dataset():
    """Load the existing PhishTank + OpenPhish + legitimate URLs dataset."""
    print("Loading datasets from 01_data/raw/...")
    
    # Load phishing URLs
    phishing_df = pd.read_csv(project_root / "01_data/raw/combined_dataset.csv")
    print(f"  Phishing URLs: {len(phishing_df)}")
```
**Lines 33-39:** Load the phishing dataset:
- Reads `combined_dataset.csv` which contains known phishing URLs
- Prints how many phishing URLs were loaded

```python
    # For legitimate URLs, we'll use a list of known safe domains
    legitimate_urls = [
        "https://google.com", "https://facebook.com", "https://youtube.com",
        # ... many more ...
    ] * 100  # Replicate to balance dataset somewhat
    
    legitimate_df = pd.DataFrame({
        'url': legitimate_urls,
        'label': 0
    })
```
**Lines 41-68:** Create legitimate URL dataset:
- Uses a list of known safe websites
- Replicates 100x to balance with phishing URLs
- Labels them as `0` (legitimate)

```python
    combined = pd.concat([
        phishing_df[['url', 'label']],
        legitimate_df
    ], ignore_index=True)
    
    return combined
```
**Lines 70-78:** Combine phishing and legitimate URLs into one dataset.

```python
def extract_features_batch(urls, max_samples=5000):
    """Extract features from URLs."""
    print(f"\nExtracting features from {min(len(urls), max_samples)} URLs...")
    extractor = URLFeatureExtractor()
```
**Lines 80-84:** Start of feature extraction function:
- Creates an instance of `URLFeatureExtractor`
- Limits to `max_samples` for speed

```python
    # Sample equally from both classes
    phishing = urls[urls['label'] == 1]
    legitimate = urls[urls['label'] == 0]
    
    samples_per_class = max_samples // 2
    phishing_sample = phishing.sample(n=min(samples_per_class, len(phishing)), random_state=42)
    legitimate_sample = legitimate.sample(n=min(samples_per_class, len(legitimate)), random_state=42)
```
**Lines 86-92:** Balance the dataset:
- Take equal samples from phishing and legitimate
- Use `random_state=42` for reproducibility

```python
    for i, row in urls_sample.iterrows():
        if i % 500 == 0:
            print(f"  Processed {i}/{len(urls_sample)} URLs...")
        try:
            features = extractor.extract_features(row['url'])
            features['label'] = row['label']
            features_list.append(features)
        except Exception as e:
            continue
```
**Lines 98-106:** Extract features from each URL:
- Print progress every 500 URLs
- Extract 17+ features using `URLFeatureExtractor`
- Add the label to features
- Skip URLs that cause errors

```python
def train_model(features_df):
    """Train and evaluate multiple models."""
    
    # Prepare features and labels
    feature_cols = [col for col in features_df.columns if col != 'label']
    X = features_df[feature_cols].values
    y = features_df['label'].values
```
**Lines 112-121:** Prepare data for training:
- Separate features (X) from labels (y)
- Get list of feature column names

```python
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
```
**Lines 127-129:** Split into training (80%) and test (20%):
- `stratify=y` ensures both sets have same ratio of phishing/legitimate

```python
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
```
**Lines 135-138:** Normalize features:
- `fit_transform`: Calculate mean/std from training data and transform
- `transform`: Use same mean/std to transform test data

```python
    # Train multiple models
    models = {
        'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
        'Gradient Boosting': GradientBoostingClassifier(n_estimators=100, random_state=42),
        'Logistic Regression': LogisticRegression(max_iter=1000, random_state=42)
    }
```
**Lines 140-145:** Define models to try:
- **Random Forest**: Ensemble of decision trees (usually best)
- **Gradient Boosting**: Sequential tree building
- **Logistic Regression**: Simple linear model

```python
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
```
**Lines 151-165:** Train and evaluate each model:
- `fit()`: Train on training data
- `predict()`: Make predictions on test data
- Calculate accuracy and F1 score
- Keep track of best model

```python
def save_model(model, scaler, feature_cols):
    """Save the trained model."""
    model_dir = project_root / "02_models"
    model_dir.mkdir(exist_ok=True)
    
    joblib.dump(model, model_dir / "phishing_classifier.joblib")
    joblib.dump(scaler, model_dir / "feature_scaler.joblib")
    joblib.dump(feature_cols, model_dir / "feature_columns.joblib")
```
**Lines 183-191:** Save trained model and related files:
- Model itself
- Scaler (for normalizing new inputs)
- Feature columns (to ensure correct order)

---

### 2. `dataset.py` - PyTorch Dataset

This file defines a custom Dataset class for loading MLLM-generated text features.

```python
class MLLMFeatureDataset(Dataset):
    """Dataset for loading MLLM text descriptions."""
    
    def __init__(self, data_dir, tokenizer, max_length=512):
        self.data_dir = data_dir
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.samples = self._load_samples()
```
**Purpose:** Loads `*_mllm.json` files and prepares them for BERT training.

---

### 3. `train.py` - BERT Training

Alternative training script using BERT on text descriptions.

```python
def train_epoch(model, dataloader, optimizer, device):
    model.train()
    total_loss = 0
    
    for batch in dataloader:
        input_ids = batch['input_ids'].to(device)
        attention_mask = batch['attention_mask'].to(device)
        labels = batch['labels'].to(device)
        
        optimizer.zero_grad()
        outputs = model(input_ids, attention_mask)
        loss = criterion(outputs, labels)
        loss.backward()
        optimizer.step()
        
        total_loss += loss.item()
```
**Purpose:** Train BERT to classify MLLM-generated text descriptions.

---

## How to Train

### Train Random Forest (Recommended)
```bash
cd 03_training
python train_ml.py
```

**Output:**
```
Loading datasets from 01_data/raw/...
  Phishing URLs: 46234
  Legitimate URLs: 5000
  Total dataset: 51234

Extracting features from 5000 URLs...
  Processed 0/5000 URLs...
  Processed 500/5000 URLs...
  ...

--- Training Random Forest ---
Accuracy: 0.9980
F1 Score: 0.9980

BEST MODEL: Random Forest (F1 Score: 0.9980)

Model saved to 02_models/
```

### Train BERT (Optional, requires GPU)
```bash
cd 03_training
python train.py
```

---

## Training Tips

1. **More data = better model**: Add more URLs to improve accuracy
2. **Balance classes**: Equal phishing/legitimate samples
3. **Random seed**: Use `random_state=42` for reproducibility
4. **Feature scaling**: Always scale before training

---

*This documentation explains the `03_training/` folder for beginners.*
