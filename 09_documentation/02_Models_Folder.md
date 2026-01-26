# 02_models Folder Documentation

## Overview

The `02_models/` folder contains all trained machine learning models used by the phishing detection system. These models are the "brain" of the system - they make predictions about whether a URL is phishing or legitimate.

## Folder Structure

```
02_models/
├── phishing_classifier.joblib    # Main Random Forest model
├── feature_scaler.joblib         # StandardScaler for feature normalization
├── feature_columns.joblib        # List of feature names (in order)
└── classifier.py                 # Neural network model definition (optional)
```

---

## File Explanations

### 1. `phishing_classifier.joblib`

**What it is:** The trained Random Forest classifier model.

**Format:** Joblib serialized file (compressed Python object)

**Size:** ~5-10 MB

**How it was trained:**
- Algorithm: Random Forest with 100 trees
- Training data: 46,000+ phishing URLs + legitimate URLs
- Features: 17+ URL-based features
- Performance: **99.8% F1 Score**

**How it's used:**
```python
import joblib

# Load the model
model = joblib.load('02_models/phishing_classifier.joblib')

# Make prediction (0 = legitimate, 1 = phishing)
prediction = model.predict(features)

# Get probability
probability = model.predict_proba(features)
```

**Why Random Forest?**
- Fast inference (~1ms per URL)
- Works well with structured features
- No GPU required
- Handles missing values gracefully
- Provides feature importance

---

### 2. `feature_scaler.joblib`

**What it is:** A StandardScaler that normalizes input features.

**Why it's needed:**
Machine learning models work better when all features are on the same scale. For example:
- `url_length` might be 50-200
- `num_dots` might be 1-5
- `entropy` might be 2.0-5.0

Without scaling, features with larger values would dominate the model.

**How it works:**
```python
from sklearn.preprocessing import StandardScaler

# StandardScaler transforms each feature to have:
# - Mean = 0
# - Standard deviation = 1

# Formula: scaled_value = (value - mean) / std_dev
```

**How it's used:**
```python
import joblib

scaler = joblib.load('02_models/feature_scaler.joblib')

# Transform features before prediction
features_scaled = scaler.transform(features)
prediction = model.predict(features_scaled)
```

---

### 3. `feature_columns.joblib`

**What it is:** A list of feature names in the correct order.

**Why it's needed:**
The model expects features in a specific order. This file ensures we always provide features in the same order as during training.

**Contents:**
```python
[
    'url_length',
    'domain_length',
    'path_length',
    'num_dots',
    'num_hyphens',
    'num_underscores',
    'num_slashes',
    'num_question_marks',
    'num_equals',
    'num_at',
    'num_ampersand',
    'num_digits',
    'is_https',
    'has_port',
    'is_ip_address',
    'subdomain_count',
    'has_suspicious_words',
    'entropy',
    'domain_entropy',
    'max_consecutive_consonants',
    'max_consecutive_vowels',
    'vowel_ratio',
    'is_random_domain',
    'is_dictionary_word'
]
```

**How it's used:**
```python
import joblib

feature_cols = joblib.load('02_models/feature_columns.joblib')

# Create feature vector in correct order
feature_vector = []
for col in feature_cols:
    feature_vector.append(extracted_features.get(col, 0))
```

---

### 4. `classifier.py`

**What it is:** Python module defining a PyTorch neural network classifier.

**Note:** This is an alternative model, not the primary one used.

**Contents:**
```python
import torch.nn as nn
from transformers import BertModel

class PhishingClassifier(nn.Module):
    def __init__(self, model_name='bert-base-uncased', num_labels=2):
        super().__init__()
        self.bert = BertModel.from_pretrained(model_name)
        self.dropout = nn.Dropout(0.1)
        self.classifier = nn.Linear(self.bert.config.hidden_size, num_labels)
    
    def forward(self, input_ids, attention_mask):
        outputs = self.bert(input_ids, attention_mask=attention_mask)
        pooled_output = outputs.pooler_output
        pooled_output = self.dropout(pooled_output)
        logits = self.classifier(pooled_output)
        return logits
```

**Why it exists:**
- For MLLM-generated text classification
- Uses BERT to understand text descriptions
- Requires GPU for reasonable speed

---

## How Models are Loaded in Service

In `04_inference/service.py`:

```python
def __init__(self, load_ml_model=True):
    if load_ml_model:
        model_dir = '02_models'
        
        # Load all three files
        self.ml_model = joblib.load(f'{model_dir}/phishing_classifier.joblib')
        self.ml_scaler = joblib.load(f'{model_dir}/feature_scaler.joblib')
        self.ml_feature_cols = joblib.load(f'{model_dir}/feature_columns.joblib')
        
        self.ml_model_loaded = True
```

## Making Predictions

The complete prediction flow:

```
URL: "https://paypa1.com"
        │
        ▼
┌─────────────────────────────────┐
│ 1. EXTRACT FEATURES             │
│    URLFeatureExtractor          │
│                                 │
│    features = {                 │
│      'url_length': 21,          │
│      'domain_length': 6,        │
│      'is_https': 1,             │
│      ...                        │
│    }                            │
└─────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────┐
│ 2. CREATE FEATURE VECTOR        │
│                                 │
│    vector = []                  │
│    for col in feature_columns:  │
│        vector.append(           │
│            features.get(col, 0) │
│        )                        │
└─────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────┐
│ 3. SCALE FEATURES               │
│                                 │
│    vector_scaled =              │
│        scaler.transform(vector) │
└─────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────┐
│ 4. PREDICT                      │
│                                 │
│    prediction = model.predict() │
│    probability = model.         │
│        predict_proba()          │
│                                 │
│    Result: 1 (phishing)         │
│    Confidence: 0.95             │
└─────────────────────────────────┘
```

---

## Model Performance

| Metric | Score |
|--------|-------|
| Accuracy | 99.8% |
| F1 Score | 99.8% |
| Precision | 99.9% |
| Recall | 99.7% |

**Confusion Matrix:**
```
              Predicted
              Legit  Phishing
Actual Legit   498      2
     Phishing    3    497
```

- TN (True Negative): 498 - Correctly identified legitimate
- FP (False Positive): 2 - Legitimate marked as phishing
- FN (False Negative): 3 - Phishing marked as legitimate
- TP (True Positive): 497 - Correctly identified phishing

---

## How to Retrain

If you want to retrain the model with new data:

```bash
# Navigate to training folder
cd 03_training

# Run training script
python train_ml.py
```

This will:
1. Load data from `01_data/raw/`
2. Extract features
3. Train multiple models
4. Save the best one to `02_models/`

---

## Troubleshooting

### "Model file not found"
```bash
# Check if files exist
ls -la 02_models/

# If missing, retrain
python 03_training/train_ml.py
```

### "Feature mismatch error"
This happens when the feature extractor outputs different features than the model expects.
- Check `feature_columns.joblib` for expected features
- Update feature extractor if needed
- Retrain model if feature extraction changed

---

*This documentation explains the `02_models/` folder for beginners.*
