#!/usr/bin/env python3
"""
Generate detailed architecture and component images for the project documentation
"""
from PIL import Image, ImageDraw, ImageFont
import os

# Create output directory
os.makedirs('viva/pdf_images_v2', exist_ok=True)

# Colors
COLORS = {
    'bg': (30, 60, 114),
    'light_bg': (70, 130, 180),
    'accent': (255, 200, 0),
    'white': (255, 255, 255),
    'green': (46, 204, 113),
    'red': (231, 76, 60),
    'orange': (243, 156, 18),
    'purple': (155, 89, 182),
    'cyan': (0, 188, 212),
    'gray': (150, 150, 150),
    'dark': (20, 40, 80)
}

def get_fonts():
    try:
        return {
            'title': ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 22),
            'subtitle': ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 16),
            'label': ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 12),
            'small': ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 10)
        }
    except:
        return {
            'title': ImageFont.load_default(),
            'subtitle': ImageFont.load_default(),
            'label': ImageFont.load_default(),
            'small': ImageFont.load_default()
        }

def create_system_architecture():
    """Complete system architecture diagram"""
    width, height = 1400, 1000
    img = Image.new('RGB', (width, height), color=COLORS['bg'])
    draw = ImageDraw.Draw(img)
    fonts = get_fonts()
    
    # Title bar
    draw.rectangle([0, 0, width, 50], fill=COLORS['light_bg'])
    draw.text((width//2 - 320, 12), "PHISHING GUARD - COMPREHENSIVE SYSTEM ARCHITECTURE", 
              fill=COLORS['white'], font=fonts['title'])
    
    # === USER INTERFACES (Left) ===
    x, y = 60, 80
    draw.rounded_rectangle([x, y, x+200, y+220], radius=10, fill=COLORS['cyan'], outline=COLORS['white'], width=2)
    draw.text((x+15, y+10), "USER INTERFACES", fill=COLORS['bg'], font=fonts['subtitle'])
    
    interfaces = [
        ("CLI Application", "demo.py, final_demo.py"),
        ("REST API", "FastAPI + Uvicorn"),
        ("Browser Extension", "Chrome/Manifest V3"),
        ("Desktop App", "Tauri + React"),
        ("Email Scanner", "IMAP Integration")
    ]
    for i, (name, desc) in enumerate(interfaces):
        draw.text((x+15, y+45 + i*40), f"• {name}", fill=COLORS['bg'], font=fonts['label'])
        draw.text((x+25, y+60 + i*40), desc, fill=COLORS['dark'], font=fonts['small'])
    
    # === PROCESSING LAYER (Center-Left) ===
    x = 300
    draw.rounded_rectangle([x, y, x+220, y+220], radius=10, fill=COLORS['purple'], outline=COLORS['white'], width=2)
    draw.text((x+15, y+10), "PROCESSING LAYER", fill=COLORS['white'], font=fonts['subtitle'])
    
    features = [
        ("Feature Extraction", "93 Features"),
        ("URL Analysis", "28 features"),
        ("Domain Features", "18 features"),
        ("Host Analysis", "10 features"),
        ("Security/TLS", "12 features"),
        ("IDN Detection", "11 features")
    ]
    for i, (name, count) in enumerate(features):
        draw.text((x+15, y+45 + i*28), f"• {name}", fill=COLORS['white'], font=fonts['label'])
        draw.text((x+25, y+60 + i*28), count, fill=COLORS['gray'], font=fonts['small'])
    
    # === ML/LLM LAYER (Center-Right) ===
    x = 550
    draw.rounded_rectangle([x, y, x+220, y+220], radius=10, fill=COLORS['green'], outline=COLORS['white'], width=2)
    draw.text((x+15, y+10), "ML & LLM LAYER", fill=COLORS['bg'], font=fonts['subtitle'])
    
    ml_items = [
        ("Random Forest", "200 trees, max_depth=20"),
        ("XGBoost", "50 estimators, max_depth=6"),
        ("Soft Voting", "Ensemble combining RF+XGB"),
        ("Qwen2.5-3B", "4-bit quantized LLM"),
        ("Accuracy", "99.64%"),
        ("F1 Score", "99.70%")
    ]
    for i, (name, value) in enumerate(ml_items):
        draw.text((x+15, y+45 + i*35), f"• {name}", fill=COLORS['bg'], font=fonts['label'])
        draw.text((x+25, y+60 + i*35), value, fill=COLORS['dark'], font=fonts['small'])
    
    # === SECURITY LAYER (Right) ===
    x = 800
    draw.rounded_rectangle([x, y, x+200, y+220], radius=10, fill=COLORS['red'], outline=COLORS['white'], width=2)
    draw.text((x+15, y+10), "SECURITY LAYER", fill=COLORS['white'], font=fonts['subtitle'])
    
    security = [
        ("JWT Authentication", "HS256, 24hr expiry"),
        ("API Key Auth", "SHA-256 hashed"),
        ("Rate Limiting", "100 req/min/IP"),
        ("SSRF Protection", "Private IP block"),
        ("TLS Validation", "TLS 1.2+ required"),
        ("Input Sanitization", "All inputs validated")
    ]
    for i, (name, value) in enumerate(security):
        draw.text((x+15, y+45 + i*35), f"• {name}", fill=COLORS['white'], font=fonts['label'])
        draw.text((x+25, y+60 + i*35), value, fill=COLORS['gray'], font=fonts['small'])
    
    # === DATA & TRAINING (Bottom Left) ===
    x, y = 60, 340
    draw.rounded_rectangle([x, y, x+300, y+180], radius=10, fill=COLORS['orange'], outline=COLORS['white'], width=2)
    draw.text((x+15, y+10), "DATA SOURCES & TRAINING", fill=COLORS['bg'], font=fonts['subtitle'])
    
    data = [
        ("PhishTank Dataset", "135,000+ phishing URLs"),
        ("OpenPhish", "15,000+ verified phishing"),
        ("Alexa Top Sites", "Legitimate websites"),
        ("Combined Dataset", "3.2MB training data"),
        ("Train/Test Split", "80/10/10 (train/val/test)")
    ]
    for i, (name, value) in enumerate(data):
        draw.text((x+15, y+40 + i*28), f"• {name}", fill=COLORS['bg'], font=fonts['label'])
        draw.text((x+25, y+55 + i*28), value, fill=COLORS['dark'], font=fonts['small'])
    
    # === CLASSIFICATION CATEGORIES (Bottom Center) ===
    x = 400
    draw.rounded_rectangle([x, y, x+320, y+180], radius=10, fill=COLORS['light_bg'], outline=COLORS['white'], width=2)
    draw.text((x+15, y+10), "4-CLASSIFICATION CATEGORIES", fill=COLORS['white'], font=fonts['subtitle'])
    
    categories = [
        ("LEGITIMATE", "Safe, trusted URLs", COLORS['green']),
        ("PHISHING", "Traditional phishing", COLORS['red']),
        ("AI_GENERATED", "LLM-created phishing", COLORS['orange']),
        ("PHISHING_KIT", "Automated phishing tools", COLORS['purple'])
    ]
    for i, (name, desc, color) in enumerate(categories):
        draw.text((x+15, y+40 + i*35), f"• {name}", fill=color, font=fonts['label'])
        draw.text((x+25, y+55 + i*35), desc, fill=COLORS['gray'], font=fonts['small'])
    
    # === DETECTION TECHNIQUES (Bottom Right) ===
    x = 760
    draw.rounded_rectangle([x, y, x+300, y+180], radius=10, fill=COLORS['accent'], outline=COLORS['white'], width=2)
    draw.text((x+15, y+10), "ADVANCED DETECTION TECHNIQUES", fill=COLORS['dark'], font=fonts['subtitle'])
    
    techniques = [
        ("IDN/Homograph Detection", "Punycode, mixed scripts"),
        ("Typosquatting", "Levenshtein, homoglyphs"),
        ("TLS Analysis", "Certificate validation"),
        ("Content Analysis", "Web scraping, DOM"),
        ("Behavioral Analysis", "URL patterns")
    ]
    for i, (name, value) in enumerate(techniques):
        draw.text((x+15, y+40 + i*28), f"• {name}", fill=COLORS['dark'], font=fonts['label'])
        draw.text((x+25, y+55 + i*28), value, fill=COLORS['dark'], font=fonts['small'])
    
    # === ARROWS/CONNECTIONS ===
    # Main flow arrows
    arrow_y = 190
    # User -> Processing
    draw.line([260, arrow_y, 300, arrow_y], fill=COLORS['white'], width=3)
    # Processing -> ML
    draw.line([520, arrow_y, 550, arrow_y], fill=COLORS['white'], width=3)
    # ML -> Security
    draw.line([770, arrow_y, 800, arrow_y], fill=COLORS['white'], width=3)
    # Processing -> Data (vertical)
    draw.line([410, 300, 410, 340], fill=COLORS['white'], width=3)
    # Processing -> Categories
    draw.line([560, 300, 560, 340], fill=COLORS['white'], width=3)
    
    img.save('viva/pdf_images_v2/system_architecture.png')
    print("✓ Created system_architecture.png")

def create_dataset_diagram():
    """Dataset sources and processing diagram"""
    width, height = 1200, 700
    img = Image.new('RGB', (width, height), color=COLORS['bg'])
    draw = ImageDraw.Draw(img)
    fonts = get_fonts()
    
    # Title
    draw.rectangle([0, 0, width, 50], fill=COLORS['light_bg'])
    draw.text((width//2 - 200, 12), "DATASET SOURCES & PROCESSING PIPELINE", 
              fill=COLORS['white'], font=fonts['title'])
    
    # Raw Data Sources (Top)
    y = 80
    
    # PhishTank
    x = 50
    draw.rounded_rectangle([x, y, x+180, y+150], radius=10, fill=COLORS['red'], outline=COLORS['white'], width=2)
    draw.text((x+20, y+10), "PhishTank", fill=COLORS['white'], font=fonts['subtitle'])
    draw.text((x+15, y+40), "Source: phishtank.com", fill=COLORS['white'], font=fonts['small'])
    draw.text((x+15, y+60), "URLs: 135,000+", fill=COLORS['white'], font=fonts['small'])
    draw.text((x+15, y+80), "Status: Verified", fill=COLORS['white'], font=fonts['small'])
    draw.text((x+15, y+100), "Format: CSV", fill=COLORS['white'], font=fonts['small'])
    draw.text((x+15, y+120), "Size: ~9.3MB", fill=COLORS['white'], font=fonts['small'])
    
    # OpenPhish
    x = 280
    draw.rounded_rectangle([x, y, x+180, y+150], radius=10, fill=COLORS['orange'], outline=COLORS['white'], width=2)
    draw.text((x+30, y+10), "OpenPhish", fill=COLORS['white'], font=fonts['subtitle'])
    draw.text((x+15, y+40), "Source: openphish.com", fill=COLORS['white'], font=fonts['small'])
    draw.text((x+15, y+60), "URLs: 15,000+", fill=COLORS['white'], font=fonts['small'])
    draw.text((x+15, y+80), "Status: Verified", fill=COLORS['white'], font=fonts['small'])
    draw.text((x+15, y+100), "Format: TXT", fill=COLORS['white'], font=fonts['small'])
    draw.text((x+15, y+120), "Size: ~19KB", fill=COLORS['white'], font=fonts['small'])
    
    # Legitimate Sites
    x = 510
    draw.rounded_rectangle([x, y, x+180, y+150], radius=10, fill=COLORS['green'], outline=COLORS['white'], width=2)
    draw.text((x+20, y+10), "Legitimate Sites", fill=COLORS['bg'], font=fonts['subtitle'])
    draw.text((x+15, y+40), "Source: Alexa Top 1M", fill=COLORS['bg'], font=fonts['small'])
    draw.text((x+15, y+60), "URLs: 50,000+", fill=COLORS['bg'], font=fonts['small'])
    draw.text((x+15, y+80), "Status: Trusted", fill=COLORS['bg'], font=fonts['small'])
    draw.text((x+15, y+100), "Format: CSV", fill=COLORS['bg'], font=fonts['small'])
    draw.text((x+15, y+120), "Updated: Daily", fill=COLORS['bg'], font=fonts['small'])
    
    # External Data
    x = 740
    draw.rounded_rectangle([x, y, x+180, y+150], radius=10, fill=COLORS['cyan'], outline=COLORS['white'], width=2)
    draw.text((x+30, y+10), "External Data", fill=COLORS['bg'], font=fonts['subtitle'])
    draw.text((x+15, y+40), "Source: Kaggle, UCI", fill=COLORS['bg'], font=fonts['small'])
    draw.text((x+15, y+60), "URLs: 10,000+", fill=COLORS['bg'], font=fonts['small'])
    draw.text((x+15, y+80), "Status: Labeled", fill=COLORS['bg'], font=fonts['small'])
    draw.text((x+15, y+100), "Format: CSV", fill=COLORS['bg'], font=fonts['small'])
    draw.text((x+15, y+120), "Size: ~1MB", fill=COLORS['bg'], font=fonts['small'])
    
    # Arrow to Processing
    draw.line([600, 230, 600, 270], fill=COLORS['white'], width=3)
    draw.polygon([600, 270, 595, 255, 605, 255], fill=COLORS['white'])
    
    # Data Processing (Middle)
    x = 450
    y = 280
    draw.rounded_rectangle([x, y, x+300, y+120], radius=10, fill=COLORS['purple'], outline=COLORS['white'], width=2)
    draw.text((x+60, y+10), "DATA PROCESSING PIPELINE", fill=COLORS['white'], font=fonts['subtitle'])
    draw.text((x+15, y+40), "1. URL Normalization & Cleaning", fill=COLORS['white'], font=fonts['label'])
    draw.text((x+15, y+60), "2. Duplicate Removal & Deduplication", fill=COLORS['white'], font=fonts['label'])
    draw.text((x+15, y+80), "3. Label Encoding (0=Legit, 1=Phish)", fill=COLORS['white'], font=fonts['label'])
    draw.text((x+15, y+100), "4. Feature Extraction & Storage", fill=COLORS['white'], font=fonts['label'])
    
    # Arrow to Combined
    draw.line([600, 400, 600, 440], fill=COLORS['white'], width=3)
    
    # Combined Dataset
    x = 450
    y = 450
    draw.rounded_rectangle([x, y, x+300, y+140], radius=10, fill=COLORS['accent'], outline=COLORS['white'], width=2)
    draw.text((x+70, y+10), "COMBINED DATASET", fill=COLORS['bg'], font=fonts['subtitle'])
    draw.text((x+15, y+40), "File: combined_dataset.csv", fill=COLORS['bg'], font=fonts['label'])
    draw.text((x+15, y+60), "Total URLs: 200,000+", fill=COLORS['bg'], font=fonts['label'])
    draw.text((x+15, y+80), "Size: ~3.2MB", fill=COLORS['bg'], font=fonts['label'])
    draw.text((x+15, y+100), "Phishing: ~50%", fill=COLORS['red'], font=fonts['label'])
    draw.text((x+15, y+120), "Legitimate: ~50%", fill=COLORS['green'], font=fonts['label'])
    
    # Arrow to splits
    draw.line([750, 520, 900, 520], fill=COLORS['white'], width=3)
    draw.polygon([900, 520, 885, 517, 885, 523], fill=COLORS['white'])
    
    # Train/Val/Test Split
    x = 950
    y = 450
    draw.rounded_rectangle([x, y, x+180, y+140], radius=10, fill=COLORS['light_bg'], outline=COLORS['white'], width=2)
    draw.text((x+30, y+10), "DATA SPLITS", fill=COLORS['white'], font=fonts['subtitle'])
    draw.text((x+15, y+40), "Train: 80%", fill=COLORS['green'], font=fonts['label'])
    draw.text((x+15, y+60), "Val: 10%", fill=COLORS['orange'], font=fonts['label'])
    draw.text((x+15, y+80), "Test: 10%", fill=COLORS['cyan'], font=fonts['label'])
    draw.text((x+15, y+100), "Stratified", fill=COLORS['white'], font=fonts['small'])
    draw.text((x+15, y+120), "Shuffle: True", fill=COLORS['white'], font=fonts['small'])
    
    img.save('viva/pdf_images_v2/dataset_sources.png')
    print("✓ Created dataset_sources.png")

def create_ml_pipeline():
    """ML training pipeline diagram"""
    width, height = 1200, 700
    img = Image.new('RGB', (width, height), color=COLORS['bg'])
    draw = ImageDraw.Draw(img)
    fonts = get_fonts()
    
    # Title
    draw.rectangle([0, 0, width, 50], fill=COLORS['light_bg'])
    draw.text((width//2 - 180, 12), "ML TRAINING PIPELINE WITH MLFLOW", 
              fill=COLORS['white'], font=fonts['title'])
    
    # Data Input
    x, y = 50, 100
    draw.rounded_rectangle([x, y, x+180, y+180], radius=10, fill=COLORS['orange'], outline=COLORS['white'], width=2)
    draw.text((x+30, y+10), "INPUT DATA", fill=COLORS['bg'], font=fonts['subtitle'])
    draw.text((x+15, y+40), "train.csv", fill=COLORS['bg'], font=fonts['label'])
    draw.text((x+15, y+60), "2,589,050 bytes", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+15, y+90), "val.csv", fill=COLORS['bg'], font=fonts['label'])
    draw.text((x+15, y+110), "315,132 bytes", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+15, y+140), "test.csv", fill=COLORS['bg'], font=fonts['label'])
    draw.text((x+15, y+160), "317,364 bytes", fill=COLORS['dark'], font=fonts['small'])
    
    # Arrow
    draw.line([230, 190, 280, 190], fill=COLORS['white'], width=3)
    
    # Feature Extraction
    x = 280
    draw.rounded_rectangle([x, y, x+180, y+180], radius=10, fill=COLORS['purple'], outline=COLORS['white'], width=2)
    draw.text((x+20, y+10), "FEATURE", fill=COLORS['white'], font=fonts['subtitle'])
    draw.text((x+50, y+30), "EXTRACTION", fill=COLORS['white'], font=fonts['subtitle'])
    draw.text((x+15, y+60), "URLFeatureExtractor", fill=COLORS['white'], font=fonts['label'])
    draw.text((x+15, y+80), "93 features total:", fill=COLORS['gray'], font=fonts['small'])
    draw.text((x+15, y+100), "- URL patterns (28)", fill=COLORS['gray'], font=fonts['small'])
    draw.text((x+15, y+115), "- Domain (18)", fill=COLORS['gray'], font=fonts['small'])
    draw.text((x+15, y+130), "- Host (10)", fill=COLORS['gray'], font=fonts['small'])
    draw.text((x+15, y+145), "- Security (12)", fill=COLORS['gray'], font=fonts['small'])
    draw.text((x+15, y+160), "- IDN (11)", fill=COLORS['gray'], font=fonts['small'])
    
    # Arrow
    draw.line([460, 190, 510, 190], fill=COLORS['white'], width=3)
    
    # Scaling
    x = 510
    draw.rounded_rectangle([x, y, x+150, y+180], radius=10, fill=COLORS['cyan'], outline=COLORS['white'], width=2)
    draw.text((x+30, y+10), "FEATURE", fill=COLORS['bg'], font=fonts['subtitle'])
    draw.text((x+40, y+30), "SCALING", fill=COLORS['bg'], font=fonts['subtitle'])
    draw.text((x+15, y+60), "StandardScaler", fill=COLORS['bg'], font=fonts['label'])
    draw.text((x+15, y+80), "fit_transform()", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+15, y+110), "Saves scaler for", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+15, y+130), "inference time", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+15, y+155), "joblib.dump()", fill=COLORS['dark'], font=fonts['small'])
    
    # Arrow
    draw.line([660, 190, 710, 190], fill=COLORS['white'], width=3)
    
    # Models Training
    x = 710
    draw.rounded_rectangle([x, y, x+220, y+180], radius=10, fill=COLORS['green'], outline=COLORS['white'], width=2)
    draw.text((x+30, y+10), "MODEL TRAINING", fill=COLORS['bg'], font=fonts['subtitle'])
    
    # Random Forest
    draw.rectangle([x+10, y+40, x+210, y+75], fill=(46, 125, 50), outline=COLORS['white'])
    draw.text((x+20, y+50), "Random Forest", fill=COLORS['white'], font=fonts['label'])
    draw.text((x+130, y+50), "200 trees", fill=COLORS['gray'], font=fonts['small'])
    
    # XGBoost
    draw.rectangle([x+10, y+80, x+210, y+115], fill=(39, 105, 25), outline=COLORS['white'])
    draw.text((x+20, y+90), "XGBoost", fill=COLORS['white'], font=fonts['label'])
    draw.text((x+140, y+90), "50 estimators", fill=COLORS['gray'], font=fonts['small'])
    
    # Ensemble
    draw.rectangle([x+10, y+120, x+210, y+155], fill=(27, 77, 18), outline=COLORS['white'])
    draw.text((x+20, y+130), "Soft Voting", fill=COLORS['white'], font=fonts['label'])
    draw.text((x+140, y+130), "RF + XGB avg", fill=COLORS['gray'], font=fonts['small'])
    
    # Arrow down
    draw.line([820, 280, 820, 340], fill=COLORS['white'], width=3)
    draw.polygon([820, 340, 815, 325, 825, 325], fill=COLORS['white'])
    
    # MLflow Tracking
    x = 710
    y = 350
    draw.rounded_rectangle([x, y, x+220, y+160], radius=10, fill=COLORS['accent'], outline=COLORS['white'], width=2)
    draw.text((x+20, y+10), "MLFLOW TRACKING", fill=COLORS['bg'], font=fonts['subtitle'])
    draw.text((x+15, y+40), "Experiment: phishing_detection", fill=COLORS['bg'], font=fonts['small'])
    draw.text((x+15, y+60), "Metrics Logged:", fill=COLORS['bg'], font=fonts['small'])
    draw.text((x+25, y+80), "- Accuracy", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+25, y+95), "- Precision", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+25, y+110), "- Recall", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+25, y+125), "- F1 Score", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+25, y+140), "- ROC-AUC", fill=COLORS['dark'], font=fonts['small'])
    
    # Arrow to models
    draw.line([820, 510, 820, 560], fill=COLORS['white'], width=3)
    
    # Output Models
    x = 710
    y = 570
    draw.rounded_rectangle([x, y, x+220, y+100], radius=10, fill=COLORS['light_bg'], outline=COLORS['white'], width=2)
    draw.text((x+20, y+10), "TRAINED MODELS", fill=COLORS['white'], font=fonts['subtitle'])
    draw.text((x+15, y+40), "phishing_classifier.joblib", fill=COLORS['white'], font=fonts['small'])
    draw.text((x+15, y+55), "feature_scaler.joblib", fill=COLORS['white'], font=fonts['small'])
    draw.text((x+15, y+70), "feature_columns.joblib", fill=COLORS['white'], font=fonts['small'])
    draw.text((x+15, y+85), "model_metrics.json", fill=COLORS['white'], font=fonts['small'])
    
    # Right side - Performance
    x = 950
    y = 100
    draw.rounded_rectangle([x, y, x+200, y+250], radius=10, fill=COLORS['green'], outline=COLORS['white'], width=2)
    draw.text((x+30, y+10), "PERFORMANCE", fill=COLORS['bg'], font=fonts['subtitle'])
    draw.text((x+15, y+40), "Random Forest:", fill=COLORS['bg'], font=fonts['label'])
    draw.text((x+25, y+60), "Accuracy: 99.64%", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+25, y+75), "F1: 99.70%", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+15, y+100), "XGBoost:", fill=COLORS['bg'], font=fonts['label'])
    draw.text((x+25, y+120), "Accuracy: 99.58%", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+25, y+135), "F1: 99.62%", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+15, y+160), "Ensemble:", fill=COLORS['bg'], font=fonts['label'])
    draw.text((x+25, y+180), "Accuracy: 99.70%", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+25, y+195), "F1: 99.82%", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+25, y+220), "Best: Ensemble", fill=COLORS['red'], font=fonts['small'])
    
    img.save('viva/pdf_images_v2/ml_pipeline.png')
    print("✓ Created ml_pipeline.png")

if __name__ == "__main__":
    create_system_architecture()
    create_dataset_diagram()
    create_ml_pipeline()
    print("\nAll images created successfully!")
