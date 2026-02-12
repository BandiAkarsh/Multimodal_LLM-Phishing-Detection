# Staged Data Processing Script
# This script handles large-scale data processing in batches
# Use this for production data processing (not interactive)

import sys
import os
import yaml
import asyncio
import pandas as pd
import requests
from tqdm import tqdm
from pathlib import Path

# Add utils to path
sys.path.append(os.path.abspath('../05_utils'))
from data_preparation import DataPreprocessor

def check_url_active(url, timeout=5):
    """Check if URL is reachable"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        response = requests.head(url, timeout=timeout, allow_redirects=True)
        return response.status_code < 400
    except:
        return False

def filter_active_urls(df, max_check=1000):
    """Filter dataframe to keep only active URLs"""
    active_urls = []
    check_df = df.head(max_check)
    
    for idx, row in tqdm(check_df.iterrows(), total=len(check_df), desc="Checking URLs"):
        if check_url_active(row['url']):
            active_urls.append(row)
    
    return pd.DataFrame(active_urls)

def main():
    print("="*60)
    print("STAGED DATA PROCESSING")
    print("="*60)
    
    # Load configuration
    with open('../07_configs/config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    print("\n✅ Configuration loaded")
    
    # Load training data
    train_df = pd.read_csv('../01_data/splits/train.csv')
    print(f"\n📊 Training data: {len(train_df):,} samples")
    print(f"  - Phishing: {sum(train_df['label'] == 1)}")
    print(f"  - Legitimate: {sum(train_df['label'] == 0)}")
    
    # Add legitimate URLs
    legitimate_urls = [
        "https://www.google.com",
        "https://www.github.com",
        "https://www.microsoft.com",
        "https://www.apple.com",
        "https://www.amazon.com",
        # Add more as needed
    ]
    
    legit_df = pd.DataFrame({
        'url': legitimate_urls,
        'label': 0
    })
    
    print(f"\n✅ Added {len(legit_df)} legitimate URLs")
    
    # Create balanced dataset
    balanced_df = pd.concat([train_df, legit_df], ignore_index=True)
    balanced_df = balanced_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"\n✅ Balanced dataset: {len(balanced_df)} samples")
    
    # Initialize preprocessor
    preprocessor = DataPreprocessor(config)
    print("\n✅ Preprocessor initialized")
    
    # Process in batches
    BATCH_SIZE = 50
    total_samples = len(balanced_df)
    
    print(f"\n🔄 Processing {total_samples} URLs in batches of {BATCH_SIZE}...")
    
    for batch_start in range(0, total_samples, BATCH_SIZE):
        batch_end = min(batch_start + BATCH_SIZE, total_samples)
        batch_num = batch_start // BATCH_SIZE + 1
        
        print(f"\n{'='*60}")
        print(f"Batch {batch_num}/{(total_samples + BATCH_SIZE - 1) // BATCH_SIZE}")
        print(f"Processing samples {batch_start} to {batch_end}")
        print(f"{'='*60}")
        
        # Create temporary CSV for this batch
        batch_df = balanced_df.iloc[batch_start:batch_end]
        batch_csv = f'../01_data/splits/temp_batch_{batch_num}.csv'
        batch_df.to_csv(batch_csv, index=False)
        
        # Process batch
        try:
            loop = asyncio.get_event_loop()
            results = loop.run_until_complete(
                preprocessor.process_dataset(csv_path=batch_csv, max_samples=BATCH_SIZE)
            )
            
            print(f"\n✅ Batch {batch_num} complete:")
            print(f"  Success: {sum(results['success'])}")
            print(f"  Failed: {len(results) - sum(results['success'])}")
            
            # Save batch results
            results_path = f'../01_data/processed/batch_{batch_num}_results.csv'
            results.to_csv(results_path, index=False)
            
        except Exception as e:
            print(f"\n❌ Batch {batch_num} failed: {e}")
        
        finally:
            # Clean up temp file
            if os.path.exists(batch_csv):
                os.remove(batch_csv)
    
    print("\n" + "="*60)
    print("PROCESSING COMPLETE")
    print("="*60)

if __name__ == "__main__":
    main()
