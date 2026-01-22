import os
import json
import pandas as pd
from pathlib import Path
from tqdm import tqdm
from scraper import WebScraper
from feature_extraction import URLFeatureExtractor

class DataPreprocessor:
    """Preprocess URLs and extract multimodal features"""
    
    def __init__(self, config):
        self.config = config
        self.scraper = WebScraper(headless=True, timeout=30)
        self.url_extractor = URLFeatureExtractor()
        
        # Create output directories
        self.processed_dir = Path(config['data']['processed_dir'])
        self.screenshots_dir = self.processed_dir / 'screenshots'
        self.html_dir = self.processed_dir / 'html'
        self.metadata_dir = self.processed_dir / 'metadata'
        
        for dir_path in [self.screenshots_dir, self.html_dir, self.metadata_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
    
    def process_dataset(self, csv_path, max_samples=None):
        """
        Process a dataset CSV and extract all modalities
        
        Args:
            csv_path: Path to CSV file with 'url' and 'label' columns
            max_samples: Maximum number of samples to process (None for all)
        """
        # Load dataset
        df = pd.read_csv(csv_path)
        
        if max_samples:
            df = df.head(max_samples)
        
        results = []
        
        for idx, row in tqdm(df.iterrows(), total=len(df), desc="Processing URLs"):
            url = row['url']
            label = row['label']
            
            # Scrape multimodal data
            scraped_data = self.scraper.scrape_url(url)
            
            if scraped_data['success']:
                # Save screenshot
                screenshot_path = self.screenshots_dir / f"{idx}.png"
                scraped_data['screenshot'].save(screenshot_path)
                
                # Save HTML
                html_path = self.html_dir / f"{idx}.html"
                with open(html_path, 'w', encoding='utf-8') as f:
                    f.write(scraped_data['html'])
                
                # Extract URL features
                url_features = self.url_extractor.extract_features(url)
                
                # Save metadata
                metadata = {
                    'idx': idx,
                    'url': url,
                    'label': label,
                    'screenshot_path': str(screenshot_path),
                    'html_path': str(html_path),
                    'dom_structure': scraped_data['dom_structure'],
                    'url_features': url_features
                }
                
                metadata_path = self.metadata_dir / f"{idx}.json"
                with open(metadata_path, 'w') as f:
                    json.dump(metadata, f, indent=2)
                
                results.append({
                    'idx': idx,
                    'url': url,
                    'label': label,
                    'success': True
                })
            else:
                results.append({
                    'idx': idx,
                    'url': url,
                    'label': label,
                    'success': False
                })
        
        # Save results summary
        results_df = pd.DataFrame(results)
        results_df.to_csv(self.processed_dir / 'processing_results.csv', index=False)
        
        print(f"\nProcessing complete:")
        print(f"Total: {len(results)}")
        print(f"Success: {sum(1 for r in results if r['success'])}")
        print(f"Failed: {sum(1 for r in results if not r['success'])}")
        
        self.scraper.close()
        
        return results_df
