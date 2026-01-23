import json
import os
from pathlib import Path
from tqdm import tqdm
from mllm_transformer import MLLMFeatureTransformer

class TextFeatureGenerator:
    def __init__(self, data_dir="./01_data/processed/metadata"):
        self.data_dir = Path(data_dir)
        self.output_dir = self.data_dir.parent / "mllm_features"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        print("Loading MLLM (this may take a while)...")
        self.transformer = MLLMFeatureTransformer()
        print("MLLM loaded successfully.")

    def generate_features(self):
        files = list(self.data_dir.glob("*.json"))
        print(f"Found {len(files)} metadata files to process.")
        
        results = []
        
        for file_path in tqdm(files, desc="Generating text features"):
            with open(file_path, 'r') as f:
                metadata = json.load(f)
            
            idx = metadata.get('idx')
            output_path = self.output_dir / f"{idx}_mllm.json"
            
            # Skip if already exists (Resumable)
            if output_path.exists():
                continue
            
            try:
                # Generate text description
                description = self.transformer.transform_to_text(metadata)
                
                # Create result object
                result = {
                    'idx': idx,
                    'url': metadata.get('url'),
                    'label': metadata.get('label'),
                    'text_description': description,
                    'original_metadata_path': str(file_path)
                }
                
                # Save individual result
                output_path = self.output_dir / f"{idx}_mllm.json"
                with open(output_path, 'w') as f:
                    json.dump(result, f, indent=2)
                
                results.append(result)
                
            except Exception as e:
                print(f"Error processing {file_path}: {e}")
        
        return results

if __name__ == "__main__":
    generator = TextFeatureGenerator()
    generator.generate_features()
