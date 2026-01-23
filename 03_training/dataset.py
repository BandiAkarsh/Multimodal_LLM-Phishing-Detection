import json
import torch
from torch.utils.data import Dataset
from pathlib import Path

class PhishingDataset(Dataset):
    def __init__(self, features_dir, tokenizer, max_length=512):
        self.features_dir = Path(features_dir)
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.files = list(self.features_dir.glob("*_mllm.json"))
        
    def __len__(self):
        return len(self.files)
    
    def __getitem__(self, idx):
        file_path = self.files[idx]
        with open(file_path, 'r') as f:
            data = json.load(f)
            
        text = data.get('text_description', '')
        label = int(data.get('label', 0))
        
        encoding = self.tokenizer(
            text,
            add_special_tokens=True,
            max_length=self.max_length,
            return_token_type_ids=False,
            padding='max_length',
            truncation=True,
            return_attention_mask=True,
            return_tensors='pt',
        )
        
        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'labels': torch.tensor(label, dtype=torch.long)
        }
