import os
import sys
import json
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader, random_split
from torch.optim import AdamW
from transformers import DistilBertTokenizer, DistilBertModel
from tqdm import tqdm
from pathlib import Path

# ============== DATASET ==============
class PhishingDataset(Dataset):
    def __init__(self, features_dir, tokenizer, max_length=256):
        self.features_dir = Path(features_dir)
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.files = list(self.features_dir.glob("*_mllm.json"))
        print(f"Found {len(self.files)} samples")
        
    def __len__(self):
        return len(self.files)
    
    def __getitem__(self, idx):
        file_path = self.files[idx]
        with open(file_path, 'r') as f:
            data = json.load(f)
            
        text = data.get('text_description', '')[:1000]  # Truncate for speed
        label = int(data.get('label', 0))
        
        encoding = self.tokenizer(
            text,
            add_special_tokens=True,
            max_length=self.max_length,
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

# ============== MODEL ==============
class PhishingClassifier(nn.Module):
    def __init__(self, num_classes=2):
        super(PhishingClassifier, self).__init__()
        self.bert = DistilBertModel.from_pretrained('distilbert-base-uncased')
        self.dropout = nn.Dropout(0.1)
        self.classifier = nn.Linear(self.bert.config.hidden_size, num_classes)
        
    def forward(self, input_ids, attention_mask):
        outputs = self.bert(input_ids=input_ids, attention_mask=attention_mask)
        pooled_output = outputs.last_hidden_state[:, 0]  # CLS token
        pooled_output = self.dropout(pooled_output)
        logits = self.classifier(pooled_output)
        return logits

# ============== TRAINING ==============
def train():
    print("=" * 50)
    print("PHISHING CLASSIFIER TRAINING")
    print("=" * 50)
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")
    
    # Paths
    data_dir = "./01_data/processed/mllm_features"
    output_dir = "./02_models"
    os.makedirs(output_dir, exist_ok=True)
    
    # Hyperparameters
    batch_size = 2
    epochs = 3
    learning_rate = 2e-5
    
    # Load tokenizer
    print("Loading tokenizer...")
    tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')
    
    # Load dataset
    print("Loading dataset...")
    dataset = PhishingDataset(data_dir, tokenizer, max_length=256)
    
    if len(dataset) < 2:
        print("ERROR: Not enough samples to train. Need at least 2 samples.")
        return
    
    # Split
    train_size = max(1, int(0.8 * len(dataset)))
    val_size = len(dataset) - train_size
    train_dataset, val_dataset = random_split(dataset, [train_size, val_size])
    
    print(f"Train samples: {len(train_dataset)}, Val samples: {len(val_dataset)}")
    
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size)
    
    # Load model
    print("Loading model...")
    model = PhishingClassifier(num_classes=2)
    model.to(device)
    print("Model loaded successfully!")
    
    # Optimizer
    optimizer = AdamW(model.parameters(), lr=learning_rate)
    criterion = nn.CrossEntropyLoss()
    
    # Training loop
    best_val_loss = float('inf')
    
    for epoch in range(epochs):
        print(f"\n--- Epoch {epoch + 1}/{epochs} ---")
        
        # Train
        model.train()
        train_loss = 0
        for batch in tqdm(train_loader, desc="Training"):
            input_ids = batch['input_ids'].to(device)
            attention_mask = batch['attention_mask'].to(device)
            labels = batch['labels'].to(device)
            
            optimizer.zero_grad()
            outputs = model(input_ids, attention_mask)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()
            train_loss += loss.item()
        
        avg_train_loss = train_loss / len(train_loader)
        print(f"Train Loss: {avg_train_loss:.4f}")
        
        # Validate
        if len(val_loader) > 0:
            model.eval()
            val_loss = 0
            correct = 0
            total = 0
            
            with torch.no_grad():
                for batch in val_loader:
                    input_ids = batch['input_ids'].to(device)
                    attention_mask = batch['attention_mask'].to(device)
                    labels = batch['labels'].to(device)
                    
                    outputs = model(input_ids, attention_mask)
                    loss = criterion(outputs, labels)
                    val_loss += loss.item()
                    
                    _, predicted = torch.max(outputs, 1)
                    total += labels.size(0)
                    correct += (predicted == labels).sum().item()
            
            avg_val_loss = val_loss / len(val_loader)
            accuracy = correct / total if total > 0 else 0
            print(f"Val Loss: {avg_val_loss:.4f}, Accuracy: {accuracy:.4f}")
            
            if avg_val_loss < best_val_loss:
                best_val_loss = avg_val_loss
                torch.save(model.state_dict(), os.path.join(output_dir, "best_model.pth"))
                print("Saved best model!")
    
    # Save final model
    torch.save(model.state_dict(), os.path.join(output_dir, "final_model.pth"))
    print(f"\nTraining complete! Model saved to {output_dir}/final_model.pth")

if __name__ == "__main__":
    train()
