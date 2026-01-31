import os
import sys
import torch
from torch.utils.data import DataLoader, random_split
from torch.optim import AdamW
from transformers import AutoTokenizer, get_linear_schedule_with_warmup
from tqdm import tqdm
import argparse

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)

# Handle imports from directories starting with digits using importlib or sys.path modification
import importlib.util

def import_module_from_path(module_name, file_path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module

classifier_module = import_module_from_path('classifier', os.path.join(project_root, '02_models/classifier.py'))
PhishingClassifier = classifier_module.PhishingClassifier

dataset_module = import_module_from_path('dataset', os.path.join(project_root, '03_training/dataset.py'))
PhishingDataset = dataset_module.PhishingDataset

def train(args):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")
    
    # Initialize tokenizer
    tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
    
    # Load dataset
    dataset = PhishingDataset(
        features_dir=args.data_dir,
        tokenizer=tokenizer,
        max_length=512
    )
    
    # Split dataset
    train_size = int(0.8 * len(dataset))
    val_size = len(dataset) - train_size
    train_dataset, val_dataset = random_split(dataset, [train_size, val_size])
    
    train_loader = DataLoader(train_dataset, batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=args.batch_size)
    
    # Initialize model
    model = PhishingClassifier(model_name="bert-base-uncased", num_classes=2)
    model.to(device)
    
    # Optimizer and Scheduler
    optimizer = AdamW(model.parameters(), lr=args.learning_rate)
    total_steps = len(train_loader) * args.epochs
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=0,
        num_training_steps=total_steps
    )
    
    # Loss function
    criterion = torch.nn.CrossEntropyLoss()
    
    # Training Loop
    best_val_loss = float('inf')
    
    for epoch in range(args.epochs):
        print(f"Epoch {epoch + 1}/{args.epochs}")
        
        # Training
        model.train()
        train_loss = 0
        for batch in tqdm(train_loader, desc="Training"):
            input_ids = batch['input_ids'].to(device)
            attention_mask = batch['attention_mask'].to(device)
            labels = batch['labels'].to(device)
            
            model.zero_grad()
            outputs = model(input_ids, attention_mask)
            loss = criterion(outputs, labels)
            
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            
            train_loss += loss.item()
            
        avg_train_loss = train_loss / len(train_loader)
        print(f"Average training loss: {avg_train_loss}")
        
        # Validation
        model.eval()
        val_loss = 0
        correct = 0
        total = 0
        
        with torch.no_grad():
            for batch in tqdm(val_loader, desc="Validation"):
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
        accuracy = correct / total
        print(f"Validation Loss: {avg_val_loss}")
        print(f"Validation Accuracy: {accuracy}")
        
        # Save best model
        if avg_val_loss < best_val_loss:
            best_val_loss = avg_val_loss
            torch.save(model.state_dict(), os.path.join(args.output_dir, "best_model.pth"))
            print("Saved best model.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data_dir", type=str, default="./01_data/processed/mllm_features")
    parser.add_argument("--output_dir", type=str, default="./02_models")
    parser.add_argument("--batch_size", type=int, default=8)
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--learning_rate", type=float, default=2e-5)
    
    args = parser.parse_args()
    os.makedirs(args.output_dir, exist_ok=True)
    train(args)
