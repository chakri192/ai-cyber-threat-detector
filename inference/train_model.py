import hashlib
import os
import torch
import torch.nn as nn
import torch.optim as optim
import random
import string
import time

# 1. Advanced Neural Network Architecture (CNN)
class DGA_CNN(nn.Module):
    def __init__(self, vocab_size=39, embed_dim=32, num_classes=1):
        super(DGA_CNN, self).__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.conv1 = nn.Conv1d(in_channels=embed_dim, out_channels=128, kernel_size=3, padding=1)
        self.conv2 = nn.Conv1d(in_channels=128, out_channels=256, kernel_size=3, padding=1)
        self.relu = nn.ReLU()
        self.pool = nn.AdaptiveMaxPool1d(1)
        self.fc1 = nn.Linear(256, 128)
        self.fc2 = nn.Linear(128, num_classes)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        x = self.embedding(x)
        x = x.permute(0, 2, 1)
        x = self.relu(self.conv1(x))
        x = self.relu(self.conv2(x))
        x = self.pool(x).squeeze(2)
        x = self.relu(self.fc1(x))
        x = self.sigmoid(self.fc2(x))
        return x

# 2. Hardened Threat Generator (Synthetic dataset creation for ML training)
def generate_hard_dataset(num_samples=100000):
    char_map = {c: i+1 for i, c in enumerate(string.ascii_lowercase + string.digits + "-.")}
    benign_domains = ["google.com", "apple.com", "microsoft.com", "amazon.com", "netflix.com", "github.com", "ubuntu.com", "wikipedia.org", "yahoo.com", "linkedin.com"]
    words = ["login", "admin", "secure", "update", "verify", "account", "portal", "support", "billing", "auth"]

    data, labels = [], []
    for _ in range(num_samples // 2):
        # Generate Difficult Malicious Threats
        threat_type = random.random()  # nosec B311
        if threat_type < 0.33:
            # 1. Dictionary DGA (Looks like benign words)
            dga = f"{random.choice(words)}-{random.choice(words)}-{random.choice(words)}.com"  # nosec B311
        elif threat_type < 0.66:
            # 2. Homoglyph Attack (Typosquatting)
            base = random.choice(benign_domains)  # nosec B311
            dga = base.replace('o', '0').replace('l', '1').replace('i', '1').replace('e', '3')
            if dga == base:
                dga = "g00gle.com"
        else:
            # 3. Standard Corebot/Cryptolocker
            length = random.randint(15, 25)  # nosec B311
            dga = ''.join(random.choices(string.ascii_lowercase + string.digits, k=length)) + ".com"  # nosec B311

        data.append(dga)
        labels.append(1.0)

        # Generate Benign
        base = random.choice(benign_domains)  # nosec B311
        if random.random() > 0.5:  # nosec B311
            # Subdomains
            prefix = random.choice(["www", "api", "mail", "dev", "staging"])  # nosec B311
            data.append(f"{prefix}.{base}")
        else:
            data.append(base)
        labels.append(0.0)

    dataset = list(zip(data, labels))
    random.shuffle(dataset)  # nosec B311
    data, labels = zip(*dataset)

    max_len = 35
    encoded_data = []
    for d in data:
        encoded = [char_map.get(c, 0) for c in d.lower()]
        if len(encoded) < max_len:
            encoded += [0] * (max_len - len(encoded))
        encoded_data.append(encoded[:max_len])

    return torch.tensor(encoded_data, dtype=torch.long), torch.tensor(labels, dtype=torch.float32).unsqueeze(1)


def save_traced_model(traced_model, save_path):
    """Persist a traced model and its sidecar .sha256 together.

    Without the sidecar, the next DeepLearningEngine startup's (correctly
    fail-safe) integrity check finds a stale/missing .sha256, fails closed,
    and crash-loops the fleet. scripts/train_dl_models.py already does this
    correctly -- pulled out as its own function here so it's testable
    without running a full training loop.
    """
    traced_model.save(save_path)
    with open(save_path, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    with open(save_path + ".sha256", "w") as f:
        f.write(file_hash + "\n")
    return file_hash

def train_to_max():
    print("[*] Generating Hardened Training Dataset (100,000 domains)...")
    print("[*] Incorporating Dictionary DGAs and Homoglyph Attacks...")
    X, y = generate_hard_dataset(100000)

    split_idx = int(len(X) * 0.8)
    X_train, y_train = X[:split_idx], y[:split_idx]
    X_val, y_val = X[split_idx:], y[split_idx:]

    model = DGA_CNN()
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)

    print("\n[*] Commencing Maximum Precision Training Loop...")

    best_acc = 0.0
    target_acc = 99.95
    patience = 8
    epochs_no_improve = 0
    epoch = 0

    os.makedirs("models", exist_ok=True)

    while best_acc < target_acc and epochs_no_improve < patience and epoch < 50:
        epoch += 1
        model.train()
        optimizer.zero_grad()
        loss = criterion(model(X_train), y_train)
        loss.backward()
        optimizer.step()

        model.eval()
        with torch.no_grad():
            val_preds = model(X_val)
            val_loss = criterion(val_preds, y_val)
            predictions = (val_preds > 0.5).float()
            accuracy = (predictions == y_val).float().mean() * 100

        acc_val = accuracy.item()

        if acc_val > best_acc:
            print(f"    Epoch {epoch:02d} | Val Accuracy: {acc_val:.3f}% (NEW BEST) | Saved Weights")
            best_acc = acc_val
            epochs_no_improve = 0

            traced_model = torch.jit.trace(model, torch.zeros((1, 35), dtype=torch.long))
            save_path = "models/cnn_dga.pt"
            save_traced_model(traced_model, save_path)
        else:
            print(f"    Epoch {epoch:02d} | Val Accuracy: {acc_val:.3f}% (No improvement)")
            epochs_no_improve += 1

    print(f"\n[*] Training halted. Maximum achievable accuracy on Hard Dataset: {best_acc:.3f}%")
    print("[*] Best model weights locked into production.")

if __name__ == "__main__":
    train_to_max()
