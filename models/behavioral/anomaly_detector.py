"""
Behavioral Anomaly Detection Model (PyTorch)
Autoencoder-based anomaly detection for UEBA.
"""
import torch
import torch.nn as nn
import numpy as np
from typing import List, Dict, Any

class BehavioralAutoencoder(nn.Module):
    def __init__(self, input_dim: int = 8, hidden_dim: int = 16, latent_dim: int = 4):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, latent_dim),
            nn.ReLU()
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, input_dim)
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

    def reconstruction_error(self, x):
        """Calculate reconstruction error for anomaly scoring."""
        with torch.no_grad():
            reconstructed = self.forward(x)
            error = torch.mean((x - reconstructed) ** 2, dim=1)
        return error

class BehavioralModelTrainer:
    def __init__(self, input_dim: int = 8):
        self.model = BehavioralAutoencoder(input_dim)
        self.optimizer = torch.optim.Adam(self.model.parameters(), lr=0.001)
        self.criterion = nn.MSELoss()

    def train(self, data: np.ndarray, epochs: int = 100):
        """Train autoencoder on normal behavior data."""
        X = torch.FloatTensor(data)
        for epoch in range(epochs):
            self.optimizer.zero_grad()
            reconstructed = self.model(X)
            loss = self.criterion(reconstructed, X)
            loss.backward()
            self.optimizer.step()
            if epoch % 10 == 0:
                print(f"Epoch {epoch}, Loss: {loss.item():.4f}")
        return self.model

    def detect_anomalies(self, data: np.ndarray, threshold: float = 0.1) -> List[Dict]:
        """Detect anomalies in new data."""
        X = torch.FloatTensor(data)
        errors = self.model.reconstruction_error(X).numpy()
        anomalies = []
        for i, error in enumerate(errors):
            if error > threshold:
                anomalies.append({
                    "index": i,
                    "reconstruction_error": float(error),
                    "is_anomaly": True,
                    "confidence": min(100, error * 1000)
                })
        return anomalies

    def save(self, path: str):
        torch.save(self.model.state_dict(), path)

    def load(self, path: str):
        self.model.load_state_dict(torch.load(path))
        self.model.eval()

# Quick test
if __name__ == "__main__":
    # Generate synthetic normal data
    np.random.seed(42)
    normal_data = np.random.randn(1000, 8) * 0.5

    trainer = BehavioralModelTrainer()
    trainer.train(normal_data, epochs=50)

    # Test with anomalous data
    anomaly_data = np.random.randn(10, 8) * 2.0
    results = trainer.detect_anomalies(anomaly_data, threshold=0.5)
    print(f"Anomalies detected: {len(results)}")

    trainer.save("behavioral_model.pt")
    print("Model saved to behavioral_model.pt")
