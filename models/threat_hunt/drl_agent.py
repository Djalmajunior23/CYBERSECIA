"""
Threat Hunting DRL Agent (PyTorch)
Deep Reinforcement Learning for proactive threat hypothesis generation.
"""
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from typing import List, Dict, Tuple

class ThreatHuntDQN(nn.Module):
    """Deep Q-Network for threat hunting action selection."""
    def __init__(self, state_dim: int = 64, action_dim: int = 32, hidden_dim: int = 128):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, action_dim)
        )

    def forward(self, state):
        return self.network(state)

class ThreatHuntDRL:
    """
    DRL Agent for autonomous threat hunting.
    State: Telemetry features (auth events, network flows, file access)
    Actions: Hunt hypotheses (MITRE technique IDs to investigate)
    Reward: +1 for confirmed threat, -0.1 for false positive
    """
    def __init__(self, state_dim: int = 64, action_dim: int = 32):
        self.policy_net = ThreatHuntDQN(state_dim, action_dim)
        self.target_net = ThreatHuntDQN(state_dim, action_dim)
        self.target_net.load_state_dict(self.policy_net.state_dict())

        self.optimizer = optim.Adam(self.policy_net.parameters(), lr=0.001)
        self.memory = []  # Experience replay buffer
        self.gamma = 0.99  # Discount factor
        self.epsilon = 1.0  # Exploration rate
        self.epsilon_decay = 0.995
        self.epsilon_min = 0.01
        self.batch_size = 32

    def select_action(self, state: np.ndarray) -> int:
        """Epsilon-greedy action selection."""
        if np.random.random() < self.epsilon:
            return np.random.randint(0, 32)

        with torch.no_grad():
            state_tensor = torch.FloatTensor(state).unsqueeze(0)
            q_values = self.policy_net(state_tensor)
            return q_values.argmax().item()

    def store_experience(self, state, action, reward, next_state, done):
        """Store transition in replay buffer."""
        self.memory.append((state, action, reward, next_state, done))
        if len(self.memory) > 10000:
            self.memory.pop(0)

    def train(self):
        """Train policy network using experience replay."""
        if len(self.memory) < self.batch_size:
            return

        batch = np.random.choice(len(self.memory), self.batch_size, replace=False)
        states, actions, rewards, next_states, dones = [], [], [], [], []

        for i in batch:
            s, a, r, ns, d = self.memory[i]
            states.append(s)
            actions.append(a)
            rewards.append(r)
            next_states.append(ns)
            dones.append(d)

        states = torch.FloatTensor(np.array(states))
        actions = torch.LongTensor(actions)
        rewards = torch.FloatTensor(rewards)
        next_states = torch.FloatTensor(np.array(next_states))
        dones = torch.FloatTensor(dones)

        # Current Q values
        current_q = self.policy_net(states).gather(1, actions.unsqueeze(1)).squeeze()

        # Target Q values
        with torch.no_grad():
            next_q = self.target_net(next_states).max(1)[0]
            target_q = rewards + (1 - dones) * self.gamma * next_q

        # Loss and update
        loss = nn.MSELoss()(current_q, target_q)
        self.optimizer.zero_grad()
        loss.backward()
        self.optimizer.step()

        # Decay epsilon
        self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)

        return loss.item()

    def update_target_network(self):
        """Copy policy network weights to target network."""
        self.target_net.load_state_dict(self.policy_net.state_dict())

    def generate_hypothesis(self, telemetry: List[Dict]) -> Dict:
        """Generate hunt hypothesis from telemetry using trained policy."""
        state = self._extract_state(telemetry)
        action = self.select_action(state)

        # Map action to MITRE technique
        techniques = ["T1566.001", "T1059.001", "T1021.002", "T1003.001", "T1071.001",
                      "T1547.001", "T1053.005", "T1083", "T1087.001", "T1110"]
        technique = techniques[action % len(techniques)]

        return {
            "technique": technique,
            "confidence": 100 - (self.epsilon * 100),
            "rationale": f"DRL policy selected technique {technique} based on telemetry patterns",
            "query": f"| search technique_id={technique}"
        }

    def _extract_state(self, telemetry: List[Dict]) -> np.ndarray:
        """Extract numerical state vector from telemetry."""
        features = np.zeros(64)
        for event in telemetry[:64]:
            idx = hash(event.get("event_type", "")) % 64
            features[idx] += 1
        return features / (np.sum(features) + 1e-8)

    def save(self, path: str):
        torch.save({
            'policy': self.policy_net.state_dict(),
            'target': self.target_net.state_dict(),
            'epsilon': self.epsilon
        }, path)

    def load(self, path: str):
        checkpoint = torch.load(path)
        self.policy_net.load_state_dict(checkpoint['policy'])
        self.target_net.load_state_dict(checkpoint['target'])
        self.epsilon = checkpoint['epsilon']

if __name__ == "__main__":
    agent = ThreatHuntDRL()

    # Simulate training
    for episode in range(100):
        state = np.random.randn(64)
        action = agent.select_action(state)
        reward = np.random.choice([1.0, -0.1], p=[0.3, 0.7])
        next_state = np.random.randn(64)
        agent.store_experience(state, action, reward, next_state, False)

        if episode % 10 == 0:
            loss = agent.train()
            print(f"Episode {episode}, Loss: {loss:.4f}, Epsilon: {agent.epsilon:.3f}")

    # Test hypothesis generation
    test_telemetry = [{"event_type": "auth", "user": "admin"} for _ in range(10)]
    hypothesis = agent.generate_hypothesis(test_telemetry)
    print(f"Generated hypothesis: {hypothesis}")

    agent.save("threat_hunt_drl.pt")
    print("Model saved to threat_hunt_drl.pt")
