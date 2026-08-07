#!/usr/bin/env python3
"""Behavioral Analysis Agent — UEBA & Anomaly Detection Engine"""
import os
import sys
import json
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from mcp.core import MCPClient, MCPClientConfig, MCPMessage, MessageType, AgentType, Priority

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(name)s | %(levelname)s | %(message)s")
logger = logging.getLogger("behavioral")

class BehavioralAgent:
    def __init__(self):
        self.config = MCPClientConfig(
            agent_id="behavioral_agent",
            agent_type=AgentType.WORKER,
            kafka_broker=os.getenv("KAFKA_BROKER", "kafka:29092"),
            redis_url=os.getenv("REDIS_URL", "redis://redis:6379/4"),
            heartbeat_interval=30
        )
        self.client = MCPClient(self.config)
        self.models = {}
        self.scalers = {}
        self._register_handlers()

    def _register_handlers(self):
        self.client.register_handler(MessageType.TASK_ASSIGNMENT, self._handle_task)
        self.client.register_handler(MessageType.QUERY_REQUEST, self._handle_query)

    def _handle_task(self, msg: MCPMessage):
        task = msg.payload.task
        if task.task_type == "behavior_analyze":
            asyncio.create_task(self._execute_behavior_analysis(msg))
        elif task.task_type == "ueba_baseline":
            asyncio.create_task(self._execute_baseline(msg))

    def _handle_query(self, msg: MCPMessage):
        query = msg.payload.query
        if query.query_type == "anomaly_score":
            entity_id = query.parameters.get("entity_id")
            score = self._get_anomaly_score(entity_id)
            response = MCPMessage.Payload(
                message_type=MessageType.QUERY_RESPONSE,
                result=MCPMessage.Payload.Result(status="success", data={"entity_id": entity_id, "anomaly_score": score})
            )
            self.client.send_message(msg.envelope.from_addr.agent_id, response, msg.correlation_id)

    async def _execute_behavior_analysis(self, msg: MCPMessage):
        task = msg.payload.task
        events = task.parameters.get("events", [])
        anomalies = []

        for event in events:
            entity_type = event.get("entity_type", "user")
            entity_id = event.get("entity_id", "")
            features = self._extract_features(event)

            model = self._get_model(entity_type)
            scaler = self._get_scaler(entity_type)

            if model and scaler:
                X = scaler.transform([features])
                score = model.decision_function(X)[0]
                prediction = model.predict(X)[0]

                if prediction == -1:  # Anomaly
                    anomaly = {
                        "entity_type": entity_type,
                        "entity_id": entity_id,
                        "anomaly_score": float(score),
                        "event": event,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "confidence": min(95, max(50, abs(score) * 50))
                    }
                    anomalies.append(anomaly)

                    # Alert if high confidence
                    if anomaly["confidence"] > 80:
                        self._send_alert(anomaly)

        self._send_result(msg, "success", data={"anomalies_detected": len(anomalies), "anomalies": anomalies})

    async def _execute_baseline(self, msg: MCPMessage):
        task = msg.payload.task
        entity_type = task.parameters.get("entity_type", "user")
        historical_events = task.parameters.get("historical_events", [])

        features = [self._extract_features(e) for e in historical_events]
        if len(features) < 10:
            self._send_result(msg, "failure", errors=["Insufficient data for baseline (min 10 events)"])
            return

        X = np.array(features)
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(X_scaled)

        self.models[entity_type] = model
        self.scalers[entity_type] = scaler

        # Save to Redis
        import pickle
        self.client._redis.set(f"model:behavioral:{entity_type}", pickle.dumps(model))
        self.client._redis.set(f"scaler:behavioral:{entity_type}", pickle.dumps(scaler))

        self._send_result(msg, "success", data={"entity_type": entity_type, "baseline_events": len(features)})

    def _extract_features(self, event: Dict) -> List[float]:
        """Extract numerical features from event."""
        features = [
            event.get("hour_of_day", 12),
            event.get("day_of_week", 0),
            event.get("data_volume_mb", 0),
            event.get("unique_destinations", 0),
            event.get("auth_failures", 0),
            event.get("privilege_escalation", 0),
            event.get("new_location", 0),
            event.get("after_hours", 0),
        ]
        return [float(f) for f in features]

    def _get_model(self, entity_type: str):
        if entity_type not in self.models:
            import pickle
            cached = self.client._redis.get(f"model:behavioral:{entity_type}")
            if cached:
                self.models[entity_type] = pickle.loads(cached)
        return self.models.get(entity_type)

    def _get_scaler(self, entity_type: str):
        if entity_type not in self.scalers:
            import pickle
            cached = self.client._redis.get(f"scaler:behavioral:{entity_type}")
            if cached:
                self.scalers[entity_type] = pickle.loads(cached)
        return self.scalers.get(entity_type)

    def _get_anomaly_score(self, entity_id: str) -> float:
        return 0.0

    def _send_alert(self, anomaly: Dict):
        alert_payload = MCPMessage.Payload(
            message_type=MessageType.ALERT,
            alert=MCPMessage.Payload.Alert(
                severity="high" if anomaly["confidence"] > 90 else "medium",
                title=f"Behavioral Anomaly: {anomaly['entity_type']} {anomaly['entity_id']}",
                description=f"Anomaly detected with score {anomaly['anomaly_score']:.2f} and confidence {anomaly['confidence']}%",
                source="behavioral_agent",
                iocs=[],
                mitre_techniques=["T1078", "T1098"]
            )
        )
        self.client.send_message("central_orchestrator", alert_payload)

    def _send_result(self, original_msg: MCPMessage, status: str, data: Optional[Dict] = None, errors: Optional[List[str]] = None):
        result_payload = MCPMessage.Payload(
            message_type=MessageType.TASK_RESULT,
            result=MCPMessage.Payload.Result(status=status, completion_time=datetime.now(timezone.utc), data=data or {}, errors=errors or [])
        )
        self.client.send_message("central_orchestrator", result_payload, correlation_id=original_msg.correlation_id)

    async def run(self):
        logger.info("Behavioral Agent started")
        await self.client.run()

if __name__ == "__main__":
    agent = BehavioralAgent()
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("Behavioral Agent shutting down...")
        agent.client.stop()
