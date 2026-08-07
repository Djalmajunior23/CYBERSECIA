#!/bin/bash
set -e

PKI_DIR="./config/pki"
mkdir -p $PKI_DIR

echo "[PKI] Generating Certificate Authority..."
openssl genrsa -out $PKI_DIR/ca-key.pem 4096
openssl req -new -x509 -days 3650 -key $PKI_DIR/ca-key.pem -out $PKI_DIR/ca-cert.pem -subj "/CN=CyberSec-AI-CA/O=CyberSec AI Ecosystem"

AGENTS=("central_orchestrator" "discovery_agent" "vulnerability_agent" "threat_intel_agent" 
        "behavioral_agent" "response_orchestrator" "governance_agent" "red_team_agent"
        "soar_agent" "purple_team_agent" "mcp_auditor_agent" "digital_twin_agent"
        "threat_hunt_agent" "compliance_agent" "forensic_agent")

for agent in "${AGENTS[@]}"; do
    echo "[PKI] Generating certificate for $agent..."
    openssl genrsa -out $PKI_DIR/${agent}-key.pem 2048
    openssl req -new -key $PKI_DIR/${agent}-key.pem -out $PKI_DIR/${agent}-csr.pem -subj "/CN=$agent/O=CyberSec AI Ecosystem"
    openssl x509 -req -days 365 -in $PKI_DIR/${agent}-csr.pem -CA $PKI_DIR/ca-cert.pem -CAkey $PKI_DIR/ca-key.pem -out $PKI_DIR/${agent}-cert.pem -CAcreateserial
    rm $PKI_DIR/${agent}-csr.pem
done

echo "[PKI] Certificates generated in $PKI_DIR"
