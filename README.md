# Federated IoT IDS — Prototype

Masters-level demo project for IoT intrusion + anomaly detection with:

- Lightweight device models (1D CNN / GRU / Autoencoder – simulated)
- Federated aggregation (Adaptive FedAvg – simulated)
- Concept drift simulation and drift-aware scoring
- Real-time telemetry & anomaly alert dashboard
- Web-based simulator to demonstrate research concepts

This project was built as part of a Masters course project on
**IoT Security, Intrusion Detection and Federated Learning**.

---

## 🚀 Project Structure

```text
backend/    → Node.js simulator + API + WebSocket server (port 9002)
frontend/   → Vite + JavaScript dashboard UI (port 9003)
