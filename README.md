# AI Network Anomaly Detection System

> Production-grade network anomaly detection combining **hybrid ML (unsupervised pre-training + supervised fine-tuning)** with **tiered real-time/batch processing**. Built for Network Security / Network Engineering placement portfolio.

## Architecture Overview

```
┌─────────────┐   ┌──────────────┐   ┌─────────────────┐   ┌─────────────┐
│  Ingestion  │──▶│  Features    │──▶│  Tiered Detect  │──▶│  Alert/Out  │
│  (Pluggable)│   │  (Unified)   │   │  Fast + Deep    │   │  (Multi)    │
└─────────────┘   └──────────────┘   └─────────────────┘   └─────────────┘
```

### Ingestion Sources (Pluggable)
- **PCAP** - Offline batch analysis (Wireshark/tcpdump)
- **Live Capture** - Real-time libpcap/AF_PACKET sniffing
- **NetFlow/sFlow/IPFIX** - Router/switch flow exports
- **Zeek/Suricata Logs** - Structured protocol metadata
- **Cloud Flow Logs** - AWS VPC, GCP VPC, Azure NSG

### Detection Engine (Tiered)
| Tier | Latency | Tech | Models |
|------|---------|------|--------|
| **Fast Path** | ~ms | Redis + ONNX Runtime | Isolation Forest, Sigma rules |
| **Deep Path** | ~min/hr | Spark/Flink + PyTorch | LSTM-AE, Transformer, XGBoost, GNN |

### ML Approach: Hybrid
1. **Unsupervised Pre-training** - LSTM Autoencoder on normal traffic (no labels needed)
2. **Supervised Fine-tuning** - XGBoost/TabTransformer on labeled attacks (CICIDS, UNSW-NB15, custom)
3. **Graph Neural Network** - Topology-aware detection (optional advanced)

### Deployment
- **Local Dev**: k3d (lightweight K8s) + Docker Compose fallback
- **Production**: Any K8s (EKS/GKE/AKS/k3s) via GitOps (ArgoCD/Flux)
- **Free-tier Cloud**: Oracle Cloud Always Free, GCP Free Tier, AWS Free Tier

## Quick Start

```bash
# Prereqs: Docker, k3d, kubectl, helm, make

# Start local cluster
make cluster-up

# Deploy stack
make deploy-dev

# Ingest sample PCAP
make ingest-pcap PCAP_FILE=./data/sample.pcap

# View dashboard
make dashboard
```

## Project Structure

```
.
├── ingestion/           # Pluggable ingestors (PCAP, live, NetFlow, Zeek, Cloud)
├── feature_extraction/  # Unified feature pipeline
├── detection/
│   ├── fast_path/       # Sub-second detection (ONNX, Redis)
│   ├── deep_path/       # Batch/streaming ML (PyTorch, Spark)
│   └── model_registry/  # MLflow + DVC versioning
├── alerting/            # Correlation, enrichment, dedup
├── output/              # SIEM, dashboard, integrations
├── k8s/                 # K8s manifests (base + overlays)
├── tests/               # Unit, integration, e2e
├── scripts/             # Operational scripts
└── docs/adr/            # Architecture Decision Records
```

## Documentation

- [Architecture Decisions](docs/adr/)
- [API Specification](docs/api.md)
- [Deployment Guide](docs/deployment.md)
- [Model Training](docs/training.md)
- [Contributing](CONTRIBUTING.md)

## Tech Stack

| Layer | Technology |
|-------|------------|
| Streaming | Apache Kafka / Redpanda |
| Orchestration | Kubernetes (k3d local) |
| ML Training | PyTorch, XGBoost, scikit-learn |
| ML Serving | ONNX Runtime, Triton (optional) |
| Feature Store | Feast (optional) / Redis |
| Experiment Tracking | MLflow |
| Data Versioning | DVC |
| Monitoring | Prometheus + Grafana |
| Logging | Loki + Promtail |
| CI/CD | GitHub Actions + ArgoCD |

## License

MIT - See [LICENSE](LICENSE)

## Author

**Kavy Makhesana** - 3rd Year B.Tech Cyber Security, Parul University
- CCST Networking | ISC2 Candidate | Ethical Hacking (130hr) | CTF Player
- [LinkedIn](https://www.linkedin.com/in/kavy-makhesana-77598a328/) | [TryHackMe](https://tryhackme.com/p/KavyMakhesana)