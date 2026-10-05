# Architecture Overview

This document provides a comprehensive overview of the AI Network Anomaly Detection System architecture.

## System Overview

The AI Network Anomaly Detection System is a production-grade network security platform that combines **hybrid ML (unsupervised pre-training + supervised fine-tuning)** with **tiered real-time/batch processing**. It ingests network traffic from multiple sources, extracts unified features, applies tiered detection, and routes enriched alerts to SIEMs and dashboards.

```
┌─────────────┐   ┌──────────────┐   ┌─────────────────┐   ┌─────────────┐
│  Ingestion  │──▶│  Features    │──▶│  Tiered Detect  │──▶│  Alert/Out  │
│  (Pluggable)│   │  (Unified)   │   │  Fast + Deep    │   │  (Multi)    │
└─────────────┘   └──────────────┘   └─────────────────┘   └─────────────┘
```

## Design Principles

1. **Modularity** - Each layer is independently deployable and replaceable
2. **Observability** - Structured logging, metrics, tracing built-in
2. **Scalability** - Horizontal scaling via Kafka partitioning + K8s HPA
3. **Reliability** - At-least-once delivery, idempotent processing, DLQ
4. **Security** - Non-root containers, least privilege, secrets management
5. **Reproducibility** - Pinned dependencies, pinned base images, SBOM

## System Layers

### 1. Ingestion Layer (5 Ingestors)

| Ingestor | Source | Protocol | Output Topic |
|----------|--------|----------|--------------|
| `pcap` | PCAP files | Batch | `raw.packets` |
| `live_capture` | AF_PACKET | Live | `raw.packets` |
| `netflow` | NetFlow/sFlow/IPFIX | UDP | `raw.netflow` |
| `zeek` | Zeek logs | File/Stream | `raw.zeek` |
| `cloud_flows` | AWS/GCP/Azure | API | `raw.cloud` |

All ingestors normalize to `raw.packets` or `raw.flows` Kafka topics.

### 2. Feature Extraction

Unified pipeline producing **51 standardized features** per flow (CICIDS2017/UNSW-NB15 compatible):

- **Flow identity**: 5-tuple, timestamps, duration
- **Volume**: packets/bytes per direction
- **Packet stats**: min/mean/max/std per direction
- **IAT**: inter-arrival time statistics
- **Flags**: TCP flag counts
- **Rates**: packets/bytes per second
- **Subflows**: TCP subflow statistics
- **Window**: initial window sizes
- **Active/Idle**: connection state timing

Output: `features.flows` Kafka topic

### 3. Detection Engine (Tiered)

| Tier | Latency | Models | Use Case |
|------|---------|--------|----------|
| **Fast Path** | <10ms | Isolation Forest (ONNX) + Sigma | Real-time blocking |
| **Deep Path** | min/hr | LSTM-AE, Transformer, XGBoost | Threat hunting |

#### Fast Path
- ONNX Runtime + Isolation Forest (sub-ms inference)
- Sigma rule engine for signature detection
- Redis caching for feature enrichment
- Output: `alerts.raw`

#### Deep Path
- LSTM Autoencoder (PyTorch Lightning)
- Training: Spark local mode → ONNX export
- Reconstruction error thresholding
- Output: `alerts.deep`

#### XGBoost Supervised
- Binary classification on labeled data
- Native JSON model export
- ONNX export for fast path integration

### 4. Alerting & Correlation

- **Deduplication**: Redis-backed sliding window
- **Enrichment**: IP WHOIS, GeoIP, STIX indicators
- **Correlation**: Multi-detector + temporal clustering
- **Routing**: Severity-based → `alerts.{debug,info,warning,error,critical,alert,emergency}`
- **Enrichment**: WHOIS, STIX, MISP (optional)

### 5. Output & Integration

| Output | Target | Format |
|--------|--------|--------|
| SIEM | Elasticsearch/OpenSearch | ECS |
| SIEM | Splunk | HEC |
| SIEM | Splunk | Splunk HEC |
| ChatOps | Slack, Mattermost, PagerDuty | Webhook |
| Dashboard | Streamlit | WebSocket |
| API | FastAPI | REST + WebSocket |

## Data Flow

```
PCAP/Live/NetFlow/Zeek/Cloud
        │
        ▼
   ┌─────────┐
   │ Ingest  │ ──▶ raw.packets / raw.flows / raw.netflow / raw.zeek / raw.cloud
   └────┬────┘
        │
        ▼
   ┌──────────────┐
   │ Feature Ext  │ ──▶ features.flows (51 features)
   └──────┬───────┘
          │
          ▼
   ┌──────────────────┐
   │ Fast Path (<10ms)│ ──▶ alerts.raw (Isolation Forest + Sigma)
   │   (ONNX + Redis) │
   └────────┬─────────┘
          │
          ▼
   ┌──────────────────┐
   │ Deep Path (min)  │ ──▶ alerts.deep (LSTM-AE reconstruction)
   │  (Spark + PT)    │
   └────────┬─────────┘
          │
          ▼
   ┌──────────────────┐
   │ XGBoost Supv.    │ ──▶ alerts.xgboost (supervised)
   └────────┬─────────┘
          │
          ▼
   ┌──────────────────┐
   │ Alerting Engine  │ ──▶ alerts.enriched
   │ (Dedup/Enrich/   │
   │  Correlate/Route)│
   └────────┬─────────┘
          │
          ▼
   ┌──────────────────┐
   │ Output Layer     │ ──▶ Elasticsearch / Splunk / Slack / Dashboard / API
   └──────────────────┘
```

## Technology Stack

| Layer | Technology | Version |
|-------|------------|---------|
| Streaming | Redpanda | 24.x |
| Orchestration | Kubernetes (k3d dev) | 1.28+ |
| ML Training | PyTorch Lightning | 2.3+ |
| ML Serving | ONNX Runtime | 1.19+ |
| Feature Store | Redis | 7.x |
| Experiment Tracking | MLflow | 2.15+ |
| Data Versioning | DVC | 3.x |
| Monitoring | Prometheus + Grafana | 2.47+ / 10.4+ |
| Logging | Loki + Promtail | 2.9+ |
| CI/CD | GitHub Actions + ArgoCD | - |
| SBOM | Syft + Grype | - |

## Deployment Architecture

### Local Development (k3d)
```bash
# Start cluster
make cluster-up

# Deploy stack
make deploy-dev

# Access services
make dashboard    # http://localhost:8501
make api          # http://localhost:8000/docs
make grafana      # http://localhost:3000
```

### Production (EKS/GKE/AKS)
```bash
# GitOps via ArgoCD
kubectl apply -k k8s/overlays/prod

# ArgoCD auto-sync from main branch
# Images from GHCR (built by CI)
```

## Security Considerations

- **Non-root containers** (UID 10001)
- **Read-only root filesystem** (where possible)
- **No secrets in images** - External secrets operator
- **Network policies** - Default deny, explicit allow
- **RBAC** - Least privilege service accounts
- **Image signing** - Cosign + Rekor
- **SBOM** - Syft + Grype in CI

## ADR Index

| ADR | Title | Status |
|-----|-------|--------|
| 0001 | Architecture Overview | Accepted |
| 0002 | Streaming - Redpanda over Kafka | Accepted |
| 0003 | ML Hybrid Approach | Accepted |
| 0004 | Local Development - k3d | Accepted |