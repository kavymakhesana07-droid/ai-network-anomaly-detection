# AI Network Anomaly Detection System — v0.1.0 Capstone Report

**Author:** Kavy Makhesana — 3rd Year B.Tech Cyber Security, Parul University
**Contact:** kavymakhesana07@gmail.com
**Repository:** https://github.com/kavymakhesana07-droid/ai-network-anomaly-detection
**Release:** [v0.1.0](https://github.com/kavymakhesana07-droid/ai-network-anomaly-detection/releases/tag/v0.1.0)
**Date:** October 2026

---

## 1. Executive Summary

The AI Network Anomaly Detection System is a production-grade, end-to-end
network security platform that ingests raw network traffic from five sources,
extracts 51 standardized flow features, applies three complementary ML
detection lanes, correlates and enriches alerts with threat intelligence, and
delivers them to SIEMs, dashboards, and ChatOps channels.

Built as a 10-day capstone (one component per day), the system ships as
14 containerized microservices with a fully green CI/CD pipeline
(ruff, mypy --strict, bandit, 179 unit tests, 128 pinned dependencies),
Kubernetes manifests with ArgoCD GitOps, Prometheus + Grafana observability,
and MLflow model lifecycle management.

---

## 2. What v0.1.0 Can Do

### 2.1 Ingest traffic from 5 sources

| Source | Method | Output topic |
|--------|--------|--------------|
| PCAP files | offline batch replay (`pcap` ingestor) | `raw.packets` |
| Live interfaces | AF_PACKET raw sockets, promiscuous (`live_capture`) | `raw.packets` |
| NetFlow / sFlow / IPFIX | UDP collectors, port 2055 (`netflow`) | `raw.netflow` |
| Zeek logs | structured protocol metadata (`zeek`) | `raw.zeek` |
| Cloud flow logs | AWS VPC / GCP VPC / Azure NSG APIs (`cloud_flows`) | `raw.cloud` |

A traffic generator (`scripts/traffic_generator.py`: pcap / replay / kafka
modes) plus Kali live-capture helpers (`scripts/examples/kali_live_capture.sh`)
provide synthetic and real attack traffic for demos.

### 2.2 Extract a unified 51-feature vector per flow

The feature extractor emits CICIDS2017/UNSW-NB15-compatible vectors
(`features.flows`): flow identity, volume, packet-length statistics, inter-arrival
times, TCP flags, rates, subflows, window sizes, and active/idle timing —
identical ordering enforced by contract tests against every detector.

### 2.3 Detect anomalies with three complementary lanes

| Lane | Model | Latency | Output |
|------|-------|---------|--------|
| Fast path | Isolation Forest (ONNX Runtime) + Sigma rules | < 10 ms | `alerts.raw` |
| Deep path | LSTM Autoencoder (PyTorch Lightning), Spark batch training | minutes | `alerts.deep` |
| XGBoost | Supervised binary classifier, early stopping on AUC | < 50 ms | `alerts.xgboost` |

The fast path filters ~95% of traffic cheaply; the deep path catches
slow/low-volume anomalies (C2 beacons, lateral movement); XGBoost scores
known attack patterns from labeled CICIDS2017/UNSW-NB15 data.

### 2.4 Correlate, enrich, and route alerts

The alerting engine deduplicates (Redis sliding window), enriches
(IP WHOIS, domain WHOIS, STIX 2.1 indicators), correlates across detectors
(IP pair, ports, protocol, time proximity), and routes by severity to
`alerts.{debug,info,notice,warning,error,critical,alert,emergency}`.

### 2.5 Deliver to operators

| Output | Target |
|--------|--------|
| SIEM sink | Elasticsearch / OpenSearch in ECS format, ILM hot→warm→cold→delete |
| ChatOps | Slack, PagerDuty Events API v2, Mattermost, generic webhooks (retry/backoff) |
| Dashboard | Streamlit real-time table, filters, alert detail, STIX view, auto-refresh |
| REST API | FastAPI: alert query/filter/pagination, stats, health, Prometheus metrics |
| Metrics | Grafana 9-panel dashboard (rates, latency p50/p95/p99, top IPs, consumer lag) |

### 2.6 Manage the ML lifecycle

Offline `train` commands for the deep path and XGBoost lanes produce
versioned artifact bundles (`.pt`/JSON checkpoints, ONNX exports,
`threshold.json`, `normalization.json`, `model_version.json`) with
best-effort MLflow logging. The Model Registry service (MLflow-backed REST)
registers versions and promotes them through
None → Staging → Production → Archived with readiness gates.

### 2.7 Deploy reproducibly

- `docker compose` profiles (`ingest`, `detect`, `alerting`, `output`)
  for local runs (~16 GB RAM).
- Kustomize base + dev/prod overlays for any Kubernetes cluster.
- ArgoCD Applications for GitOps promotion.
- GitHub Actions: lint → unit tests → base image → 14 service images → GHCR.

---

## 3. How It Works (Data Flow)

```
PCAP / Live / NetFlow / Zeek / Cloud
        │  (raw.packets, raw.netflow, raw.zeek, raw.cloud)
        ▼
┌──────────────────┐
│ Feature Extract  │  51-feature vector per flow ──▶ features.flows
└────────┬─────────┘
         │
         ├──▶ Fast Path  (ONNX Isolation Forest + Sigma) ──▶ alerts.raw
         │
         ├──▶ Deep Path  (LSTM-AE reconstruction error)  ──▶ alerts.deep
         │
         └──▶ XGBoost    (supervised probability)        ──▶ alerts.xgboost
                            │
                            ▼
              ┌──────────────────────────┐
              │ Alerting: dedup → enrich │
              │ → correlate → route      │ ──▶ alerts.enriched
              └────────────┬─────────────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
        Elasticsearch  ChatOps    Dashboard/API
        (ECS + ILM)    (Slack…)   (Streamlit/FastAPI)
```

Every hop is an async Kafka (Redpanda) topic, so each lane scales,
fails, and deploys independently.

### 3.1 Why three detectors

- **Fast path** answers "is this flow weird *right now*?" in milliseconds
  using a cheap unsupervised model plus analyst-written Sigma signatures.
- **Deep path** answers "is this *sequence* of flows weird over minutes?"
  by reconstructing 10-flow windows with an LSTM autoencoder; high
  reconstruction error marks slow attacks the fast path misses.
- **XGBoost** answers "does this look like a *known* attack?" using labels,
  with calibrated probabilities and class-imbalance handling
  (`scale_pos_weight`).

Majority/any-vote fusion happens in alerting via correlation groups.

---

## 4. Architecture Decisions (ADRs)

| ADR | Decision | Rationale |
|-----|----------|-----------|
| 0001 | Microservices on Kafka | Independent scaling of ingest/detect/output; backpressure via topics |
| 0002 | Redpanda over Kafka | Single binary, no JVM, Kafka-compatible, 10x lower footprint |
| 0003 | Hybrid ML (unsupervised + supervised) | Labels are scarce; unsupervised catches zero-days, supervised scores known attacks |
| 0004 | k3d for local K8s | Lightweight, disposable, matches prod manifests |

Full records live in `docs/adr/`.

---

## 5. Repository Layout

```
ai-network-anomaly-detection/
├── ingestion/            # pcap, live_capture, netflow, zeek, cloud_flows
├── feature_extraction/   # 51-feature pipeline
├── detection/
│   ├── fast_path/        # ONNX + Isolation Forest + Sigma
│   ├── deep_path/        # LSTM-AE train/serve, Spark, MLflow
│   ├── xgboost/          # supervised train/serve
│   └── model_registry/   # MLflow-backed registry REST service
├── alerting/             # dedup, enrichment, correlation, routing
├── output/
│   ├── dashboard/        # Streamlit
│   ├── siem/             # Elasticsearch ECS sink + ILM
│   ├── integrations/     # Slack/PagerDuty/Mattermost/webhooks
│   └── api/              # FastAPI REST
├── k8s/                  # base + dev/prod overlays + ArgoCD
├── monitoring/           # Prometheus + Grafana
├── scripts/              # traffic_generator, kali helpers, demo.sh, check_pins.py
├── tests/unit/           # 179 tests
├── tests/e2e/            # 12 scenarios (Kafka/Redis/ES helpers)
└── docs/                 # ARCHITECTURE, api, deployment, training + ADRs
```

Every service follows the same contract: dependency-free `models.py`
(unit-tested without heavy deps), lazy heavy imports, root-install into
`/opt/venv` with a non-root `appuser` runtime, structured JSON logging,
health endpoints, and Prometheus metrics.

---

## 6. Quality Gates (all green on v0.1.0)

| Gate | Tool | Result |
|------|------|--------|
| Lint + format | ruff, ruff format | clean |
| Types | mypy --strict | clean |
| Security | bandit | no issues |
| Unit tests | pytest | 179 passed |
| Pins | scripts/check_pins.py --strict | 128 pins exist on PyPI, shipped profiles resolve |
| Builds | CI build matrix | 14/14 images build and push to GHCR |

---

## 7. How to Run the Demo (for the professor)

```bash
# 1. Clone and start the stack (~5 min, needs Docker + 8 GB RAM)
git clone https://github.com/kavymakhesana07-droid/ai-network-anomaly-detection.git
cd ai-network-anomaly-detection
docker compose --profile ingest --profile detect --profile alerting --profile output up -d

# 2. Generate attack traffic (SYN flood + port scan + normal HTTP)
python scripts/traffic_generator.py kafka --brokers localhost:9092 --topic raw.packets

# 3. Watch detections (pick any)
docker logs -f anomaly-fast-path       # sub-10 ms scores
docker logs -f anomaly-alerting        # dedup + enrichment + routing

# 4. Open the UIs
# Dashboard:   http://localhost:8501
# API docs:    http://localhost:8000/docs
# Grafana:     http://localhost:3000  (admin/admin)
# Prometheus:  http://localhost:9090
# MLflow:      http://localhost:5000

# 5. Query the API
curl "http://localhost:8000/api/v1/alerts?limit=5&severity=critical" | jq .
curl "http://localhost:8000/api/v1/alerts/stats/summary" | jq .

# 6. Train a model offline (example: XGBoost)
python -m detection.xgboost.main train \
  --input data/labeled_flows.json --output /models/xgboost --epochs 500
```

Expected demo narrative: normal HTTP flows score low everywhere; the SYN
flood trips the fast path in milliseconds (Sigma + Isolation Forest), the
deep path flags the anomalous window by reconstruction error, alerting
merges the three detector hits into one correlated, enriched incident,
and it appears simultaneously in Streamlit, Elasticsearch/Kibana, the API,
and (if configured) Slack.

---

## 8. Day-by-Day Build Log

| Day | Delivered |
|-----|-----------|
| 1 | Scaffold, CI/CD, base image, pcap ingestor, feature extraction |
| 2 | live_capture, netflow, zeek, cloud_flows ingestors + traffic generator |
| 3 | Fast path (ONNX + Isolation Forest + Sigma rules) |
| 4 | Deep path (LSTM autoencoder train/serve, Spark, MLflow, ONNX export) |
| 5 | XGBoost supervised detector (train/serve, stratified splits, MLflow) |
| 6 | Model Registry (MLflow-backed REST, stage promotion, readiness gates) |
| 7 | Alerting (dedup, WHOIS/STIX enrichment, correlation, severity routing) |
| 8 | Dashboard (Streamlit), SIEM sink (ECS + ILM), ChatOps, FastAPI |
| 9 | K8s manifests, ArgoCD GitOps, E2E test infrastructure + 12 scenarios |
| 10 | Documentation, demo script, ruleset (LICENSE/CODEOWNERS/SECURITY), v0.1.0 public release |

---

## 9. Future Work (v0.2.0)

- Unified React analyst workspace (single pane of glass)
- Alert triage workflow (assign, comment, SLA) and case management
- Automated retraining on drift (Evidently → trigger → train → promote)
- YAML runbook engine with response actions (block IP, quarantine host)
- JWT + RBAC, audit logging, WebSocket live updates

---

*End of report — v0.1.0, October 2026.*
