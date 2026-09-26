# ADR 0001: Overall System Architecture

## Status
Accepted

## Context
We need a production-grade network anomaly detection system that:
- Handles multiple ingestion sources (PCAP, live capture, NetFlow, Zeek, Cloud Flow Logs)
- Supports both real-time (ms) and batch (hr) detection tiers
- Uses hybrid ML (unsupervised pre-training + supervised fine-tuning)
- Deploys locally on k3d and to cloud K8s via GitOps
- Runs on free-tier cloud resources

## Decision
Adopt a **modular, event-driven microservices architecture** on Kubernetes with these layers:

1. **Ingestion Layer** - Pluggable ingestors publishing to Kafka/Redpanda
2. **Feature Extraction** - Unified pipeline producing standardized feature vectors
3. **Tiered Detection Engine** - Fast path (ONNX/Redis) + Deep path (Spark/PyTorch)
4. **Model Registry** - MLflow + DVC for versioning
5. **Alerting & Output** - Correlation, enrichment, multi-channel output

All services communicate via **async messaging (Kafka)** for decoupling and backpressure handling.

## Consequences
**Positive:**
- Independent scaling of ingest vs detection vs output
- Pluggable ingestors = easy to add new sources
- Tiered detection = cost-effective (cheap fast path filters 95%+)
- GitOps-ready K8s manifests
- Vendor-agnostic (runs anywhere K8s runs)

**Negative:**
- Operational complexity (K8s, Kafka, multiple services)
- Requires learning curve for k3d/K8s/Helm
- Local resource usage (8GB+ RAM recommended)

**Mitigation:**
- Comprehensive Makefile for common operations
- Docker Compose fallback for simpler local dev
- Detailed docs and runbooks