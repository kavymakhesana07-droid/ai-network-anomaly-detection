# Contributing to AI Network Anomaly Detection

Thank you for your interest in contributing! This project is part of a placement portfolio demonstrating production-grade network security engineering.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- No harassment or discrimination

## Development Setup

```bash
# Clone
git clone https://github.com/kavymakhesana07-droid/ai-network-anomaly-detection.git
cd ai-network-anomaly-detection

# Install pre-commit hooks
pip install pre-commit
pre-commit install

# Start local stack
make cluster-up
make deploy-dev
# OR use docker-compose
source scripts/dev.sh && dev_up
```

## Project Structure

```
.
├── ingestion/           # Data ingestors (PCAP, Live, NetFlow, Zeek, Cloud)
├── feature_extraction/  # Unified feature pipeline
├── detection/
│   ├── fast_path/       # Sub-second detection (ONNX/Redis)
│   ├── deep_path/       # Batch/streaming ML (PyTorch/Spark)
│   └── model_registry/  # MLflow + DVC
├── alerting/            # Correlation, enrichment, dedup
├── output/              # SIEM, dashboard, integrations
├── k8s/                 # K8s manifests (base + overlays)
├── tests/               # Unit, integration, e2e
├── scripts/             # Operational scripts
└── docs/adr/            # Architecture Decision Records
```

## Making Changes

1. **Create an issue** describing the change
2. **Fork & branch**: `git checkout -b feat/your-feature`
3. **Write code** following style guides
4. **Add tests** for new functionality
5. **Run checks**: `make lint && make test`
6. **Submit PR** with clear description

## Code Style

- **Python**: Ruff + Black + MyPy (strict)
- **Commits**: Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`)
- **ADRs**: Required for architectural decisions (see `docs/adr/`)

## Testing

```bash
# Unit tests (fast)
make test-unit

# Integration tests (needs services)
make test-integration

# E2E tests (full pipeline)
make test-e2e

# All tests
make test
```

## Adding New Ingestors

1. Create `ingestion/<name>/` with `Dockerfile`, `main.py`, `requirements.txt`
2. Implement `IngestorBase` interface
3. Publish to `raw.packets` Kafka topic
4. Add to `docker-compose.yml` and K8s manifests
5. Document in `docs/adr/`

## Adding New Detection Models

1. Train in `detection/deep_path/train_*.py`
2. Export to ONNX for fast path
3. Register in MLflow with versioning
4. Update model registry service
5. Document in `docs/adr/`

## Deployment

- **Dev**: `make deploy-dev` (k3d local)
- **Prod**: Push to `main` → GitHub Actions → ArgoCD sync

## Questions?

Open an issue or contact: kanomakhesana@gmail.com

---

**Author**: Kavy Makhesana - 3rd Year B.Tech Cyber Security, Parul University
- CCST Networking | ISC2 Candidate | Ethical Hacking (130hr) | CTF Player