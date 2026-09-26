# AI Network Anomaly Detection - Makefile
# Usage: make <target>

.PHONY: help cluster-up cluster-down deploy-dev deploy-prod ingest-pcap ingest-live train-fast train-deep test lint fmt dashboard logs clean

# Default target
help:
	@echo "AI Network Anomaly Detection System"
	@echo ""
	@echo "Cluster Management:"
	@echo "  make cluster-up          - Start k3d local cluster"
	@echo "  make cluster-down        - Stop k3d cluster"
	@echo ""
	@echo "Deployment:"
	@echo "  make deploy-dev          - Deploy to dev overlay (k3d)"
	@echo "  make deploy-prod         - Deploy to prod overlay"
	@echo ""
	@echo "Data Ingestion:"
	@echo "  make ingest-pcap PCAP_FILE=path/to/file.pcap"
	@echo "  make ingest-live IFACE=eth0"
	@echo ""
	@echo "ML Training:"
	@echo "  make train-fast          - Train fast path models (Isolation Forest)"
	@echo "  make train-deep          - Train deep path models (LSTM-AE, XGBoost)"
	@echo ""
	@echo "Testing & Quality:"
	@echo "  make test                - Run all tests"
	@echo "  make lint                - Run linters"
	@echo "  make fmt                 - Format code"
	@echo ""
	@echo "Observability:"
	@echo "  make dashboard           - Open Grafana dashboard"
	@echo "  make logs SERVICE=name   - Tail service logs"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean               - Clean build artifacts"

# =============================================================================
# Cluster Management
# =============================================================================
cluster-up:
	k3d cluster create anomaly-detection \
		--agents 2 \
		-p "8080:80@loadbalancer" \
		-p "8443:443@loadbalancer" \
		-p "9090:9090@loadbalancer" \
		-p "3000:3000@loadbalancer" \
		-p "9000:9000@loadbalancer" \
		--k3s-arg "--disable=traefik@server:0" \
		--wait
	kubectl apply -f k8s/base/namespace.yaml
	kubectl apply -f k8s/base/storage.yaml

cluster-down:
	k3d cluster delete anomaly-detection

# =============================================================================
# Deployment
# =============================================================================
deploy-dev: cluster-up
	kubectl apply -k k8s/overlays/dev
	kubectl wait --for=condition=available --timeout=300s deployment -n anomaly-detection --all

deploy-prod:
	kubectl apply -k k8s/overlays/prod
	kubectl wait --for=condition=available --timeout=300s deployment -n anomaly-detection --all

# =============================================================================
# Data Ingestion
# =============================================================================
ingest-pcap:
	@if [ -z "$(PCAP_FILE)" ]; then echo "Usage: make ingest-pcap PCAP_FILE=path/to/file.pcap"; exit 1; fi
	kubectl run pcap-ingestor-$$(date +%s) \
		--image=anomaly-detection/pcap-ingestor:latest \
		--namespace=anomaly-detection \
		--restart=Never \
		--env="PCAP_FILE=$(PCAP_FILE)" \
		--env="KAFKA_BROKERS=redpanda:9092" \
		--env="TOPIC=raw.packets"

ingest-live:
	@if [ -z "$(IFACE)" ]; then echo "Usage: make ingest-live IFACE=eth0"; exit 1; fi
	kubectl run live-capture-$$(date +%s) \
		--image=anomaly-detection/live-capture:latest \
		--namespace=anomaly-detection \
		--restart=Never \
		--env="INTERFACE=$(IFACE)" \
		--env="KAFKA_BROKERS=redpanda:9092" \
		--env="TOPIC=raw.packets"

# =============================================================================
# ML Training
# =============================================================================
train-fast:
	python -m detection.fast_path.train \
		--data-path data/processed/train.parquet \
		--model-path models/fast_path/ \
		--algorithm isolation_forest

train-deep:
	python -m detection.deep_path.train \
		--data-path data/processed/train.parquet \
		--model-path models/deep_path/ \
		--algorithm lstm_ae

train-gnn:
	python -m detection.deep_path.train_gnn \
		--topology data/topology/graph.gml \
		--features data/processed/node_features.parquet \
		--model-path models/deep_path/gnn/

# =============================================================================
# Testing
# =============================================================================
test: test-unit test-integration test-e2e

test-unit:
	python -m pytest tests/unit -v --cov=ingestion --cov=feature_extraction --cov=detection --cov=alerting --cov=output

test-integration:
	python -m pytest tests/integration -v

test-e2e:
	python -m pytest tests/e2e -v

# =============================================================================
# Code Quality
# =============================================================================
lint:
	ruff check .
	mypy --strict ingestion detection feature_extraction alerting output
	bandit -r ingestion detection feature_extraction alerting output

fmt:
	ruff format .
	black .

# =============================================================================
# Observability
# =============================================================================
dashboard:
	kubectl port-forward -n monitoring svc/grafana 3000:3000 &
	@echo "Grafana: http://localhost:3000 (admin/admin)"

logs:
	@if [ -z "$(SERVICE)" ]; then echo "Usage: make logs SERVICE=service-name"; exit 1; fi
	kubectl logs -n anomaly-detection -l app=$(SERVICE) -f --tail=100

# =============================================================================
# Maintenance
# =============================================================================
clean:
	docker system prune -f
	rm -rf __pycache__ .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

# =============================================================================
# Development Helpers
# =============================================================================
dev-shell:
	kubectl run dev-shell --rm -it --restart=Never --image=python:3.11-slim --namespace=anomaly-detection -- bash

port-forward-kafka:
	kubectl port-forward -n anomaly-detection svc/redpanda 9092:9092

port-forward-mlflow:
	kubectl port-forward -n anomaly-detection svc/mlflow 5000:5000