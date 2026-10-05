# Deployment Guide

This guide covers deploying the AI Network Anomaly Detection System in various environments.

## Prerequisites

### Local Development
- Docker Desktop (or Docker Engine + Docker Compose)
- k3d (for local Kubernetes)
- kubectl
- helm
- make

### Production
- Kubernetes 1.28+ (EKS/GKE/AKS/k3s)
- Helm 3.x
- ArgoCD
- External secrets operator
- Cert-manager (for TLS)

## Quick Start (Local)

### 1. Prerequisites
```bash
# Install k3d
curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash

# Or with Homebrew
brew install k3d
```

### 2. Start Local Cluster
```bash
make cluster-up
# Or manually:
k3d cluster create anomaly-detection \
  --agents 2 \
  -p "8080:80@loadbalancer" \
  -p "8443:443@loadbalancer" \
  --wait
```

### 3. Deploy Stack
```bash
# Build images
make build

# Deploy all services
make deploy-dev

# Or just specific services
make deploy-detect    # Detectors only
make deploy-ingest    # Ingestors only
make deploy-output    # Dashboard, SIEM, API
```

### 4. Verify Deployment
```bash
# Check pods
kubectl get pods -n anomaly-detection

# Check services
kubectl get svc -n anomaly-detection

# View logs
kubectl logs -n anomaly-detection -l app=fast-path -f
```

### 5. Access Services
```bash
# Dashboard
open http://localhost:8501

# API docs
open http://localhost:8000/docs

# Grafana
open http://localhost:3000  # admin/admin

# Prometheus
open http://localhost:9090

# MLflow
open http://localhost:5000
```

---

## Production Deployment (EKS/GKE/AKS)

### 1. Prepare Infrastructure
```bash
# EKS example
eksctl create cluster \
  --name anomaly-detection \
  --version 1.28 \
  --region us-east-1 \
  --nodegroup-name standard-workers \
  --node-type m6i.xlarge \
  --nodes 3 \
  --nodes-min 2 \
  --nodes-max 10 \
  --managed
```

### 2. Install ArgoCD
```bash
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
```

### 3. Configure Secrets
```bash
# Create secrets for production
kubectl create secret generic anomaly-secrets \
  --namespace anomaly-detection \
  --from-literal=slack-webhook-url="$SLACK_WEBHOOK" \
  --from-literal=pagerduty-key="$PAGERDUTY_KEY" \
  --from-literal=elasticsearch-password="$ES_PASSWORD" \
  --from-literal=mlflow-artifacts-s3-key="$AWS_SECRET_KEY" \
  --from-literal=mlflow-artifacts-s3-secret="$AWS_ACCESS_KEY"
```

### 4. Apply ArgoCD Applications
```bash
kubectl apply -f k8s/argocd/applications/anomaly-detection-platform.yaml
```

### 4. Verify
```bash
argocd app list
argocd app get anomaly-detection-platform
```

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `KAFKA_BROKERS` | Kafka bootstrap servers | `redpanda:9092` |
| `REDIS_URL` | Redis connection | `redis://redis:6379` |
| `ELASTICSEARCH_URL` | Elasticsearch endpoint | `http://elasticsearch:9200` |
| `MLFLOW_TRACKING_URI` | MLflow server | `http://mlflow:5000` |
| `MODEL_PATH` | Model artifacts path | `/models` |
| `REDIS_URL` | Redis for caching | `redis://redis:6379` |

### Resource Limits

| Service | CPU Request | CPU Limit | Memory Request | Memory Limit |
|---------|-------------|-----------|----------------|--------------|
| Ingestors | 500m | 2000m | 1Gi | 2Gi |
| Feature Extraction | 500m | 2000m | 1Gi | 2Gi |
| Fast Path | 500m | 1000m | 1Gi | 1Gi |
| Deep Path | 1000m | 2000m | 4Gi | 4Gi |
| XGBoost | 1000m | 2000m | 2Gi | 4Gi |
| Model Registry | 250m | 500m | 512Mi | 512Mi |
| Alerting | 250m | 500m | 512Mi | 512Mi |
| Dashboard | 250m | 500m | 512Mi | 512Mi |
| SIEM Output | 500m | 1000m | 512Mi | 1Gi |
| Integrations | 250m | 500m | 256Mi | 512Mi |
| API | 250m | 500m | 512Mi | 512Mi |

### Scaling

| Service | HPA | Metric |
|---------|-----|--------|
| Ingestors | CPU > 70% | CPU |
| Feature Extraction | CPU > 70% | CPU |
| Fast Path | CPU > 70% | CPU |
| Deep Path | N/A | Manual |
| XGBoost | N/A | Manual |
| API | CPU > 70% | CPU |

---

## Monitoring & Observability

### Prometheus Metrics
```bash
# Port forward
kubectl port-forward -n monitoring svc/prometheus 9090:9090

# Open http://localhost:9090
```

### Grafana Dashboards
```bash
# Port forward
kubectl port-forward -n monitoring svc/grafana 3000:3000

# Open http://localhost:3000 (admin/admin)
```

### Key Metrics to Alert On

| Alert | Expression | Severity |
|-------|------------|----------|
| HighConsumerLag | `kafka_consumer_lag > 10000` | warning |
| HighErrorRate | `rate(errors_total[5m]) > 0.05` | critical |
| HighLatency | `histogram_quantile(0.99, rate(inference_latency_ms_bucket[5m])) > 1000` | warning |
| DiskSpace | `disk_usage_percent > 85` | warning |
| MemoryUsage | `container_memory_usage_bytes / container_spec_memory_limit_bytes > 0.9` | critical |

---

## Troubleshooting

### Common Issues

| Issue | Diagnosis | Resolution |
|-------|-----------|------------|
| Pods stuck in Pending | `kubectl describe pod` | Check resources, PVC binding |
| Consumer lag growing | `kafka-consumer-groups.sh` | Scale consumers, check processing time |
| ES indexing failures | ES logs | Check mapping, disk space |
| Model load failures | Container logs | Check model path, ONNX format |
| High memory usage | `kubectl top pods` | Increase limits, check leaks |

### Useful Commands

```bash
# View all pods
kubectl get pods -A -o wide

# Tail logs
kubectl logs -n anomaly-detection -l app=fast-path -f --tail=100

# Exec into pod
kubectl exec -it -n anomaly-detection <pod> -- /bin/bash

# Port forward
kubectl port-forward -n anomaly-detection svc/fast-path 8080:8080

# Check resource usage
kubectl top pods -n anomaly-detection

# Describe pod
kubectl describe pod -n anomaly-detection <pod>

# Check events
kubectl get events -n anomaly-detection --sort-by=.metadata.creationTimestamp
```

---

## Backup & Recovery

### MLflow Backup
```bash
# Backup MLflow DB
kubectl exec -n anomaly-detection mlflow-0 -- sqlite3 /mlflow/mlflow.db .dump > mlflow-backup.sql

# Backup artifacts
aws s3 sync s3://mlflow-artifacts s3://backup-bucket/mlflow/$(date +%Y%m%d)/
```

### Elasticsearch Snapshot
```bash
# Register repository
PUT /_snapshot/backup_repo
{
  "type": "s3",
  "settings": {
    "bucket": "backup-bucket",
    "region": "us-east-1"
  }
}

# Create snapshot
PUT /_snapshot/backup_repo/snapshot_20261005
{
  "indices": "network-alerts-*",
  "ignore_unavailable": true
}
```

### Redis Backup
```bash
# Trigger BGSAVE
kubectl exec -n anomaly-detection redis-0 -- redis-cli BGSAVE

# Copy RDB
kubectl cp anomaly-detection/redis-0:/data/dump.rdb ./redis-backup-$(date +%Y%m%d).rdb
```

---

## Rollback Procedures

### ArgoCD Rollback
```bash
# List history
argocd app history anomaly-detection-platform

# Rollback to previous version
argocd app rollback anomaly-detection-platform <revision>

# Or via CLI
argocd app rollback anomaly-detection-platform 5
```

### Manual Image Rollback
```bash
# Update image tag
kubectl set image deployment/fast-path fast-path=ghcr.io/org/anomaly-detection/fast_path:v1.2.3 -n anomaly-detection

# Or via ArgoCD
argocd app set anomaly-detection-platform --parameter image.tag=v1.2.3
```

---

## Security Checklist

- [ ] All images scanned (Grype/Trivy)
- [ ] No secrets in images
- [ ] Network policies applied
- [ ] RBAC least privilege
- [ ] Secrets encrypted at rest
- [ ] TLS everywhere (cert-manager)
- [ ] Audit logging enabled
- [ ] Image signing verified
- [ ] SBOM generated
- [ ] Dependency scanning passed