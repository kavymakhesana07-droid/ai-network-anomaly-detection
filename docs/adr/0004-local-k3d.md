# ADR 0004: Local Development - k3d with Docker Compose Fallback

## Status
Accepted

## Context
Student budget constraints:
- No paid cloud credits
- Limited local RAM (16GB typical laptop)
- Need production-parity environment
- Fast iteration cycle

## Decision
**Primary**: **k3d** (k3s in Docker) for local K8s
- Lightweight (~500MB vs 4GB for kind/minikube)
- Multi-node cluster in seconds
- Traefik ingress built-in (disabled, we use NGINX)
- Full K8s API compatibility

**Fallback**: **Docker Compose** for ultra-lightweight dev
- No K8s overhead
- Direct service-to-service networking
- Good for single-service development

## k3d Cluster Spec
```yaml
# 1 server + 2 agents = 3 nodes
# Port mappings:
# 8080  -> HTTP ingress (dashboard, APIs)
# 8443  -> HTTPS ingress
# 9090  -> Prometheus
# 3000  -> Grafana
# 9000  -> Redpanda console
# 5000  -> MLflow
# 8081  -> Redpanda Schema Registry
```

## Resource Limits (per container)
| Service | CPU | Memory |
|---------|-----|--------|
| Redpanda | 1000m | 1Gi |
| Feature Extraction | 500m | 512Mi |
| Fast Path Detection | 500m | 512Mi |
| Deep Path (batch) | 2000m | 4Gi |
| MLflow | 500m | 1Gi |
| Prometheus/Grafana | 500m | 1Gi |
| **Total** | ~5 cores | ~8.5Gi |

Fits comfortably on 16GB laptop with 4GB for host OS.

## Free Cloud Tier Targets
| Provider | Offering | Use For |
|----------|----------|---------|
| Oracle Cloud | 4 ARM Ampere cores, 24GB RAM, 200GB boot | Permanent free cluster |
| GCP Free Tier | e2-micro (burstable), 30GB disk | Dev/staging |
| AWS Free Tier | t2/t3.micro, 750 hrs/mo | CI/CD runners |
| GitHub Actions | 2000 min/mo free | CI/CD pipeline |

## Consequences
- All manifests tested on k3d first
- Resource quotas enforced in dev overlay
- CI runs on GitHub Actions (self-hosted runner on Oracle ARM for heavy tests)