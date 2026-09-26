# ADR 0002: Streaming Platform - Redpanda over Kafka

## Status
Accepted

## Context
Need a streaming backbone for:
- High-throughput packet/flow ingestion (100K+ events/sec)
- Low-latency fast path (<10ms end-to-end)
- Replay capability for model retraining
- Local development (k3d) and cloud parity

## Decision
Use **Redpanda** (Kafka-compatible, Rust-based) instead of Apache Kafka.

## Reasoning
| Factor | Redpanda | Apache Kafka |
|--------|----------|--------------|
| Resource usage | ~3x lower RAM/CPU | High (JVM overhead) |
| Binary size | Single 50MB binary | Multiple JARs + ZK |
| Startup time | <1 sec | 30-60 sec |
| k3d/local fit | Excellent | Heavy |
| Kafka API compat | 100% wire-compatible | Native |
| Schema registry | Built-in | Separate (Confluent) |
| Cost (cloud) | Lower | Higher |

## Consequences
- Use `redpanda` Helm chart for K8s deployment
- All producers/consumers use standard `kafka-python` / `confluent-kafka` / `aiokafka`
- Schema Registry built-in at `http://redpanda:8081`
- Topic design: `raw.packets`, `features.flows`, `alerts.raw`, `alerts.enriched`

## Migration Path
If needed, can migrate to managed Kafka (Confluent Cloud, AWS MSK, Aiven) with zero code changes.