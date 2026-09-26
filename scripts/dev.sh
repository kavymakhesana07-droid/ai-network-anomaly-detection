# AI Network Anomaly Detection - Development Scripts

# Quick start for local development with docker-compose
# Usage: source scripts/dev.sh && dev_up

dev_up() {
    echo "Starting anomaly detection stack..."
    docker-compose up -d
    echo "Services starting... Check status with: dev_status"
}

dev_down() {
    echo "Stopping anomaly detection stack..."
    docker-compose down
}

dev_status() {
    docker-compose ps
}

dev_logs() {
    if [ -z "$1" ]; then
        docker-compose logs -f --tail=100
    else
        docker-compose logs -f --tail=100 "$1"
    fi
}

dev_restart() {
    if [ -z "$1" ]; then
        echo "Usage: dev_restart <service>"
        return 1
    fi
    docker-compose restart "$1"
}

dev_rebuild() {
    if [ -z "$1" ]; then
        docker-compose build --no-cache
    else
        docker-compose build --no-cache "$1"
    fi
}

# Ingest a PCAP file
dev_ingest_pcap() {
    if [ -z "$1" ]; then
        echo "Usage: dev_ingest_pcap <path/to/file.pcap>"
        return 1
    fi
    docker-compose run --rm \
        -e PCAP_FILE="/data/$(basename "$1")" \
        -v "$(dirname "$(realpath "$1")")":/data:ro \
        pcap-ingestor
}

# Open Grafana dashboard
dev_dashboard() {
    echo "Opening Grafana at http://localhost:3000 (admin/admin)"
    # xdg-open http://localhost:3000 2>/dev/null || open http://localhost:3000 2>/dev/null || echo "Open manually"
}

# Open MLflow
dev_mlflow() {
    echo "Opening MLflow at http://localhost:5000"
}

# Run tests in container
dev_test() {
    docker-compose run --rm feature-extractor pytest tests/ -v
}

# Format code
dev_fmt() {
    docker-compose run --rm feature-extractor black . && docker-compose run --rm feature-extractor ruff format .
}

# Lint code
dev_lint() {
    docker-compose run --rm feature-extractor ruff check . && docker-compose run --rm feature-extractor mypy --strict ingestion detection feature_extraction alerting output
}

# Show help
dev_help() {
    cat <<EOF
AI Network Anomaly Detection - Development Commands

Stack Management:
  dev_up              Start all services
  dev_down            Stop all services
  dev_status          Show service status
  dev_logs [service]  Tail logs (all or specific service)
  dev_restart <svc>   Restart a service
  dev_rebuild [svc]   Rebuild images

Data Ingestion:
  dev_ingest_pcap <file.pcap>  Ingest a PCAP file

Observability:
  dev_dashboard       Open Grafana (localhost:3000)
  dev_mlflow          Open MLflow (localhost:5000)

Development:
  dev_test            Run tests
  dev_fmt             Format code (black + ruff)
  dev_lint            Lint code (ruff + mypy)

Examples:
  dev_up
  dev_ingest_pcap ./data/sample.pcap
  dev_logs feature-extractor
  dev_dashboard
EOF
}

# Alias for convenience
alias anomaly=dev_help