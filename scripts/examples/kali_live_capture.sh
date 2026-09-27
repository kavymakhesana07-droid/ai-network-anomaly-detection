#!/usr/bin/env bash
# Kali Linux Live Capture Example
# Run this on Kali Linux to capture live traffic and feed it to the anomaly detection pipeline.
#
# Prerequisites:
#   - Kali Linux (or any Linux with libpcap-dev)
#   - Python 3.11+
#   - Docker (for running the full pipeline) OR
#     Python deps: pip install -r requirements/ingest.txt
#   - Access to Kafka (Redpanda) at $KAFKA_BROKERS
#
# Usage:
#   sudo ./kali_live_capture.sh                    # Capture on default interface (eth0)
#   sudo ./kali_live_capture.sh -i wlan0           # Capture on WiFi interface
#   sudo ./kali_live_capture.sh -i eth0 -s 1000    # Snaplen 1000 bytes
#   sudo ./kali_live_capture.sh -h                 # Help

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# Defaults
INTERFACE="${INTERFACE:-eth0}"
PROMISC="${PROMISC:-true}"
SNAPLEN="${SNAPLEN:-65535}"
KAFKA_BROKERS="${KAFKA_BROKERS:-localhost:9092}"
TOPIC="${TOPIC:-raw.packets}"
CHECKPOINT_DIR="${CHECKPOINT_DIR:-./data/checkpoints}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"

usage() {
    cat <<EOF
Kali Live Capture - Network Anomaly Detection Ingestor

Usage: sudo $0 [OPTIONS]

Options:
  -i, --interface IFACE    Network interface to capture on (default: eth0)
  -p, --promisc BOOL       Enable promiscuous mode (default: true)
  -s, --snaplen BYTES      Snapshot length in bytes (default: 65535)
  -b, --brokers HOST:PORT  Kafka brokers (default: localhost:9092)
  -t, --topic TOPIC        Kafka topic (default: raw.packets)
  -c, --checkpoint-dir DIR Checkpoint directory (default: ./data/checkpoints)
  -l, --log-level LEVEL    Log level: DEBUG, INFO, WARNING, ERROR (default: INFO)
  -h, --help               Show this help

Environment variables (override defaults):
  INTERFACE, PROMISC, SNAPLEN, KAFKA_BROKERS, TOPIC, CHECKPOINT_DIR, LOG_LEVEL

Examples:
  # Basic capture on eth0
  sudo $0

  # Capture on WiFi monitor mode interface
  sudo $0 -i wlan0mon

  # Capture with custom Kafka
  sudo $0 -b kafka.example.com:9092 -t raw.packets

  # Run via Docker (recommended for production)
  sudo $0 --docker

Prerequisites for live capture:
  - CAP_NET_RAW capability (granted by sudo)
  - Interface must be up: sudo ip link set eth0 up
  - For WiFi: sudo airmon-ng start wlan0  (creates wlan0mon)

EOF
}

# Parse arguments
DOCKER_MODE=false
while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--interface)
            INTERFACE="$2"
            shift 2
            ;;
        -p|--promisc)
            PROMISC="$2"
            shift 2
            ;;
        -s|--snaplen)
            SNAPLEN="$2"
            shift 2
            ;;
        -b|--brokers)
            KAFKA_BROKERS="$2"
            shift 2
            ;;
        -t|--topic)
            TOPIC="$2"
            shift 2
            ;;
        -c|--checkpoint-dir)
            CHECKPOINT_DIR="$2"
            shift 2
            ;;
        -l|--log-level)
            LOG_LEVEL="$2"
            shift 2
            ;;
        --docker)
            DOCKER_MODE=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must run as root (sudo) for raw socket access."
    exit 1
fi

# Verify interface exists
if ! ip link show "$INTERFACE" &>/dev/null; then
    echo "ERROR: Interface '$INTERFACE' not found."
    echo "Available interfaces:"
    ip link show | grep -E '^[0-9]+:' | awk '{print "  " $2}' | sed 's/:$//'
    exit 1
fi

# Bring interface up
ip link set "$INTERFACE" up || true

echo "=== Kali Live Capture ==="
echo "Interface:     $INTERFACE"
echo "Promiscuous:   $PROMISC"
echo "Snaplen:       $SNAPLEN"
echo "Kafka Brokers: $KAFKA_BROKERS"
echo "Topic:         $TOPIC"
echo "Checkpoint:    $CHECKPOINT_DIR"
echo "Log Level:     $LOG_LEVEL"
echo ""

mkdir -p "$CHECKPOINT_DIR"

if [[ "$DOCKER_MODE" == "true" ]]; then
    echo "Running via Docker Compose..."
    cd "$REPO_ROOT"

    # Build if needed
    if ! docker image inspect anomaly-detection/ingestion-live_capture:latest &>/dev/null; then
        echo "Building live-capture image..."
        docker compose build live-capture-ingestor
    fi

    # Run with required capabilities
    docker run --rm \
        --name anomaly-live-capture \
        --cap-add=NET_RAW \
        --cap-add=NET_ADMIN \
        --network anomaly-net \
        -e KAFKA_BROKERS="$KAFKA_BROKERS" \
        -e TOPIC="$TOPIC" \
        -e INTERFACE="$INTERFACE" \
        -e PROMISC="$PROMISC" \
        -e SNAPLEN="$SNAPLEN" \
        -e CHECKPOINT_DIR="/data/checkpoints" \
        -e LOG_LEVEL="$LOG_LEVEL" \
        -v "$CHECKPOINT_DIR:/data/checkpoints" \
        anomaly-detection/ingestion-live_capture:latest
else
    echo "Running via Python (direct)..."
    cd "$REPO_ROOT"

    # Check Python deps
    if ! python3 -c "import scapy; import aiokafka; import structlog" 2>/dev/null; then
        echo "Installing Python dependencies..."
        pip install -r requirements/ingest.txt
    fi

    # Run the ingestor
    export KAFKA_BROKERS="$KAFKA_BROKERS"
    export TOPIC="$TOPIC"
    export INTERFACE="$INTERFACE"
    export PROMISC="$PROMISC"
    export SNAPLEN="$SNAPLEN"
    export CHECKPOINT_DIR="$CHECKPOINT_DIR"
    export LOG_LEVEL="$LOG_LEVEL"
    export PYTHONPATH="$REPO_ROOT"

    python3 -m ingestion.live_capture.main
fi