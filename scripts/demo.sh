#!/usr/bin/env bash
# Demo script for AI Network Anomaly Detection System
# Run this after deploying the stack to demonstrate the full pipeline

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Config
DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$DEMO_DIR")"
DATA_DIR="$PROJECT_ROOT/data/demo"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  AI Network Anomaly Detection Demo${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check prerequisites
check_prereqs() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"
    
    for cmd in docker docker-compose kubectl k3d make; do
        if ! command -v "$cmd" &> /dev/null; then
            echo -e "${RED}Missing: $cmd${NC}"
            exit 1
        fi
    done
    echo -e "${GREEN}All prerequisites met${NC}"
}

# Start local stack
start_stack() {
    echo -e "${YELLOW}Starting local stack...${NC}"
    cd "$PROJECT_ROOT"
    
    # Start k3d cluster
    echo "Starting k3d cluster..."
    make cluster-up
    
    # Wait for cluster ready
    kubectl wait --for=condition=Ready nodes --all --timeout=120s
    
    # Deploy stack
    make deploy-dev
    
    # Wait for all pods ready
    kubectl wait --for=condition=Ready pods --all -n anomaly-detection --timeout=300s
    kubectl wait --for=condition=Ready pods --all -n streaming --timeout=120s
    kubectl wait --for=condition=Ready pods --all -n monitoring --timeout=120s
    
    echo -e "${GREEN}Stack ready!${NC}"
}

# Generate sample PCAP with attacks
generate_sample_pcap() {
    echo -e "${YELLOW}Generating sample PCAP with attack scenarios...${NC}"
    
    mkdir -p "$DATA_DIR"
    
    # Create sample PCAP with various attack patterns
    python3 << 'EOF'
import subprocess
import time

# Generate PCAP with:
# 1. Normal HTTP traffic
# 2. SYN flood
# 2. Port scan
# 3. Brute force SSH
# 4. Data exfiltration

# Use tcpreplay or scapy to generate
# For demo, we'll use a pre-generated sample
import urllib.request
import os

sample_url = "https://github.com/kavymakhesana07-droid/ai-network-anomaly-detection/releases/download/sample-data/demo-attacks.pcap"
output = "data/demo/sample-attacks.pcap"

if not os.path.exists(output):
    print("Downloading sample PCAP...")
    try:
        urllib.request.urlretrieve(sample_url, output)
        print("Downloaded sample PCAP")
    except:
        print("Could not download, generating synthetic...")
        # Generate synthetic using scapy if available
        try:
            from scapy.all import Ether, IP, TCP, Raw, wrpcap, RandIP, RandShort
            pkts = []
            # Normal traffic
            for i in range(100):
                pkts.append(Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=12345, dport=80)/Raw(b"GET / HTTP/1.1"))
            # SYN flood
            for i in range(1000):
                pkts.append(Ether()/IP(src="192.168.1.100", dst="10.0.0.1")/TCP(sport=12345, dport=22, flags="S"))
            # Port scan
            for port in range(1, 1000):
                pkts.append(Ether()/IP(src="192.168.1.100", dst="10.0.0.1")/TCP(dport=port, flags="S"))
            wrpcap("data/demo/sample-attacks.pcap", pkts)
            print("Generated synthetic PCAP")
        except ImportError:
            print("Scapy not available, creating dummy PCAP")
            with open("data/demo/sample-attacks.pcap", "wb") as f:
                f.write(b"dummy pcap for demo")
EOF

    echo -e "${GREEN}Sample PCAP ready${NC}"
}

# Run PCAP ingestion demo
demo_pcap_ingestion() {
    echo -e "${YELLOW}Running PCAP ingestion demo...${NC}"
    
    # Copy PCAP to ingestor pod
    kubectl cp "$DATA_DIR/sample-attacks.pcap" anomaly-detection/$(kubectl get pod -n anomaly-detection -l app=pcap-ingestor -o jsonpath='{.items[0].metadata.name}'):/data/sample-attacks.pcap
    
    # Trigger ingestion
    kubectl exec -n anomaly-detection deployment/pcap-ingestor -- python -m ingestion.pcap.main /data/sample-attacks.pcap
    
    echo -e "${GREEN}PCAP ingested${NC}"
}

# Watch alerts in real-time
watch_alerts() {
    echo -e "${YELLOW}Watching alerts (press Ctrl+C to stop)...${NC}"
    
    # Tail alerts from all detectors
    kubectl logs -n anomaly-detection -l app=fast-path -f --tail=0 &
    kubectl logs -n anomaly-detection -l app=deep-path -f --tail=0 &
    kubectl logs -n anomaly-detection -l app=xgboost -f --tail=0 &
    kubectl logs -n anomaly-detection -l app=alerting -f --tail=0 &
    
    wait
}

# Run API demo
demo_api() {
    echo -e "${YELLOW}Testing API endpoints...${NC}"
    
    API_BASE="http://localhost:8000/api/v1"
    
    # Health check
    curl -s http://localhost:8000/health | jq .
    
    # List alerts
    curl -s "http://localhost:8000/api/v1/alerts?limit=5" | jq .
    
    # Stats
    curl -s "http://localhost:8000/api/v1/alerts/stats/summary" | jq .
    
    echo -e "${GREEN}API demo complete${NC}"
}

# Cleanup
cleanup() {
    echo -e "${YELLOW}Cleaning up...${NC}"
    
    # Stop port forwards
    pkill -f "kubectl port-forward" 2>/dev/null || true
    
    # Optional: delete cluster
    # make cluster-down
    
    echo -e "${GREEN}Cleanup complete${NC}"
}

# Main
main() {
    case "${1:-all}" in
        prereqs)
            check_prereqs
            ;;
        start)
            check_prereqs
            start_stack
            ;;
        generate-pcap)
            generate_sample_pcap
            ;;
        ingest)
            demo_pcap_ingestion
            ;;
        watch)
            watch_alerts
            ;;
        api)
            demo_api
            ;;
        cleanup)
            cleanup
            ;;
        all)
            check_prereqs
            start_stack
            generate_sample_pcap
            demo_pcap_ingestion
            sleep 10
            demo_api
            watch_alerts
            ;;
        *)
            echo "Usage: $0 {prereqs|start|generate-pcap|ingest|watch|api|cleanup|all}"
            exit 1
            ;;
    esac
}

# Run
main "$@"