# Example Scripts

## Traffic Generator

Generates synthetic network traffic for testing ingestors.

```bash
# Generate PCAP file
python scripts/traffic_generator.py pcap --output test.pcap --packets 10000 --pps 1000

# Replay PCAP on interface (requires root)
sudo python scripts/traffic_generator.py replay --pcap test.pcap --speed 10.0 --interface eth0

# Inject directly into Kafka
python scripts/traffic_generator.py kafka --topic raw.packets --brokers localhost:9092 --rate 1000 --packets 5000
```

## Kali Live Capture

Capture live traffic on Kali Linux and feed to the anomaly detection pipeline.

### Bash Version (Recommended)
```bash
# Basic capture on eth0
sudo ./scripts/examples/kali_live_capture.sh

# Capture on WiFi monitor interface
sudo ./scripts/examples/kali_live_capture.sh -i wlan0mon

# Custom Kafka
sudo ./scripts/examples/kali_live_capture.sh -b kafka.example.com:9092

# Via Docker (recommended for production)
sudo ./scripts/examples/kali_live_capture.sh --docker
```

### Python Version
```bash
sudo python scripts/examples/kali_live_capture.py -i eth0 -b localhost:9092
```

### Prerequisites
- Root access (CAP_NET_RAW)
- Interface up: `sudo ip link set eth0 up`
- WiFi monitor mode: `sudo airmon-ng start wlan0`
- Kafka accessible at `$KAFKA_BROKERS`

### Docker Compose Profile
All ingestors are available via the `ingest` profile:

```bash
# Start Kafka + all ingestors
docker compose --profile ingest up -d

# Start specific ingestor
docker compose --profile ingest up live-capture-ingestor
docker compose --profile ingest up netflow-ingestor
docker compose --profile ingest up zeek-ingestor
docker compose --profile ingest up cloud-flows-ingestor
```