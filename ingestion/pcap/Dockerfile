# PCAP Ingestor Service
FROM anomaly-detection/base:latest AS builder

# Additional system deps for PCAP
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    wireshark-common \
    && rm -rf /var/lib/apt/lists/*
USER appuser

# Install PCAP-specific deps
COPY requirements/ingest.txt /tmp/requirements/ingest.txt
RUN pip install --no-cache-dir -r /tmp/requirements/ingest.txt

# Copy source
COPY ingestion/pcap/ /app/ingestion/pcap/
COPY feature_extraction/ /app/feature_extraction/

WORKDIR /app
ENV PYTHONPATH=/app

# Entry point
ENTRYPOINT ["python", "-m", "ingestion.pcap.main"]