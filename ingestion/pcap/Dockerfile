# PCAP Ingestor Service
#
# BASE_IMAGE defaults to the locally built base image ("make base"). CI
# overrides it with the published ghcr.io tag via --build-arg so the runner
# does not need to build the base first.
ARG BASE_IMAGE=anomaly-detection/base:latest
FROM ${BASE_IMAGE} AS builder

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