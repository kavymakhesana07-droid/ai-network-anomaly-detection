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

# Install PCAP-specific deps as root, into the venv created by Dockerfile.base.
# Installing as appuser would not work: the venv is root-owned on purpose, and
# with PYTHONNOUSERSITE set pip would fail rather than quietly writing into a
# home directory that is not on the venv's path.
COPY requirements/ingest.txt /tmp/requirements/ingest.txt
RUN pip install --no-cache-dir -r /tmp/requirements/ingest.txt \
    && rm -rf /tmp/requirements

# Copy source
COPY ingestion/pcap/ /app/ingestion/pcap/
COPY feature_extraction/ /app/feature_extraction/

WORKDIR /app
ENV PYTHONPATH=/app

# The USER root at the top of this file is only for apt and pip. Without
# switching back, the container would run as root and the non-root user created
# in Dockerfile.base would be dead code.
USER appuser

# Entry point
ENTRYPOINT ["python", "-m", "ingestion.pcap.main"]