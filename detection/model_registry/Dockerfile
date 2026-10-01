# Model Registry Service
#
# BASE_IMAGE defaults to the locally built base image ("make base"). CI
# overrides it with the published ghcr.io tag via --build-arg so the runner
# does not need to build the base first.
ARG BASE_IMAGE=anomaly-detection/base:latest
FROM ${BASE_IMAGE} AS builder

USER root

# Install model_registry-specific deps as root, into the venv created by Dockerfile.base
COPY requirements/model_registry.txt /tmp/requirements/model_registry.txt
RUN pip install --no-cache-dir -r /tmp/requirements/model_registry.txt \
    && rm -rf /tmp/requirements

# Copy source
COPY detection/model_registry/ /app/detection/model_registry/

WORKDIR /app
ENV PYTHONPATH=/app

# The USER root at the top of this file is only for pip. Without
# switching back, the container would run as root and the non-root user created
# in Dockerfile.base would be dead code.
USER appuser

# Entry point
ENTRYPOINT ["python", "-m", "detection.model_registry.main"]