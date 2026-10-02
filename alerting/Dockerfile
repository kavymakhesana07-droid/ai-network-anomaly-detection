# Alerting & Correlation Service
#
# BASE_IMAGE defaults to the locally built base image ("make base"). CI
# overrides it with the published ghcr.io tag via --build-arg so the runner
# does not need to build the base first.
ARG BASE_IMAGE=anomaly-detection/base:latest
FROM ${BASE_IMAGE} AS builder

USER root

# Install alerting-specific deps as root, into the venv created by Dockerfile.base
COPY requirements/alerting.txt /tmp/requirements/alerting.txt
RUN pip install --no-cache-dir -r /tmp/requirements/alerting.txt \
    && rm -rf /tmp/requirements

# Copy source
COPY alerting/ /app/alerting/

WORKDIR /app
ENV PYTHONPATH=/app

# The USER root at the top of this file is only for pip. Without
# switching back, the container would run as root and the non-root user created
# in Dockerfile.base would be dead code.
USER appuser

# Entry point
ENTRYPOINT ["python", "-m", "alerting.main"]