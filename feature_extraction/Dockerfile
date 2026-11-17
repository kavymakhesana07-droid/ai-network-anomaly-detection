# Feature Extraction Service
#
# BASE_IMAGE defaults to the locally built base image ("make base"). CI
# overrides it with the published ghcr.io tag via --build-arg so the runner
# does not need to build the base first.
ARG BASE_IMAGE=anomaly-detection/base:latest
FROM ${BASE_IMAGE} AS builder

# No additional system deps for feature extraction (pure Python + wheels)
USER root

# Install feature-extraction-specific deps as root, into the venv created by Dockerfile.base.
COPY requirements/features.txt requirements/base.txt /tmp/requirements/
RUN pip install --no-cache-dir -r /tmp/requirements/features.txt \
    && rm -rf /tmp/requirements

# Copy source
COPY feature_extraction/ /app/feature_extraction/

WORKDIR /app
ENV PYTHONPATH=/app

# The USER root at the top of this file is only for pip. Without
# switching back, the container would run as root and the non-root user created
# in Dockerfile.base would be dead code.
USER appuser

# Entry point
ENTRYPOINT ["python", "-m", "feature_extraction.main"]
