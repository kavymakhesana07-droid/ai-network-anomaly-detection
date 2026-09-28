# Fast Path Detection Service
#
# BASE_IMAGE defaults to the locally built base image ("make base"). CI
# overrides it with the published ghcr.io tag via --build-arg so the runner
# does not need to build the base first.
ARG BASE_IMAGE=anomaly-detection/base:latest
FROM ${BASE_IMAGE} AS builder

# No additional system deps for fast path (pure Python)
USER root

# Install fast-path-specific deps as root, into the venv created by Dockerfile.base
COPY requirements/detect_fast.txt /tmp/requirements/detect_fast.txt
RUN pip install --no-cache-dir -r /tmp/requirements/detect_fast.txt \
    && rm -rf /tmp/requirements

# Copy source
COPY detection/fast_path/ /app/detection/fast_path/
COPY feature_extraction/ /app/feature_extraction/

WORKDIR /app
ENV PYTHONPATH=/app

# The USER root at the top of this file is only for pip. Without
# switching back, the container would run as root and the non-root user created
# in Dockerfile.base would be dead code.
USER appuser

# Entry point
ENTRYPOINT ["python", "-m", "detection.fast_path.main"]