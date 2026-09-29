# Deep Path Detection Service
#
# BASE_IMAGE defaults to the locally built base image ("make base"). CI
# overrides it with the published ghcr.io tag via --build-arg so the runner
# does not need to build the base first.
ARG BASE_IMAGE=anomaly-detection/base:latest
FROM ${BASE_IMAGE} AS builder

# No additional system deps for deep path (pure Python + wheels)
USER root

# Install deep-path-specific deps as root, into the venv created by Dockerfile.base.
# detect_deep.txt includes base.txt; base.txt also happens to leak through from
# the base image (it never rm's /tmp/requirements), but COPY it explicitly so
# this build does not depend on that accident.
COPY requirements/detect_deep.txt requirements/base.txt /tmp/requirements/
RUN pip install --no-cache-dir -r /tmp/requirements/detect_deep.txt \
    && rm -rf /tmp/requirements

# Copy source
COPY detection/deep_path/ /app/detection/deep_path/

WORKDIR /app
ENV PYTHONPATH=/app

# The USER root at the top of this file is only for pip. Without
# switching back, the container would run as root and the non-root user created
# in Dockerfile.base would be dead code.
USER appuser

# Entry point
ENTRYPOINT ["python", "-m", "detection.deep_path.main"]
