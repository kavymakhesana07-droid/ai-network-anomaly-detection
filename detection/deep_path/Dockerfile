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
# Unlike the other services this profile pulls a second include chain
# (detect_deep.txt -> ml.txt -> base.txt), so all three files must be present:
# base.txt happens to leak through from the base image (it never rm's
# /tmp/requirements), but ml.txt does not - COPY it explicitly.
COPY requirements/detect_deep.txt requirements/ml.txt requirements/base.txt /tmp/requirements/
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
