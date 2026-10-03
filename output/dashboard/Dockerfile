# Streamlit Dashboard Service
#
# BASE_IMAGE defaults to the locally built base image ("make base"). CI
# overrides it with the published ghcr.io tag via --build-arg so the runner
# does not need to build the base first.
ARG BASE_IMAGE=anomaly-detection/base:latest
FROM ${BASE_IMAGE} AS builder

USER root

# Install dashboard-specific deps
COPY requirements/output.txt /tmp/requirements/output.txt
RUN pip install --no-cache-dir -r /tmp/requirements/output.txt \
    && rm -rf /tmp/requirements

# Copy source
COPY output/dashboard/ /app/output/dashboard/
COPY output/models.py /app/output/models.py

WORKDIR /app
ENV PYTHONPATH=/app

USER appuser

# Streamlit config
ENV STREAMLIT_SERVER_HEADLESS=true
ENV STREAMLIT_SERVER_PORT=8501
ENV STREAMLIT_SERVER_ADDRESS=0.0.0.0

ENTRYPOINT ["python", "-m", "output.dashboard.main"]