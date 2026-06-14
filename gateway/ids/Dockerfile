# Dockerfile - Multi-architecture support (x86_64 and arm64)
# Build: docker buildx build --platform linux/amd64,linux/arm64 -t yourrepo/ids_model:latest --push .
# Test x86_64: docker build -t ids_model:test .
# Test arm64 (emulated): docker buildx build --platform linux/arm64 -t ids_model:test-arm64 --output type=docker .

FROM python:3.11-slim

WORKDIR /app

# Install runtime and build dependencies
# Keep build tools for ARM64 wheel compilation fallback
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build tools (needed for ARM64 wheel compilation)
    build-essential \
    gcc g++ gfortran \
    pkg-config \
    # Scientific computing libraries
    libopenblas-dev \
    liblapack-dev \
    # Network utilities (for iptables-based blocking)
    iptables \
    iproute2 \
    # libpcap — required by Scapy to compile BPF filters
    libpcap-dev \
    # System dependencies
    libffi-dev \
    libssl-dev \
    # Utilities
    curl \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip for better wheel resolution on ARM
RUN python -m pip install --no-cache-dir --upgrade pip setuptools wheel

# Copy runtime dependencies
COPY requirements-runtime.txt ./
RUN pip install --no-cache-dir -r requirements-runtime.txt

# Copy application code (including rule-based engine)
# Note: rules.py is part of ids_gateway package
COPY ids_gateway ./ids_gateway
COPY configs ./configs
COPY models ./models

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONHASHSEED=0

# Health check: verify model can be loaded and basic imports work
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import joblib; joblib.load('/app/models/ids_model.joblib'); print('ok')" || exit 1

# Default command: run IDS gateway
# Requires: /app/models/ids_model.joblib and /app/models/feature_scaler.joblib mounted or present
CMD ["python", "-m", "ids_gateway.main", "configs/ids_config.yaml"]

# Label for metadata
LABEL maintainer="Your Team"
LABEL description="IDS Gateway for DDoS Detection (multi-arch: amd64, arm64)"
LABEL org.opencontainers.image.source="https://github.com/yourrepo/ids_gateway"
