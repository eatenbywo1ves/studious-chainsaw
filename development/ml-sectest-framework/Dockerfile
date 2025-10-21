# ============================================================================
# ML-SecTest Framework - Production Dockerfile
# ============================================================================
# Multi-stage build with security hardening
# Python 3.13 | Non-root user | Minimal attack surface | Health checks
# ============================================================================

# --- Stage 1: Builder Stage ---
FROM python:3.13-slim AS builder

LABEL stage="builder"

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir --user -r requirements.txt


# --- Stage 2: Runtime Stage ---
FROM python:3.13-slim

LABEL maintainer="ML-SecTest Team"
LABEL version="1.0.0"
LABEL description="ML Security Testing Framework - Multi-Agent System"
LABEL org.opencontainers.image.source="https://github.com/yourusername/ml-sectest-framework"
LABEL org.opencontainers.image.vendor="ML-SecTest"
LABEL org.opencontainers.image.licenses="MIT"

# Security: Install only essential runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Security: Create non-root user BEFORE copying files
RUN useradd -m -u 1000 -s /bin/bash mlsectest && \
    mkdir -p /app /app/reports /app/config /app/logs && \
    chown -R mlsectest:mlsectest /app

WORKDIR /app

# Copy Python dependencies from builder stage
COPY --from=builder --chown=mlsectest:mlsectest /root/.local /home/mlsectest/.local

# Copy framework code with proper ownership
COPY --chown=mlsectest:mlsectest agents/ ./agents/
COPY --chown=mlsectest:mlsectest core/ ./core/
COPY --chown=mlsectest:mlsectest utils/ ./utils/
COPY --chown=mlsectest:mlsectest ml_sectest.py .
COPY --chown=mlsectest:mlsectest README.md .
COPY --chown=mlsectest:mlsectest LICENSE .

# Set Python path to include user site-packages
ENV PATH="/home/mlsectest/.local/bin:${PATH}" \
    PYTHONPATH="/app:${PYTHONPATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=UTF-8 \
    ML_SECTEST_VERSION=1.0.0 \
    LOG_LEVEL=INFO \
    ENVIRONMENT=production

# Security: Switch to non-root user
USER mlsectest

# Health check - verify framework can be imported
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import sys; from core import SecurityOrchestrator; sys.exit(0)" || exit 1

# Expose port for future API deployment (Phase 6)
EXPOSE 8080

# Volume mounts for reports and config
VOLUME ["/app/reports", "/app/logs"]

# Default entrypoint and command
ENTRYPOINT ["python", "ml_sectest.py"]
CMD ["--help"]

# ============================================================================
# Build Instructions:
# docker build -t ml-sectest:latest .
# docker build -t ml-sectest:1.0.0 --build-arg VERSION=1.0.0 .
#
# Run Instructions:
# docker run --rm ml-sectest:latest list-challenges
# docker run --rm -v $(pwd)/reports:/app/reports ml-sectest:latest scan http://target.com
#
# Security Scan:
# trivy image ml-sectest:latest
# docker scan ml-sectest:latest
# ============================================================================
