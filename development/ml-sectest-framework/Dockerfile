# ML-SecTest Framework - Production Dockerfile
# Multi-stage build for minimal image size

# ============================================================================
# Stage 1: Builder
# ============================================================================
FROM python:3.13-slim as builder

# Set working directory
WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --user -r requirements.txt

# ============================================================================
# Stage 2: Runtime
# ============================================================================
FROM python:3.13-slim

# Metadata
LABEL maintainer="ML-SecTest Framework"
LABEL version="1.0.0"
LABEL description="Automated ML Security Testing Framework"

# Create non-root user
RUN groupadd -r mlsectest && useradd -r -g mlsectest -u 1000 mlsectest

# Set working directory
WORKDIR /app

# Copy Python dependencies from builder
COPY --from=builder /root/.local /home/mlsectest/.local

# Copy application code
COPY --chown=mlsectest:mlsectest . .

# Create data directories
RUN mkdir -p /data /data/reports && \
    chown -R mlsectest:mlsectest /data

# Set environment variables
ENV PATH=/home/mlsectest/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ENVIRONMENT=production

# Expose ports
EXPOSE 8081 9090

# Switch to non-root user
USER mlsectest

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8081/health')"

# Default command
CMD ["python", "-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8081", "--workers", "4"]
