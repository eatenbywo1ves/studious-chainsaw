# Multi-stage build for production-ready image
FROM nvidia/cuda:12.2.0-runtime-ubuntu22.04 AS base

# Install Python and dependencies
RUN apt-get update && apt-get install -y \
    python3.11 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 catalytic && \
    mkdir -p /app && \
    chown -R catalytic:catalytic /app

WORKDIR /app

# Install Python dependencies
FROM base AS dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Build stage
FROM dependencies AS builder
COPY --chown=catalytic:catalytic . .
RUN pip3 install --no-cache-dir -e .

# Production stage
FROM base AS production

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/dist-packages /usr/local/lib/python3.11/dist-packages
COPY --from=builder /app /app

# Switch to non-root user
USER catalytic

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python3 -c "import requests; requests.get('http://localhost:8080/health/live').raise_for_status()"

# Expose ports
EXPOSE 8080 9090

# Run the application
CMD ["python3", "-m", "uvicorn", "catalytic_computing.api.server:app", \
     "--host", "0.0.0.0", "--port", "8080", \
     "--workers", "4", "--loop", "uvloop", \
     "--access-log", "--log-config", "/app/config/logging.yaml"]