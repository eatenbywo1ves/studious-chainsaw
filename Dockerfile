# Multi-stage build for production-ready Catalytic Lattice Computing

# Stage 1: Build environment
FROM python:3.11-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Copy source code
COPY src/ ./src/
COPY setup.py .
COPY README.md .

# Install the package
RUN pip install --no-cache-dir --user -e .

# Stage 2: Runtime environment
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 catalytic && \
    mkdir -p /app/data /app/logs /app/aux_memory && \
    chown -R catalytic:catalytic /app

# Copy installed packages from builder
COPY --from=builder --chown=catalytic:catalytic /root/.local /home/catalytic/.local

# Copy application
WORKDIR /app
COPY --chown=catalytic:catalytic src/ ./src/
COPY --chown=catalytic:catalytic configs/ ./configs/

# Set environment variables
ENV PYTHONPATH=/app:$PYTHONPATH \
    PATH=/home/catalytic/.local/bin:$PATH \
    NUMBA_NUM_THREADS=4 \
    OMP_NUM_THREADS=4 \
    CATALYTIC_CONFIG=/app/configs/production.yaml

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import catalytic_lattice; print('healthy')" || exit 1

# Switch to non-root user
USER catalytic

# Expose API port
EXPOSE 8000

# Default command - start the API server
CMD ["python", "-m", "uvicorn", "src.api.server:app", "--host", "0.0.0.0", "--port", "8000"]