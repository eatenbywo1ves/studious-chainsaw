# Multi-stage build for API Gateway
FROM python:3.11-slim as builder

# Set build arguments
ARG BUILD_DATE
ARG VERSION
ARG VCS_REF

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim as production

# Add metadata
LABEL maintainer="MCP Architecture Team" \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="mcp-api-gateway" \
      org.label-schema.description="Enterprise API Gateway for MCP Architecture" \
      org.label-schema.version=$VERSION \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.schema-version="1.0"

# Create non-root user
RUN groupadd --gid 1000 gateway && \
    useradd --uid 1000 --gid gateway --shell /bin/bash --create-home gateway

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=gateway:gateway shared/ ./shared/
COPY --chown=gateway:gateway configs/ ./configs/

# Create necessary directories
RUN mkdir -p /app/logs && \
    chown -R gateway:gateway /app/logs

# Switch to non-root user
USER gateway

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9000/health || exit 1

# Expose port
EXPOSE 9000

# Set environment variables
ENV PYTHONPATH="/app/shared"
ENV GATEWAY_PORT=9000
ENV LOG_LEVEL=INFO

# Start command
CMD ["python", "shared/gateway/api_gateway.py"]