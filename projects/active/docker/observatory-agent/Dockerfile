# Multi-stage build for Observatory Agent
FROM python:3.11-slim as builder

# Set build arguments
ARG BUILD_DATE
ARG VERSION
ARG VCS_REF

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    sqlite3 \
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
      org.label-schema.name="mcp-observatory-agent" \
      org.label-schema.description="Real-time Monitoring and Observability Agent" \
      org.label-schema.version=$VERSION \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.schema-version="1.0"

# Create non-root user
RUN groupadd --gid 1000 observatory && \
    useradd --uid 1000 --gid observatory --shell /bin/bash --create-home observatory

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=observatory:observatory shared/ ./shared/
COPY --chown=observatory:observatory configs/ ./configs/
COPY --chown=observatory:observatory agents/production/observatory-agent/ ./observatory-agent/

# Create necessary directories
RUN mkdir -p /app/logs /app/data /app/database && \
    chown -R observatory:observatory /app/logs /app/data /app/database

# Switch to non-root user
USER observatory

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose port
EXPOSE 8080

# Set environment variables
ENV PYTHONPATH="/app/shared:/app"
ENV OBSERVATORY_PORT=8080
ENV LOG_LEVEL=INFO
ENV DATABASE_PATH="/app/database/observatory.db"

# Start command
CMD ["python", "enhanced_observatory_adapter.py"]

# Volume for persistent data
VOLUME ["/app/database", "/app/logs"]