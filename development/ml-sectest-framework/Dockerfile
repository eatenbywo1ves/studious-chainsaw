FROM python:3.11-slim

LABEL maintainer="ML-SecTest Team"
LABEL version="1.0.0"
LABEL description="ML Security Testing Framework - Multi-Agent System"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (Docker layer caching optimization)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy framework code
COPY agents/ ./agents/
COPY core/ ./core/
COPY utils/ ./utils/
COPY ml_sectest.py .
COPY README.md .
COPY QUICKSTART.md .

# Create directories for reports and configuration
RUN mkdir -p /app/reports /app/config /app/logs

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=UTF-8 \
    ML_SECTEST_VERSION=1.0.0 \
    LOG_LEVEL=INFO

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import sys; from core import SecurityOrchestrator; sys.exit(0)" || exit 1

# Create non-root user for security
RUN useradd -m -u 1000 mlsectest && \
    chown -R mlsectest:mlsectest /app

USER mlsectest

# Expose port for future API (if needed)
EXPOSE 8080

# Default command
ENTRYPOINT ["python", "ml_sectest.py"]
CMD ["--help"]
