# Multi-stage build for MCP Servers
FROM node:18-slim as builder

# Set build arguments
ARG BUILD_DATE
ARG VERSION
ARG VCS_REF

# Install build dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy package files and install dependencies
COPY mcp-servers/package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Production stage
FROM node:18-slim as production

# Add metadata
LABEL maintainer="MCP Architecture Team" \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="mcp-servers" \
      org.label-schema.description="Model Context Protocol Servers Collection" \
      org.label-schema.version=$VERSION \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.schema-version="1.0"

# Create non-root user
RUN groupadd --gid 1000 mcp && \
    useradd --uid 1000 --gid mcp --shell /bin/bash --create-home mcp

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    dumb-init \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Set working directory
WORKDIR /app

# Copy node modules from builder
COPY --from=builder /build/node_modules ./node_modules

# Copy MCP server implementations
COPY --chown=mcp:mcp mcp-servers/ ./mcp-servers/

# Create necessary directories
RUN mkdir -p /app/logs /app/data && \
    chown -R mcp:mcp /app/logs /app/data

# Switch to non-root user
USER mcp

# Health check endpoint (will be implemented per server)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${MCP_PORT:-3000}/health || exit 1

# Set environment variables
ENV NODE_ENV=production
ENV MCP_PORT=3000
ENV LOG_LEVEL=info

# Use dumb-init as PID 1
ENTRYPOINT ["dumb-init", "--"]

# Default command (overridden by specific server)
CMD ["node", "mcp-servers/financial/stochastic/src/index.js"]

# Volume for persistent data
VOLUME ["/app/data", "/app/logs"]