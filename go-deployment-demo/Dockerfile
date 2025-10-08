# Multi-stage Dockerfile for Go application
# Stage 1: Build stage with full Go toolchain
FROM golang:1.25.1-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
# CGO_ENABLED=0 for static binary
# -ldflags="-w -s" to strip debug info and reduce size
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s" \
    -o go-deployment-demo .

# Run tests during build
RUN go test -v ./...

# Stage 2: Minimal runtime image
FROM alpine:3.18

# Install minimal dependencies for health checks and debugging
RUN apk add --no-cache ca-certificates wget

# Copy CA certificates for HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the binary from builder
COPY --from=builder /app/go-deployment-demo /go-deployment-demo

# Expose port (documented, not enforced)
EXPOSE 8080

# Add labels for better metadata
LABEL maintainer="corbin"
LABEL version="1.0.0"
LABEL description="Go Deployment Demo - Production-ready Go web service"

# Run as non-root user (use existing nobody user in alpine)
USER nobody:nobody

# Health check using HTTP endpoint
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:8080/health || exit 1

# Set environment variables
ENV PORT=8080
ENV ENVIRONMENT=production
ENV VERSION=1.0.0

# Run the application
ENTRYPOINT ["/go-deployment-demo"]
