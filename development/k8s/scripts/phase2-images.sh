#!/bin/bash
# ========================================
# Phase 2: Docker Image Pipeline
# Build, scan, and push Docker images
# ========================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

REGISTRY="${DOCKER_REGISTRY:-localhost:5000}"
VERSION="${VERSION:-v1.0.0}"
ENVIRONMENT="${1:-staging}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

log_info "========================================="
log_info "Phase 2: Docker Image Pipeline"
log_info "Registry: ${REGISTRY}"
log_info "Version: ${VERSION}"
log_info "Environment: ${ENVIRONMENT}"
log_info "========================================="

# Check prerequisites
command -v docker >/dev/null 2>&1 || { log_error "docker not found"; exit 1; }

# Check Docker daemon
docker info >/dev/null 2>&1 || { log_error "Docker daemon not running"; exit 1; }

cd "${PROJECT_ROOT}"

# Get git commit hash
GIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
FULL_VERSION="${VERSION}-${GIT_HASH}"

log_info "Build metadata: ${FULL_VERSION} (${BUILD_DATE})"

# Function to build image
build_image() {
  local dockerfile=$1
  local image_name=$2
  local context=$3

  log_info "Building ${image_name}..."

  docker build \
    --file "${dockerfile}" \
    --tag "${REGISTRY}/${image_name}:${FULL_VERSION}" \
    --tag "${REGISTRY}/${image_name}:${ENVIRONMENT}" \
    --tag "${REGISTRY}/${image_name}:latest" \
    --build-arg BUILD_DATE="${BUILD_DATE}" \
    --build-arg VERSION="${FULL_VERSION}" \
    --label "org.opencontainers.image.created=${BUILD_DATE}" \
    --label "org.opencontainers.image.version=${FULL_VERSION}" \
    --label "org.opencontainers.image.revision=${GIT_HASH}" \
    --progress=plain \
    "${context}"

  if [ $? -eq 0 ]; then
    log_success "✓ ${image_name} built successfully"
    return 0
  else
    log_error "✗ ${image_name} build failed"
    return 1
  fi
}

# Build SaaS API
build_image "saas/Dockerfile" "catalytic-saas" "." || exit 1

# Build Catalytic API
build_image "Dockerfile.catalytic" "catalytic-computing" "." || exit 1

# Build Webhook System
build_image "Dockerfile.webhook" "webhook-system" "." || exit 1

# List built images
log_info "Built images:"
docker images | grep -E "catalytic|webhook" | grep "${FULL_VERSION}"

# Security scanning (if Trivy available)
if command -v trivy >/dev/null 2>&1; then
  log_info "Running security scans..."

  for image in "catalytic-saas" "catalytic-computing" "webhook-system"; do
    log_info "Scanning ${image}..."
    trivy image --severity HIGH,CRITICAL "${REGISTRY}/${image}:${FULL_VERSION}" || log_warning "Vulnerabilities found in ${image}"
  done
else
  log_warning "Trivy not installed - skipping vulnerability scan"
  log_info "Install: https://aquasecurity.github.io/trivy/"
fi

# Push images to registry
log_info "Pushing images to ${REGISTRY}..."

docker login "${REGISTRY}" 2>/dev/null || log_warning "Docker login may be required"

for image in "catalytic-saas" "catalytic-computing" "webhook-system"; do
  log_info "Pushing ${image}..."

  docker push "${REGISTRY}/${image}:${FULL_VERSION}" || exit 1
  docker push "${REGISTRY}/${image}:${ENVIRONMENT}" || exit 1
  docker push "${REGISTRY}/${image}:latest" || exit 1

  log_success "✓ ${image} pushed"
done

# Update Kubernetes manifests
log_info "Updating Kubernetes manifests..."
cd "${PROJECT_ROOT}/k8s"

# Update image references
find . -name "*.yaml" -type f -exec \
  sed -i.bak "s|your-registry/|${REGISTRY}/|g" {} \; -exec rm {}.bak \;

log_success "Manifests updated"

# Generate build manifest
BUILD_MANIFEST="${PROJECT_ROOT}/k8s/build-manifest-${ENVIRONMENT}.json"
cat > "${BUILD_MANIFEST}" <<EOF
{
  "buildDate": "${BUILD_DATE}",
  "version": "${FULL_VERSION}",
  "gitHash": "${GIT_HASH}",
  "environment": "${ENVIRONMENT}",
  "registry": "${REGISTRY}",
  "images": {
    "catalytic-saas": "${REGISTRY}/catalytic-saas:${FULL_VERSION}",
    "catalytic-computing": "${REGISTRY}/catalytic-computing:${FULL_VERSION}",
    "webhook-system": "${REGISTRY}/webhook-system:${FULL_VERSION}"
  }
}
EOF

log_success "Build manifest: ${BUILD_MANIFEST}"

log_success "========================================="
log_success "Phase 2 Complete!"
log_success "========================================="
log_info "Images built: 3"
log_info "Images pushed: 3"
log_info "Next step: Run ../deploy.sh ${ENVIRONMENT}"
