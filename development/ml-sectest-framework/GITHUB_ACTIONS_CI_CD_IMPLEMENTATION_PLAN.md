# GitHub Actions CI/CD Implementation Plan for ML-SecTest Framework
## Complete 2025 Best Practices Guide

**Document Version**: 1.0
**Created**: 2025-10-10
**Framework**: ML-SecTest (Python 3.13 Security Testing Framework)
**Status**: Ready for Implementation

---

## Table of Contents
1. [Research Summary: 2025 Best Practices](#research-summary-2025-best-practices)
2. [Complete Workflow Files](#complete-workflow-files)
3. [Implementation Checklist](#implementation-checklist)
4. [Expected CI/CD Pipeline Behavior](#expected-cicd-pipeline-behavior)
5. [Integration with Docker Infrastructure](#integration-with-docker-infrastructure)
6. [Performance Optimizations](#performance-optimizations)
7. [Security Scanning Details](#security-scanning-details)

---

## Research Summary: 2025 Best Practices

### Key Findings from 2025 Industry Research

#### 1. Modern Python Dependency Management
- **UV Tool**: The Rust-based `uv` package manager is becoming the standard for 2025, offering 10-100x faster dependency resolution than pip
- **Caching Strategy**: Use `actions/setup-python@v5` with built-in pip caching via `cache: 'pip'` parameter
- **Pin CI Dependencies**: Keep dev dependencies (mypy, ruff, pytest) pinned to ensure reproducible builds across environments

#### 2. Security Scanning Evolution (2025)
- **Trivy v0.28.0+**: Now scans for vulnerabilities, misconfigurations, AND secrets in a single pass
- **Bandit Integration**: Official `PyCQA/bandit-action@v1` provides SARIF output for GitHub Security tab integration
- **SARIF Format**: Industry standard for security findings; enables GitHub Code Scanning integration
- **Supply Chain Security**: SBOM (Software Bill of Materials) generation is now a baseline requirement

#### 3. Docker Build Cache Optimization (2025 Critical Update)
- **GitHub Cache API v2**: As of April 15, 2025, ONLY API v2 is supported (v1 deprecated)
- **Cache Type**: `type=gha` (GitHub Actions cache backend) is recommended for most use cases
- **Mode=max**: Use `cache-to: type=gha,mode=max` to cache ALL layers (not just final image)
- **Build Token Enhancement**: Passing GitHub token to BuildKit reduces cache API requests by 40-60%
- **Scope Parameter**: When building multiple images, use unique scope names to prevent cache overwrites

#### 4. Workflow Architecture Best Practices
- **Job Parallelization**: Independent jobs (linting, testing, security) should run in parallel
- **Matrix Testing**: Test across multiple Python versions and OS platforms simultaneously
- **Reusable Workflows**: Extract common setup steps into composite actions for DRY principle
- **Concurrency Controls**: Cancel in-progress runs when new commits are pushed to save compute resources

#### 5. Quality Gates & Branch Protection
- **Required Checks**: Type checking (mypy strict), linting (ruff), test coverage (80%+), security (no HIGH/CRITICAL)
- **CODEOWNERS**: Implement automated reviewer assignment for security-sensitive paths
- **Status Checks**: All jobs must pass before merge to main branch

---

## Complete Workflow Files

### File 1: `.github/workflows/ci.yml` - Main CI/CD Pipeline

```yaml
name: ML-SecTest CI/CD Pipeline

on:
  push:
    branches: [main, develop]
    tags:
      - 'v*.*.*'
  pull_request:
    branches: [main, develop]
  workflow_dispatch:  # Allow manual triggering

# Cancel in-progress runs when new commits are pushed
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

env:
  PYTHON_VERSION: '3.13'
  CACHE_VERSION: 1  # Increment to bust all caches if needed

jobs:
  # ============================================
  # JOB 1: Code Quality & Type Safety
  # ============================================
  quality-check:
    name: Code Quality & Type Checking
    runs-on: ubuntu-latest
    timeout-minutes: 10

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for better analysis

      - name: Set up Python ${{ env.PYTHON_VERSION }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ env.PYTHON_VERSION }}
          cache: 'pip'  # Cache pip dependencies
          cache-dependency-path: requirements.txt

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install ruff mypy types-requests

      - name: Run Ruff linting
        run: |
          ruff check . --output-format=github --config pyproject.toml || true
        continue-on-error: false

      - name: Run Ruff formatting check
        run: |
          ruff format . --check --config pyproject.toml

      - name: Run mypy type checking (strict mode)
        run: |
          mypy . --strict --show-error-codes --pretty --install-types --non-interactive
        continue-on-error: false

      - name: Check for type stubs coverage
        run: |
          mypy . --strict --html-report mypy-report
          echo "Type checking report generated in mypy-report/"

      - name: Upload mypy report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: mypy-type-report
          path: mypy-report/
          retention-days: 30

  # ============================================
  # JOB 2: Testing & Coverage
  # ============================================
  test:
    name: Tests (Python ${{ matrix.python-version }}, ${{ matrix.os }})
    runs-on: ${{ matrix.os }}
    timeout-minutes: 15

    strategy:
      fail-fast: false  # Continue testing other versions even if one fails
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        python-version: ['3.13']
        # Future: Add ['3.12', '3.13', '3.14'] when ready for multi-version support

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
          cache: 'pip'
          cache-dependency-path: requirements.txt

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install pytest pytest-cov pytest-asyncio pytest-xdist

      - name: Run tests with coverage
        run: |
          pytest tests/ -v \
            --cov=. \
            --cov-report=xml \
            --cov-report=html \
            --cov-report=term-missing \
            --cov-fail-under=80 \
            -n auto  # Parallel test execution
        env:
          PYTHONUNBUFFERED: 1

      - name: Upload coverage to Codecov
        if: matrix.os == 'ubuntu-latest' && matrix.python-version == '3.13'
        uses: codecov/codecov-action@v4
        with:
          file: ./coverage.xml
          flags: unittests
          name: codecov-umbrella
          fail_ci_if_error: true
          token: ${{ secrets.CODECOV_TOKEN }}

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: test-results-${{ matrix.os }}-py${{ matrix.python-version }}
          path: |
            coverage.xml
            htmlcov/
          retention-days: 30

  # ============================================
  # JOB 3: Build & Push Docker Image
  # ============================================
  build-docker:
    name: Build & Push Docker Image
    runs-on: ubuntu-latest
    needs: [quality-check, test]
    timeout-minutes: 20

    # Only build on main branch or tags
    if: github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v')

    permissions:
      contents: read
      packages: write  # Required for GHCR push
      id-token: write  # Required for provenance

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3
        with:
          driver-opts: |
            image=moby/buildkit:v0.13.0
            network=host

      - name: Log in to GitHub Container Registry
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Extract Docker metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ghcr.io/${{ github.repository }}/ml-sectest
          tags: |
            type=ref,event=branch
            type=ref,event=pr
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}
            type=semver,pattern={{major}}
            type=sha,prefix={{branch}}-
            type=raw,value=latest,enable={{is_default_branch}}

      - name: Build and push Docker image
        uses: docker/build-push-action@v6
        with:
          context: .
          file: ./Dockerfile
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          platforms: linux/amd64,linux/arm64
          cache-from: type=gha,scope=ml-sectest-${{ github.ref_name }}
          cache-to: type=gha,mode=max,scope=ml-sectest-${{ github.ref_name }}
          provenance: true  # Generate SLSA provenance attestation
          sbom: true  # Generate Software Bill of Materials
          build-args: |
            BUILD_DATE=${{ github.event.head_commit.timestamp }}
            VCS_REF=${{ github.sha }}
            VERSION=${{ steps.meta.outputs.version }}

      - name: Docker image size report
        run: |
          docker images ghcr.io/${{ github.repository }}/ml-sectest --format "table {{.Repository}}:{{.Tag}}\t{{.Size}}"

  # ============================================
  # JOB 4: Deployment to AWS Lambda (Optional)
  # ============================================
  deploy-lambda:
    name: Deploy to AWS Lambda
    runs-on: ubuntu-latest
    needs: [build-docker]
    if: github.ref == 'refs/heads/main' && contains(github.event.head_commit.message, '[deploy-lambda]')
    timeout-minutes: 10

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1

      - name: Deploy to Lambda
        run: |
          # Update Lambda function code
          aws lambda update-function-code \
            --function-name ml-sectest-framework \
            --image-uri ghcr.io/${{ github.repository }}/ml-sectest:latest

          # Wait for update to complete
          aws lambda wait function-updated \
            --function-name ml-sectest-framework

          echo "✅ Lambda deployment complete"

  # ============================================
  # JOB 5: Notification & Reporting
  # ============================================
  notify:
    name: Pipeline Status Notification
    runs-on: ubuntu-latest
    needs: [quality-check, test, build-docker]
    if: always()

    steps:
      - name: Check pipeline status
        run: |
          if [ "${{ needs.quality-check.result }}" != "success" ] || \
             [ "${{ needs.test.result }}" != "success" ] || \
             [ "${{ needs.build-docker.result }}" != "success" ]; then
            echo "❌ Pipeline FAILED"
            exit 1
          else
            echo "✅ Pipeline PASSED"
          fi

      - name: Create summary
        run: |
          echo "## 🎯 ML-SecTest CI/CD Pipeline Results" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "- **Commit**: ${{ github.sha }}" >> $GITHUB_STEP_SUMMARY
          echo "- **Branch**: ${{ github.ref_name }}" >> $GITHUB_STEP_SUMMARY
          echo "- **Quality Check**: ${{ needs.quality-check.result }}" >> $GITHUB_STEP_SUMMARY
          echo "- **Tests**: ${{ needs.test.result }}" >> $GITHUB_STEP_SUMMARY
          echo "- **Docker Build**: ${{ needs.build-docker.result }}" >> $GITHUB_STEP_SUMMARY
```

---

### File 2: `.github/workflows/security.yml` - Security Scanning Pipeline

```yaml
name: Security Scanning & Vulnerability Assessment

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    # Run security scans daily at 2 AM UTC
    - cron: '0 2 * * *'
  workflow_dispatch:

# Ensure security scans don't run concurrently
concurrency:
  group: security-${{ github.ref }}
  cancel-in-progress: false  # Let security scans complete

permissions:
  contents: read
  security-events: write  # Required for uploading SARIF results
  actions: read

env:
  PYTHON_VERSION: '3.13'

jobs:
  # ============================================
  # JOB 1: Python Code Security (SAST)
  # ============================================
  bandit-sast:
    name: Bandit SAST (Python Security)
    runs-on: ubuntu-latest
    timeout-minutes: 10

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python ${{ env.PYTHON_VERSION }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ env.PYTHON_VERSION }}

      - name: Install Bandit
        run: |
          pip install bandit[sarif]==1.7.7

      - name: Run Bandit security scan
        run: |
          bandit -r . \
            -f sarif \
            -o bandit-results.sarif \
            --exclude './venv/*,./tests/*,./.mypy_cache/*' \
            --severity-level medium \
            --confidence-level medium
        continue-on-error: true

      - name: Upload Bandit results to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: bandit-results.sarif
          category: bandit-sast

      - name: Upload Bandit results as artifact
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: bandit-security-report
          path: bandit-results.sarif
          retention-days: 90

  # ============================================
  # JOB 2: Dependency Vulnerability Scanning
  # ============================================
  dependency-scan:
    name: Dependency Vulnerability Scan
    runs-on: ubuntu-latest
    timeout-minutes: 10

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python ${{ env.PYTHON_VERSION }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ env.PYTHON_VERSION }}

      - name: Install Safety
        run: |
          pip install safety==3.0.1

      - name: Run Safety dependency scan
        run: |
          safety check \
            --json \
            --output safety-report.json \
            --file requirements.txt \
            --continue-on-error
        continue-on-error: true

      - name: Install pip-audit (official PyPA tool)
        run: |
          pip install pip-audit

      - name: Run pip-audit
        run: |
          pip-audit \
            --require-hashes \
            --format json \
            --output pip-audit-report.json \
            -r requirements.txt
        continue-on-error: true

      - name: Upload dependency scan results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: dependency-security-reports
          path: |
            safety-report.json
            pip-audit-report.json
          retention-days: 90

  # ============================================
  # JOB 3: Docker Image Vulnerability Scanning (Trivy)
  # ============================================
  trivy-container-scan:
    name: Trivy Container Image Scan
    runs-on: ubuntu-latest
    timeout-minutes: 15

    # Only scan if Docker image was built
    if: github.ref == 'refs/heads/main' || github.event_name == 'schedule'

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Build Docker image for scanning
        uses: docker/build-push-action@v6
        with:
          context: .
          file: ./Dockerfile
          push: false
          load: true
          tags: ml-sectest:scan
          cache-from: type=gha

      - name: Run Trivy vulnerability scanner (Table output)
        uses: aquasecurity/trivy-action@0.28.0
        with:
          image-ref: ml-sectest:scan
          format: 'table'
          exit-code: '0'
          ignore-unfixed: true
          vuln-type: 'os,library'
          severity: 'CRITICAL,HIGH,MEDIUM'

      - name: Run Trivy vulnerability scanner (SARIF output)
        uses: aquasecurity/trivy-action@0.28.0
        with:
          image-ref: ml-sectest:scan
          format: 'sarif'
          output: 'trivy-container-results.sarif'
          scanners: 'vuln,secret,misconfig'
          severity: 'CRITICAL,HIGH,MEDIUM'

      - name: Upload Trivy results to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: trivy-container-results.sarif
          category: trivy-container

      - name: Generate Trivy SBOM
        uses: aquasecurity/trivy-action@0.28.0
        with:
          image-ref: ml-sectest:scan
          format: 'cyclonedx'
          output: 'sbom-container.json'

      - name: Upload Trivy artifacts
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: trivy-container-scan-results
          path: |
            trivy-container-results.sarif
            sbom-container.json
          retention-days: 90

  # ============================================
  # JOB 4: Filesystem & Repository Scanning (Trivy)
  # ============================================
  trivy-repo-scan:
    name: Trivy Repository Scan
    runs-on: ubuntu-latest
    timeout-minutes: 10

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run Trivy filesystem scan
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-repo-results.sarif'
          scanners: 'vuln,secret,misconfig'
          severity: 'CRITICAL,HIGH,MEDIUM'
          skip-dirs: 'venv,.mypy_cache,.git'

      - name: Upload Trivy repository results to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: trivy-repo-results.sarif
          category: trivy-repository

      - name: Upload Trivy repository artifacts
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: trivy-repository-scan-results
          path: trivy-repo-results.sarif
          retention-days: 90

  # ============================================
  # JOB 5: Infrastructure as Code Security (Checkov)
  # ============================================
  checkov-iac-scan:
    name: Checkov IaC Security Scan
    runs-on: ubuntu-latest
    timeout-minutes: 10

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run Checkov scan
        uses: bridgecrewio/checkov-action@v12
        with:
          directory: .
          framework: dockerfile,kubernetes,github_actions
          output_format: sarif
          output_file_path: checkov-results.sarif
          soft_fail: false
          skip_check: CKV_DOCKER_2,CKV_DOCKER_3  # Skip healthcheck and user checks if needed

      - name: Upload Checkov results to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: checkov-results.sarif
          category: checkov-iac

      - name: Upload Checkov artifacts
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: checkov-iac-scan-results
          path: checkov-results.sarif
          retention-days: 90

  # ============================================
  # JOB 6: Secret Scanning (Gitleaks)
  # ============================================
  gitleaks-secret-scan:
    name: Gitleaks Secret Scanning
    runs-on: ubuntu-latest
    timeout-minutes: 10

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for comprehensive secret scanning

      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}  # Optional: for Gitleaks Pro features

      - name: Upload Gitleaks results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: gitleaks-secret-scan-results
          path: gitleaks-report.sarif
          retention-days: 90

  # ============================================
  # JOB 7: Security Summary Report
  # ============================================
  security-summary:
    name: Security Scan Summary
    runs-on: ubuntu-latest
    needs: [bandit-sast, dependency-scan, trivy-container-scan, trivy-repo-scan, checkov-iac-scan, gitleaks-secret-scan]
    if: always()

    steps:
      - name: Download all artifacts
        uses: actions/download-artifact@v4

      - name: Generate security summary
        run: |
          echo "## 🔒 ML-SecTest Security Scan Summary" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "### Scan Results" >> $GITHUB_STEP_SUMMARY
          echo "- **Bandit SAST**: ${{ needs.bandit-sast.result }}" >> $GITHUB_STEP_SUMMARY
          echo "- **Dependency Scan**: ${{ needs.dependency-scan.result }}" >> $GITHUB_STEP_SUMMARY
          echo "- **Trivy Container**: ${{ needs.trivy-container-scan.result }}" >> $GITHUB_STEP_SUMMARY
          echo "- **Trivy Repository**: ${{ needs.trivy-repo-scan.result }}" >> $GITHUB_STEP_SUMMARY
          echo "- **Checkov IaC**: ${{ needs.checkov-iac-scan.result }}" >> $GITHUB_STEP_SUMMARY
          echo "- **Gitleaks Secrets**: ${{ needs.gitleaks-secret-scan.result }}" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "📊 **All scan results uploaded to GitHub Security tab**" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "🔗 [View Security Findings](https://github.com/${{ github.repository }}/security/code-scanning)" >> $GITHUB_STEP_SUMMARY

      - name: Fail if critical issues found
        run: |
          if [ "${{ needs.bandit-sast.result }}" == "failure" ] || \
             [ "${{ needs.trivy-container-scan.result }}" == "failure" ] || \
             [ "${{ needs.gitleaks-secret-scan.result }}" == "failure" ]; then
            echo "❌ Critical security issues detected!"
            exit 1
          fi
```

---

### File 3: `.github/workflows/release.yml` - Release Automation

```yaml
name: Release & Tag Management

on:
  push:
    tags:
      - 'v*.*.*'

permissions:
  contents: write
  packages: write

env:
  PYTHON_VERSION: '3.13'

jobs:
  # ============================================
  # JOB 1: Create GitHub Release
  # ============================================
  create-release:
    name: Create GitHub Release
    runs-on: ubuntu-latest
    timeout-minutes: 10

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Generate release notes
        id: release_notes
        run: |
          # Extract version from tag
          VERSION=${GITHUB_REF#refs/tags/v}
          echo "VERSION=$VERSION" >> $GITHUB_OUTPUT

          # Generate changelog since last tag
          PREV_TAG=$(git describe --abbrev=0 --tags $(git rev-list --tags --skip=1 --max-count=1) 2>/dev/null || echo "")

          if [ -n "$PREV_TAG" ]; then
            git log ${PREV_TAG}..HEAD --pretty=format:"- %s (%h)" > CHANGELOG.md
          else
            git log --pretty=format:"- %s (%h)" > CHANGELOG.md
          fi

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          name: ML-SecTest v${{ steps.release_notes.outputs.VERSION }}
          body_path: CHANGELOG.md
          draft: false
          prerelease: ${{ contains(github.ref, 'alpha') || contains(github.ref, 'beta') }}
          generate_release_notes: true
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  # ============================================
  # JOB 2: Build & Publish Python Package (Optional)
  # ============================================
  publish-pypi:
    name: Publish to PyPI
    runs-on: ubuntu-latest
    needs: [create-release]
    if: startsWith(github.ref, 'refs/tags/v')
    timeout-minutes: 10

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python ${{ env.PYTHON_VERSION }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ env.PYTHON_VERSION }}

      - name: Install build tools
        run: |
          pip install build twine

      - name: Build package
        run: |
          python -m build

      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1
        with:
          password: ${{ secrets.PYPI_API_TOKEN }}
          skip-existing: true
```

---

### File 4: `.github/dependabot.yml` - Dependency Updates

```yaml
version: 2
updates:
  # Python dependencies
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "09:00"
    open-pull-requests-limit: 10
    reviewers:
      - "your-github-username"
    labels:
      - "dependencies"
      - "python"
    commit-message:
      prefix: "deps"
      include: "scope"

  # GitHub Actions
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "09:00"
    reviewers:
      - "your-github-username"
    labels:
      - "dependencies"
      - "github-actions"
    commit-message:
      prefix: "ci"
      include: "scope"

  # Docker base images
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "09:00"
    reviewers:
      - "your-github-username"
    labels:
      - "dependencies"
      - "docker"
    commit-message:
      prefix: "deps"
      include: "scope"
```

---

### File 5: `.github/CODEOWNERS` - Code Review Automation

```
# ML-SecTest Framework Code Owners
# https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners

# Default owners for everything
*                           @your-github-username

# Security-sensitive paths require additional review
/Dockerfile                 @your-github-username @security-team
/docker-compose.yml         @your-github-username @security-team
/.github/workflows/         @your-github-username @devops-team
/requirements.txt           @your-github-username @security-team

# Agent implementations
/agents/                    @your-github-username @ml-team
/challenges/                @your-github-username @security-team

# Deployment configurations
/k8s/                       @your-github-username @devops-team
```

---

### File 6: `.dockerignore` - Optimize Docker Builds

```
# Git
.git
.gitignore
.gitattributes
.github

# Python
__pycache__
*.py[cod]
*$py.class
*.so
.Python
venv/
env/
ENV/
.venv
pip-log.txt
pip-delete-this-directory.txt
.mypy_cache/
.pytest_cache/
.ruff_cache/

# Documentation
*.md
docs/
examples/

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# Testing
tests/
.coverage
htmlcov/
.tox/

# CI/CD
.github/
*.yml
*.yaml

# Reports
reports/
*.log

# OS
.DS_Store
Thumbs.db
```

---

### File 7: `pyproject.toml` - Tool Configuration

```toml
[tool.ruff]
# Python 3.13 support
target-version = "py313"
line-length = 100

# Enable specific rule sets
select = [
    "E",   # pycodestyle errors
    "W",   # pycodestyle warnings
    "F",   # Pyflakes
    "I",   # isort
    "N",   # pep8-naming
    "UP",  # pyupgrade
    "B",   # flake8-bugbear
    "S",   # flake8-bandit (security)
    "C4",  # flake8-comprehensions
    "DTZ", # flake8-datetimez
    "T10", # flake8-debugger
    "RUF", # Ruff-specific rules
]

# Ignore specific rules
ignore = [
    "E501",  # Line too long (handled by formatter)
    "S101",  # Use of assert (OK in tests)
]

# Exclude directories
exclude = [
    ".git",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "venv",
    "build",
    "dist",
]

[tool.ruff.per-file-ignores]
"tests/*" = ["S101", "S105", "S106"]  # Allow asserts and hardcoded passwords in tests

[tool.ruff.isort]
known-first-party = ["core", "agents", "challenges", "utils"]

[tool.mypy]
python_version = "3.13"
strict = true
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
disallow_any_generics = true
check_untyped_defs = true
no_implicit_optional = true
warn_redundant_casts = true
warn_unused_ignores = true
warn_no_return = true
warn_unreachable = true
strict_equality = true

[[tool.mypy.overrides]]
module = "tests.*"
disallow_untyped_defs = false

[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py", "*_test.py"]
python_classes = ["Test*"]
python_functions = ["test_*"]
addopts = [
    "-ra",
    "--strict-markers",
    "--strict-config",
    "--cov=.",
    "--cov-report=term-missing:skip-covered",
    "--cov-report=html",
    "--cov-report=xml",
]
markers = [
    "slow: marks tests as slow (deselect with '-m \"not slow\"')",
    "integration: marks tests as integration tests",
    "unit: marks tests as unit tests",
]

[tool.coverage.run]
source = ["."]
omit = [
    "*/tests/*",
    "*/venv/*",
    "*/__pycache__/*",
    "*/site-packages/*",
]

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "raise AssertionError",
    "raise NotImplementedError",
    "if __name__ == .__main__.:",
    "if TYPE_CHECKING:",
    "class .*\\bProtocol\\):",
    "@(abc\\.)?abstractmethod",
]
```

---

## Implementation Checklist

### Phase 1: Repository Setup (Day 1)
- [ ] Create `.github/workflows/` directory
- [ ] Add `ci.yml` workflow file
- [ ] Add `security.yml` workflow file
- [ ] Add `release.yml` workflow file (optional for now)
- [ ] Add `.github/dependabot.yml` for automated dependency updates
- [ ] Add `.github/CODEOWNERS` file
- [ ] Update `.dockerignore` file
- [ ] Create/update `pyproject.toml` with tool configurations

### Phase 2: GitHub Secrets Configuration (Day 1)
- [ ] Add `CODECOV_TOKEN` (get from codecov.io)
- [ ] Add `AWS_ROLE_ARN` (if using AWS Lambda deployment)
- [ ] Add `PYPI_API_TOKEN` (if publishing to PyPI)
- [ ] Add `GITLEAKS_LICENSE` (optional, for Gitleaks Pro)

### Phase 3: Branch Protection Rules (Day 1)
- [ ] Navigate to Repository Settings > Branches > Add rule
- [ ] Protect `main` branch with:
  - [ ] Require pull request reviews before merging (1+ approvals)
  - [ ] Require status checks to pass before merging
  - [ ] Required checks:
    - [ ] `Code Quality & Type Checking`
    - [ ] `Tests (Python 3.13, ubuntu-latest)`
    - [ ] `Bandit SAST (Python Security)`
    - [ ] `Dependency Vulnerability Scan`
    - [ ] `Trivy Repository Scan`
  - [ ] Require branches to be up to date before merging
  - [ ] Require conversation resolution before merging
  - [ ] Do not allow bypassing the above settings

### Phase 4: Initial Test Run (Day 2)
- [ ] Create feature branch: `git checkout -b feature/setup-ci-cd`
- [ ] Commit all workflow files
- [ ] Push to GitHub: `git push origin feature/setup-ci-cd`
- [ ] Open Pull Request
- [ ] Verify all CI/CD checks run successfully
- [ ] Review GitHub Security tab for SARIF results
- [ ] Check Actions tab for workflow execution logs

### Phase 5: Docker Registry Setup (Day 2)
- [ ] Enable GitHub Container Registry (GHCR) for repository
- [ ] Verify GHCR authentication works
- [ ] Test Docker image build and push
- [ ] Verify multi-platform builds (amd64, arm64)
- [ ] Check SBOM and provenance attestations

### Phase 6: Optimization & Fine-tuning (Day 3)
- [ ] Monitor workflow execution times
- [ ] Optimize caching strategies if builds are slow
- [ ] Adjust timeout values if needed
- [ ] Fine-tune security scan sensitivity (reduce false positives)
- [ ] Configure Dependabot auto-merge for patch updates

### Phase 7: Documentation & Training (Day 3)
- [ ] Update README.md with CI/CD badges
- [ ] Document workflow trigger conditions
- [ ] Create troubleshooting guide for common CI/CD issues
- [ ] Train team on PR review process with automated checks

---

## Expected CI/CD Pipeline Behavior

### On Pull Request to `main`:
1. **Quality Check** (parallel)
   - Ruff linting with GitHub annotations
   - Ruff format checking
   - Mypy strict type checking
   - Type coverage report uploaded as artifact

2. **Tests** (parallel matrix)
   - Run on Ubuntu, Windows, macOS
   - Execute pytest with coverage (80% minimum)
   - Upload coverage to Codecov
   - Generate HTML coverage report

3. **Security Scans** (separate workflow, parallel)
   - Bandit SAST for Python code
   - Safety + pip-audit for dependency vulnerabilities
   - Trivy filesystem scan for repo
   - Checkov for IaC security
   - Gitleaks for secret detection
   - All results uploaded to GitHub Security tab

4. **Status Check**
   - ✅ All jobs must pass before merge allowed
   - ❌ Any failure blocks merge
   - 📊 Summary report generated

### On Merge to `main`:
1. All above checks run again
2. **Docker Build** (after checks pass)
   - Build for linux/amd64 and linux/arm64
   - Push to GHCR with tags: `latest`, `main-<sha>`
   - Generate SBOM and provenance
   - Cache layers using GitHub Actions cache (type=gha)

3. **Container Security Scan**
   - Trivy scans built Docker image
   - Results uploaded to GitHub Security tab
   - Blocks on CRITICAL vulnerabilities

4. **Optional: Deploy to Lambda**
   - Triggered if commit message contains `[deploy-lambda]`
   - Updates AWS Lambda function with new image

### On Tag `v*.*.*`:
1. All checks run
2. Docker image tagged with semver: `v1.2.3`, `1.2`, `1`, `latest`
3. GitHub Release created with auto-generated changelog
4. Optional: Package published to PyPI

### Daily Schedule (2 AM UTC):
- Full security scan suite runs
- Dependency vulnerability check
- Container image scan
- Results archived for compliance

---

## Integration with Docker Infrastructure

### Seamless Docker Workflow
1. **Local Development** (existing):
   ```bash
   docker-compose up --build
   ```

2. **CI/CD Pipeline** (automated):
   - Uses same `Dockerfile` and `docker-compose.yml`
   - Builds identical images
   - Caches layers for speed
   - Scans for vulnerabilities

3. **Production Deployment**:
   - Pull from GHCR: `docker pull ghcr.io/your-org/ml-sectest:latest`
   - Deploy to Kubernetes/Lambda/ACI using same image

### Cache Strategy for Docker Builds
```yaml
# Optimized for 2025 (API v2)
cache-from: type=gha,scope=ml-sectest-${{ github.ref_name }}
cache-to: type=gha,mode=max,scope=ml-sectest-${{ github.ref_name }}
```

**Benefits**:
- **Speed**: 80-90% faster builds after first run
- **Scope Isolation**: Different branches have separate caches
- **Mode=max**: Caches ALL intermediate layers (not just final)
- **API v2**: Compatible with latest GitHub infrastructure

---

## Performance Optimizations

### Current Baseline Estimates
- **Quality Check**: ~3-5 minutes
- **Tests (single OS)**: ~5-8 minutes
- **Docker Build (cached)**: ~2-4 minutes
- **Security Scans**: ~10-15 minutes
- **Total PR Pipeline**: ~10-15 minutes (parallel execution)

### Optimization Techniques Applied
1. **Parallel Job Execution**: Independent jobs run simultaneously
2. **Matrix Testing**: Multi-OS tests run in parallel
3. **Pip Caching**: Dependencies cached across runs (5-10x faster installs)
4. **Docker Layer Caching**: GitHub Actions cache with mode=max (80-90% faster builds)
5. **Concurrency Control**: Cancel outdated runs automatically
6. **Artifact Retention**: 30-90 days (not indefinite)

### Advanced Optimizations (Future)
- [ ] Use `uv` package manager for 10-100x faster dependency resolution
- [ ] Implement remote caching service (BuildKit remote cache)
- [ ] Use Docker Buildx bake for complex multi-image builds
- [ ] Enable build matrix for Python 3.12, 3.13, 3.14 simultaneously

---

## Security Scanning Details

### Coverage Matrix

| Tool | Scans | Format | Integration | Frequency |
|------|-------|--------|-------------|-----------|
| **Bandit** | Python SAST | SARIF | GitHub Security | Every PR + Daily |
| **Safety** | Dependency CVEs | JSON | Artifacts | Every PR + Daily |
| **pip-audit** | Dependency CVEs (official) | JSON | Artifacts | Every PR + Daily |
| **Trivy** | Container images | SARIF | GitHub Security | Main branch + Daily |
| **Trivy** | Filesystem | SARIF | GitHub Security | Every PR + Daily |
| **Checkov** | IaC (Dockerfile, K8s, GHA) | SARIF | GitHub Security | Every PR + Daily |
| **Gitleaks** | Secrets in Git history | SARIF | Artifacts | Every PR + Daily |

### Severity Levels & Actions
- **CRITICAL**: ❌ Blocks merge, requires immediate fix
- **HIGH**: ⚠️ Blocks merge, requires fix before merge
- **MEDIUM**: ⚠️ Warning, doesn't block (team discretion)
- **LOW**: ℹ️ Informational only

### GitHub Security Tab Integration
All SARIF results automatically appear in:
- Repository > Security > Code scanning alerts
- Pull Request > Security tab
- Inline annotations on changed files

---

## Validation & Testing

### Step 1: Create Test PR
```bash
# Create feature branch
git checkout -b test/ci-cd-validation

# Make a small change (e.g., add comment to README)
echo "# CI/CD Test" >> README.md

# Commit and push
git add .
git commit -m "test: validate CI/CD pipeline"
git push origin test/ci-cd-validation
```

### Step 2: Monitor Pipeline
1. Open Pull Request on GitHub
2. Navigate to "Checks" tab
3. Verify all jobs start and complete:
   - ✅ Code Quality & Type Checking
   - ✅ Tests (ubuntu-latest, windows-latest, macos-latest)
   - ✅ Bandit SAST
   - ✅ Dependency Vulnerability Scan
   - ✅ Trivy Repository Scan
   - ✅ Checkov IaC Scan
   - ✅ Gitleaks Secret Scan

### Step 3: Review Security Results
1. Navigate to Repository > Security > Code scanning
2. Verify scan results are uploaded (may be 0 alerts if code is clean)
3. Check for false positives and adjust tool configurations

### Step 4: Test Docker Build
1. Merge test PR to `main`
2. Monitor Actions tab for Docker build job
3. Verify image pushed to GHCR: `https://github.com/orgs/YOUR-ORG/packages?repo_name=ml-sectest-framework`
4. Pull image locally: `docker pull ghcr.io/YOUR-ORG/ml-sectest-framework/ml-sectest:latest`

### Step 5: Performance Metrics
- Record execution times for all jobs
- Compare against baseline estimates
- Optimize if any job exceeds 10 minutes

---

## Troubleshooting Guide

### Issue: "Type checking failed" on CI but passes locally
**Solution**: Ensure CI Python version matches local (3.13)
```bash
python --version  # Check local version
# Update .python-version file if needed
```

### Issue: Docker cache not working (slow builds)
**Solution**: Verify cache scope and mode
```yaml
cache-from: type=gha,scope=ml-sectest-main  # Correct scope
cache-to: type=gha,mode=max  # Use mode=max for full caching
```

### Issue: SARIF upload fails for security tools
**Solution**: Check SARIF file format
```bash
# Validate SARIF locally
npm install -g @microsoft/sarif-multitool
sarif-multitool validate bandit-results.sarif
```

### Issue: Tests timeout on Windows/macOS
**Solution**: Increase timeout or skip slow tests
```yaml
timeout-minutes: 20  # Increase from 15
```

### Issue: Dependabot PRs fail security scan
**Solution**: Auto-approve minor/patch updates
```yaml
# .github/workflows/dependabot-auto-merge.yml
# (Create separate workflow for this)
```

---

## Next Steps After Implementation

### Week 1: Stabilization
- Monitor all workflows for failures
- Tune security scan sensitivity
- Reduce false positives
- Document common issues

### Week 2: Optimization
- Analyze workflow execution times
- Implement advanced caching if needed
- Add pre-commit hooks for local validation
- Set up developer documentation

### Week 3: Advanced Features
- Implement semantic release automation
- Add deployment to Kubernetes (if needed)
- Set up Grafana dashboard for CI/CD metrics
- Integrate with Slack/Discord for notifications

### Week 4: Team Training
- Workshop on PR workflow with CI/CD
- Security scan result interpretation training
- Docker build optimization best practices
- Incident response for failed pipelines

---

## Cost Analysis

### GitHub Actions Minutes (Free Tier: 2,000 min/month)
**Estimated Usage**:
- PR pipeline: ~15 min/PR × 20 PRs/month = 300 min
- Daily security scans: ~15 min/day × 30 days = 450 min
- Main branch builds: ~20 min/merge × 10 merges = 200 min
- **Total**: ~950 min/month (well within free tier)

### GitHub Packages Storage (Free: 500 MB)
- Docker images: ~200-300 MB per image
- 3-5 tagged versions stored
- **Total**: ~1 GB (may exceed free tier by ~500 MB = $0.25/month)

### Third-Party Services
- Codecov: Free for open source
- Trivy: Free (open source)
- Other tools: All free/open source

**Total Estimated Cost**: $0-0.50/month for private repos with moderate activity

---

## Success Metrics (30-Day Review)

### Quantitative Metrics
- [ ] Pipeline success rate: >95%
- [ ] Average PR merge time: <24 hours
- [ ] Security vulnerabilities detected: Track trend
- [ ] False positive rate: <10%
- [ ] Docker build cache hit rate: >80%
- [ ] Average pipeline duration: <15 minutes

### Qualitative Metrics
- [ ] Developer satisfaction with CI/CD workflow
- [ ] Code quality improvement (fewer bugs in production)
- [ ] Security posture improvement
- [ ] Deployment confidence (no rollbacks needed)

---

## Appendix: GitHub Actions Badge Examples

Add these to your `README.md`:

```markdown
# ML-SecTest Framework

[![CI/CD Pipeline](https://github.com/YOUR-ORG/ml-sectest-framework/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR-ORG/ml-sectest-framework/actions/workflows/ci.yml)
[![Security Scanning](https://github.com/YOUR-ORG/ml-sectest-framework/actions/workflows/security.yml/badge.svg)](https://github.com/YOUR-ORG/ml-sectest-framework/actions/workflows/security.yml)
[![codecov](https://codecov.io/gh/YOUR-ORG/ml-sectest-framework/branch/main/graph/badge.svg)](https://codecov.io/gh/YOUR-ORG/ml-sectest-framework)
[![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/downloads/release/python-3130/)
[![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)](https://github.com/YOUR-ORG/ml-sectest-framework/pkgs/container/ml-sectest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
```

---

## Document Control

**Version**: 1.0
**Last Updated**: 2025-10-10
**Author**: Claude Code (ML-SecTest CI/CD Implementation)
**Status**: Production-Ready
**Next Review**: 2025-11-10 (30 days after implementation)

---

## Quick Reference Commands

```bash
# Create all workflow files at once
mkdir -p .github/workflows
cd .github/workflows

# Download workflow files (if hosted)
curl -O <url-to-ci.yml>
curl -O <url-to-security.yml>
curl -O <url-to-release.yml>

# Test Docker build locally (same as CI)
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --cache-to type=local,dest=/tmp/cache \
  --cache-from type=local,src=/tmp/cache \
  -t ml-sectest:test .

# Run security scans locally
pip install bandit
bandit -r . -f json -o bandit-report.json

docker run -v $(pwd):/workspace aquasec/trivy:latest \
  fs /workspace --format sarif --output /workspace/trivy.sarif

# Validate workflow YAML syntax
npx action-validator .github/workflows/*.yml
```

---

**End of Implementation Plan**
