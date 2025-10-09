#!/usr/bin/env python3
"""
Security Integration Script
Integrates security components into the SaaS application codebase
"""

import sys
import shutil
import re
from pathlib import Path

# Color codes
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
RED = "\033[0;31m"
NC = "\033[0m"  # No Color


class SecurityIntegrator:
    """Integrates security components into application"""

    def __init__(self, project_root: Path, env: str = "development"):
        self.project_root = project_root
        self.security_dir = project_root / "security"
        self.saas_dir = project_root / "saas"
        self.env = env

    def print_step(self, message: str):
        """Print colored step message"""
        print(f"{BLUE}{message}{NC}")

    def print_success(self, message: str):
        """Print colored success message"""
        print(f"{GREEN}[OK] {message}{NC}")

    def print_warning(self, message: str):
        """Print colored warning message"""
        print(f"{YELLOW}[WARN] {message}{NC}")

    def print_error(self, message: str):
        """Print colored error message"""
        print(f"{RED}[ERROR] {message}{NC}")

    def backup_file(self, file_path: Path) -> Path:
        """Create backup of file before modification"""
        backup_path = file_path.with_suffix(file_path.suffix + ".backup")
        if file_path.exists():
            shutil.copy2(file_path, backup_path)
            return backup_path
        return None

    def create_requirements(self):
        """Create security-requirements.txt"""
        self.print_step("Creating security requirements file...")

        requirements = """# Security Dependencies for Catalytic Computing Platform

# JWT and Cryptography
PyJWT==2.8.0
cryptography==41.0.7
python-jose[cryptography]==3.3.0

# Rate Limiting and DDoS Protection
slowapi==0.1.9
redis==5.0.1
aioredis==2.0.1

# Input Validation
pydantic==2.5.0
email-validator==2.1.0
phonenumbers==8.13.26

# Security Monitoring
python-logstash==0.4.8
sentry-sdk==1.38.0

# CORS and Session Management
fastapi-cors==0.0.6
itsdangerous==2.1.2

# Additional Security Tools
bleach==6.1.0  # HTML sanitization
argon2-cffi==23.1.0  # Password hashing
"""

        req_file = self.security_dir / "security-requirements.txt"
        with open(req_file, "w") as f:
            f.write(requirements)

        self.print_success(f"Security requirements file created: {req_file}")

        # Merge with existing requirements
        saas_req = self.saas_dir / "api" / "requirements.txt"
        if saas_req.exists():
            self.print_step("Merging with existing requirements...")
            with open(saas_req, "a") as f:
                f.write("\n# Security dependencies\n")
                f.write(requirements)
            self.print_success("Requirements merged")

    def integrate_jwt_security(self):
        """Integrate JWT security into SaaS API"""
        self.print_step("Integrating JWT security into SaaS API...")

        api_server = self.saas_dir / "api" / "saas_server.py"

        if not api_server.exists():
            self.print_warning(f"API server not found: {api_server}")
            return

        # Backup original
        self.backup_file(api_server)

        # Read current content
        with open(api_server, "r") as f:
            content = f.read()

        # Add imports if not present
        if "from security.application.jwt_security import" not in content:
            import_block = """
# Security imports
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))
from security.application.jwt_security import (
    JWTSecurityManager,
    TokenType,
    SecurityLevel
)
from security.application.rate_limiting import (
    RateLimitMiddleware,
    DDoSProtectionMiddleware,
    RateLimitConfig
)
from security.application.input_validation import (
    SecureInputValidator,
    sanitize_input,
    ValidationLevel
)
"""
            # Insert after existing imports
            content = re.sub(r"(from fastapi import.*?\n)", r"\1" + import_block, content, count=1)

        # Add JWT manager initialization
        if "jwt_manager = JWTSecurityManager" not in content:
            jwt_init = """
# Initialize JWT Security Manager
jwt_manager = JWTSecurityManager(
    private_key_path=os.getenv("JWT_PRIVATE_KEY_PATH", "/app/keys/jwt_development_private.pem"),
    public_key_path=os.getenv("JWT_PUBLIC_KEY_PATH", "/app/keys/jwt_development_public.pem"),
    access_token_expire_minutes=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "15")),
    refresh_token_expire_days=int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "7")),
    security_level=SecurityLevel[os.getenv("SECURITY_LEVEL", "ENHANCED").upper()]
)

# Initialize Input Validator
input_validator = SecureInputValidator(
    validation_level=ValidationLevel[os.getenv("VALIDATION_LEVEL", "STRICT").upper()]
)
"""
            # Insert after app creation
            content = re.sub(
                r"(app = FastAPI\(.*?\))", r"\1\n" + jwt_init, content, flags=re.DOTALL
            )

        # Add middleware
        if "app.add_middleware(RateLimitMiddleware" not in content:
            middleware_block = """
# Add security middleware
rate_limit_config = RateLimitConfig(
    enabled=os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true",
    requests_per_minute=int(os.getenv("RATE_LIMIT_PER_MINUTE", "60")),
    burst_size=int(os.getenv("RATE_LIMIT_BURST", "10"))
)

app.add_middleware(RateLimitMiddleware, config=rate_limit_config)

if os.getenv("DDOS_PROTECTION_ENABLED", "true").lower() == "true":
    app.add_middleware(DDoSProtectionMiddleware,
                       block_duration=int(os.getenv("DDOS_BLOCK_DURATION_MINUTES", "60")))
"""
            # Insert after middleware section
            content = re.sub(
                r"(app\.add_middleware\(CORSMiddleware.*?\))",
                r"\1\n" + middleware_block,
                content,
                flags=re.DOTALL,
                count=1,
            )

        # Write updated content
        with open(api_server, "w") as f:
            f.write(content)

        self.print_success("JWT security integrated into API server")

    def create_env_file(self):
        """Create .env file from template"""
        self.print_step("Creating .env file...")

        env_template = self.security_dir / f".env.{self.env}.template"
        env_file = self.saas_dir / ".env"

        if not env_template.exists():
            self.print_warning(f"Environment template not found: {env_template}")
            self.print_warning("Run 01-setup-keys.sh first to generate templates")
            return

        if env_file.exists():
            self.print_warning(f".env file already exists: {env_file}")
            response = input("Overwrite? (y/N): ")
            if response.lower() != "y":
                return

        shutil.copy2(env_template, env_file)
        self.print_success(f".env file created from template: {env_file}")
        self.print_warning("Remember to customize .env with your specific configuration")

    def create_docker_compose_override(self):
        """Create docker-compose.override.yml with security settings"""
        self.print_step("Creating docker-compose.override.yml...")

        override_content = """version: '3.8'

# Security overlay for docker-compose
# This file overrides base docker-compose.yml with security settings

services:
  api:
    security_opt:
      - no-new-privileges:true
      - apparmor=docker-default
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    read_only: true
    tmpfs:
      - /tmp
      - /var/run
    environment:
      - JWT_PRIVATE_KEY_PATH=/app/keys/jwt_development_private.pem
      - JWT_PUBLIC_KEY_PATH=/app/keys/jwt_development_public.pem
      - SECURITY_LEVEL=enhanced
      - RATE_LIMIT_ENABLED=true
    volumes:
      - ../security/keys:/app/keys:ro

  frontend:
    security_opt:
      - no-new-privileges:true
      - apparmor=docker-default
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    read_only: true
    tmpfs:
      - /tmp
      - /.next/cache
    environment:
      - NEXTAUTH_SECRET=${SESSION_SECRET_KEY}
      - CSRF_SECRET=${CSRF_SECRET_KEY}
"""

        override_file = self.saas_dir / "docker-compose.override.yml"
        with open(override_file, "w") as f:
            f.write(override_content)

        self.print_success(f"Docker compose override created: {override_file}")

    def create_deployment_docs(self):
        """Create security deployment documentation"""
        self.print_step("Creating deployment documentation...")

        docs_content = """# Security Implementation Deployment Guide

## Quick Start

1. **Generate Security Keys**
   ```bash
   cd security/deployment
   ./01-setup-keys.sh development
   ```

2. **Build and Scan Containers**
   ```bash
   ./02-build-containers.sh development
   ```

3. **Deploy Kubernetes Security (if using K8s)**
   ```bash
   ./03-deploy-k8s-security.sh staging
   ```

4. **Integrate Application Security**
   ```bash
   python 04-integrate-application.py development
   ```

5. **Deploy Application**
   ```bash
   cd ../../saas
   docker-compose up -d
   ```

## Environment Variables

Create `.env` file in saas/ directory:

```bash
# Copy from template
cp security/.env.development.template saas/.env

# Edit with your configuration
vi saas/.env
```

## Testing Security

1. **Test JWT Authentication**
   ```bash
   curl -X POST http://localhost:8000/auth/login \\
     -H "Content-Type: application/json" \\
     -d '{"username":"admin","password":"secure123"}'
   ```

2. **Test Rate Limiting**
   ```bash
   for i in {1..100}; do
     curl http://localhost:8000/api/test
   done
   ```

3. **Run Security Scan**
   ```bash
   cd security/container
   ./security-scanner.sh
   ```

## Monitoring

- **Security Dashboard**: http://localhost:3000/dashboards/security
- **Prometheus Alerts**: http://localhost:9090/alerts
- **Log Aggregation**: Check security/monitoring/

## Troubleshooting

### JWT Key Errors
- Verify keys exist in security/keys/
- Check file permissions (600 for private key)
- Verify environment variables point to correct paths

### Rate Limiting Issues
- Check Redis connection
- Verify RATE_LIMIT_ENABLED=true in .env
- Review rate limit configuration

### Container Security Scan Failures
- Fix reported vulnerabilities
- Update base images
- Review Trivy scan reports

## Production Checklist

- [ ] Generate production RSA keys
- [ ] Configure production .env
- [ ] Run full security scan (0 HIGH/CRITICAL)
- [ ] Deploy network policies
- [ ] Enable monitoring and alerting
- [ ] Test disaster recovery
- [ ] Schedule regular security audits

---
Generated: {date}
Environment: {env}
"""

        docs_file = self.security_dir / "deployment" / "README.md"
        with open(docs_file, "w") as f:
            from datetime import datetime

            content = docs_content.format(date=datetime.now().strftime("%Y-%m-%d"), env=self.env)
            f.write(content)

        self.print_success(f"Deployment documentation created: {docs_file}")

    def run(self):
        """Run full integration"""
        print(f"{GREEN}=== Security Integration ==={NC}")
        print(f"Environment: {self.env}")
        print(f"Project root: {self.project_root}")
        print()

        try:
            self.create_requirements()
            self.integrate_jwt_security()
            self.create_env_file()
            self.create_docker_compose_override()
            self.create_deployment_docs()

            print()
            print(f"{GREEN}=== Integration Complete ==={NC}")
            print()
            print("Next steps:")
            print("  1. Review generated files")
            print("  2. Customize .env file with your configuration")
            print(
                "  3. Install security dependencies: pip install -r security/security-requirements.txt"
            )
            print("  4. Test application with security enabled")
            print()
            print(
                f"{YELLOW}Important: Review all generated code before deploying to production!{NC}"
            )

        except Exception as e:
            self.print_error(f"Integration failed: {e}")
            import traceback

            traceback.print_exc()
            sys.exit(1)


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="Integrate security components into application")
    parser.add_argument(
        "env",
        nargs="?",
        default="development",
        help="Environment (development, staging, production)",
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).parent.parent.parent,
        help="Project root directory",
    )

    args = parser.parse_args()

    integrator = SecurityIntegrator(args.project_root, args.env)
    integrator.run()


if __name__ == "__main__":
    main()
