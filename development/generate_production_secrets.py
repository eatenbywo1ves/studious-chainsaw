#!/usr/bin/env python3
"""
Production Secrets Generator
=============================

Generates cryptographically secure random secrets for production deployment.

Usage:
    python generate_production_secrets.py

This script will generate:
- JWT_SECRET_KEY (64-byte URL-safe token)
- REDIS_PASSWORD (32-byte strong password)
- SESSION_SECRET_KEY (64-byte URL-safe token)
- DATABASE_PASSWORD (32-byte strong password)
- RSA key pair for JWT signing (4096-bit)

Author: Configuration Migration Team
Date: 2025-10-23
Related: .env.production.template, PRODUCTION_DEPLOYMENT_CHECKLIST.md
"""

import secrets
import string
import subprocess
import sys
from pathlib import Path
from typing import Dict


def generate_url_safe_token(nbytes: int = 64) -> str:
    """Generate a URL-safe token using secrets module."""
    return secrets.token_urlsafe(nbytes)


def generate_strong_password(length: int = 32) -> str:
    """
    Generate a strong password with mixed character types.
    Suitable for database passwords, Redis passwords, etc.
    """
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        # Ensure password has at least one of each type
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)
                and any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in password)):
            return password


def generate_rsa_keypair(output_dir: Path = Path("./secrets"), key_size: int = 4096) -> Dict[str, str]:
    """
    Generate RSA key pair for JWT signing using ssh-keygen.

    Args:
        output_dir: Directory to store the keys
        key_size: RSA key size in bits (4096 recommended)

    Returns:
        Dict with 'private_key_path' and 'public_key_path'
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    private_key_path = output_dir / "jwt_rsa"
    public_key_path = output_dir / "jwt_rsa.pub"

    # Check if ssh-keygen is available
    try:
        subprocess.run(
            ["ssh-keygen", "-t", "rsa", "-b", str(key_size), "-m", "PEM",
             "-f", str(private_key_path), "-N", ""],
            check=True,
            capture_output=True,
            text=True
        )

        return {
            "private_key_path": str(private_key_path.absolute()),
            "public_key_path": str(public_key_path.absolute())
        }
    except subprocess.CalledProcessError as e:
        print(f"Warning: Could not generate RSA keys: {e}", file=sys.stderr)
        print("You can generate them manually with:", file=sys.stderr)
        print(f"  ssh-keygen -t rsa -b {key_size} -m PEM -f jwt_rsa", file=sys.stderr)
        return {
            "private_key_path": "NOT_GENERATED",
            "public_key_path": "NOT_GENERATED"
        }
    except FileNotFoundError:
        print("Warning: ssh-keygen not found. Install OpenSSH to generate RSA keys.", file=sys.stderr)
        print("Alternatively, use online tools or OpenSSL:", file=sys.stderr)
        print(f"  openssl genrsa -out jwt_rsa {key_size}", file=sys.stderr)
        print("  openssl rsa -in jwt_rsa -pubout -out jwt_rsa.pub", file=sys.stderr)
        return {
            "private_key_path": "NOT_GENERATED",
            "public_key_path": "NOT_GENERATED"
        }


def format_env_output(secrets_dict: Dict[str, str]) -> str:
    """Format secrets as .env file content."""
    lines = ["# Generated Production Secrets", "# Generated: 2025-10-23", ""]

    for key, value in secrets_dict.items():
        lines.append(f"{key}={value}")

    return "\n".join(lines)


def main():
    """Generate all production secrets and display them."""

    print("=" * 80)
    print("PRODUCTION SECRETS GENERATOR")
    print("=" * 80)
    print()
    print("Generating cryptographically secure secrets...")
    print()

    # Generate all secrets
    secrets_dict = {
        "JWT_SECRET_KEY": generate_url_safe_token(64),
        "SESSION_SECRET_KEY": generate_url_safe_token(64),
        "REDIS_PASSWORD": generate_strong_password(32),
        "DATABASE_PASSWORD": generate_strong_password(32),
    }

    # Generate RSA keypair
    print("Generating RSA key pair for JWT signing...")
    rsa_keys = generate_rsa_keypair()

    # Display results
    print("=" * 80)
    print("GENERATED SECRETS (SAVE THESE SECURELY)")
    print("=" * 80)
    print()
    print("Copy these values to your .env.production file:")
    print()
    print("-" * 80)
    print(format_env_output(secrets_dict))
    print()

    if rsa_keys["private_key_path"] != "NOT_GENERATED":
        print(f"JWT_PRIVATE_KEY_PATH={rsa_keys['private_key_path']}")
        print(f"JWT_PUBLIC_KEY_PATH={rsa_keys['public_key_path']}")
        print()
        print("RSA keys generated successfully:")
        print(f"  Private key: {rsa_keys['private_key_path']}")
        print(f"  Public key: {rsa_keys['public_key_path']}")
    else:
        print("# RSA keys not generated - see warnings above")

    print("-" * 80)
    print()

    # Security warnings
    print("=" * 80)
    print("SECURITY WARNINGS")
    print("=" * 80)
    print()
    print("1. NEVER commit these secrets to version control")
    print("2. Store secrets in a secure secret management system:")
    print("   - AWS Secrets Manager")
    print("   - HashiCorp Vault")
    print("   - Azure Key Vault")
    print("   - Environment variables in your deployment platform")
    print()
    print("3. Rotate secrets regularly (every 90 days minimum)")
    print("4. Use different secrets for each environment (dev/staging/prod)")
    print("5. Restrict access to secrets to only necessary personnel")
    print()

    # Save to file option
    print("=" * 80)
    print("OPTIONAL: Save to file")
    print("=" * 80)
    print()
    response = input("Save secrets to .env.production? (yes/no): ").strip().lower()

    if response in ['yes', 'y']:
        env_file = Path(".env.production")

        if env_file.exists():
            print(f"WARNING: {env_file} already exists!")
            overwrite = input("Overwrite? (yes/no): ").strip().lower()
            if overwrite not in ['yes', 'y']:
                print("Aborted. Secrets not saved to file.")
                return

        # Write to file
        with open(env_file, 'w') as f:
            f.write(format_env_output(secrets_dict))
            f.write("\n")
            if rsa_keys["private_key_path"] != "NOT_GENERATED":
                f.write(f"JWT_PRIVATE_KEY_PATH={rsa_keys['private_key_path']}\n")
                f.write(f"JWT_PUBLIC_KEY_PATH={rsa_keys['public_key_path']}\n")

        print(f"Secrets saved to {env_file.absolute()}")
        print()
        print("IMPORTANT: Add .env.production to .gitignore immediately!")
    else:
        print("Secrets not saved to file. Make sure to copy them from above!")

    print()
    print("=" * 80)
    print("Next Steps:")
    print("=" * 80)
    print("1. Copy the generated secrets to your secure storage")
    print("2. Complete .env.production.template with remaining values")
    print("3. Review PRODUCTION_DEPLOYMENT_CHECKLIST.md")
    print("4. Test configuration in staging environment")
    print("5. Deploy to production")
    print()


if __name__ == "__main__":
    main()
