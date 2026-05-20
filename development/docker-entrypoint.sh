#!/bin/bash
# Docker entrypoint for Catalytic Computing SaaS Platform
# Handles runtime initialization including RSA key generation

set -e

echo "Starting Catalytic Computing SaaS Platform..."

# Generate RSA keys at runtime if not present
if [ ! -f /app/keys/jwt_private.pem ]; then
    echo "Generating RSA keys for JWT signing..."
    python -c "from saas.auth.jwt_auth import RSAKeyManager; RSAKeyManager()"
    echo "✓ RSA keys generated successfully"
else
    echo "✓ RSA keys already exist"
fi

# Verify critical environment variables
if [ -z "$JWT_SECRET_KEY" ]; then
    echo "ERROR: JWT_SECRET_KEY environment variable is not set!"
    exit 1
fi

if [ "$ENVIRONMENT" = "production" ]; then
    # Production validation
    if [ "$JWT_SECRET_KEY" = "change_me_to_secure_random_key" ]; then
        echo "ERROR: Default JWT_SECRET_KEY detected in production environment!"
        exit 1
    fi

    if [ -z "$DATABASE_URL" ]; then
        echo "ERROR: DATABASE_URL not set in production!"
        exit 1
    fi

    echo "✓ Production environment variables validated"
fi

echo "✓ All checks passed. Starting application..."
echo ""

# Start the application
exec "$@"
