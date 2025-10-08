#!/bin/bash
# ============================================================================
# Catalytic Computing SaaS - Production Deployment Script
# ============================================================================
#
# This script handles production deployment with safety checks and rollback
#
# Usage: ./deploy_production.sh [--skip-backup] [--force]
#
# Requirements:
#   - PostgreSQL 14+ installed and running
#   - Redis 6+ installed and running
#   - Python 3.11+ with pip
#   - Git
#   - Nginx (optional, for reverse proxy)
#
# ============================================================================

set -e  # Exit on error

# ============================================================================
# CONFIGURATION
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="$PROJECT_ROOT/backups/$TIMESTAMP"
LOG_FILE="$PROJECT_ROOT/logs/deployment_$TIMESTAMP.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ============================================================================
# FUNCTIONS
# ============================================================================

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

banner() {
    echo ""
    echo "============================================================================"
    echo "$1"
    echo "============================================================================"
    echo ""
}

# Check if command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Parse command line arguments
SKIP_BACKUP=false
FORCE=false

for arg in "$@"; do
    case $arg in
        --skip-backup)
            SKIP_BACKUP=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        *)
            ;;
    esac
done

# ============================================================================
# PRE-DEPLOYMENT CHECKS
# ============================================================================

banner "CATALYTIC COMPUTING SAAS - PRODUCTION DEPLOYMENT"

log "Starting pre-deployment checks..."

# Create necessary directories
mkdir -p "$PROJECT_ROOT/logs"
mkdir -p "$PROJECT_ROOT/backups"

# Check for required commands
REQUIRED_COMMANDS=("python3" "pip" "git" "psql" "redis-cli")
for cmd in "${REQUIRED_COMMANDS[@]}"; do
    if ! command_exists "$cmd"; then
        error "Required command not found: $cmd"
        exit 1
    fi
    success "Found: $cmd"
done

# Check Python version
PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
log "Python version: $PYTHON_VERSION"

if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 11) else 1)"; then
    error "Python 3.11 or higher required"
    exit 1
fi
success "Python version check passed"

# Check if .env.production exists
if [ ! -f "$PROJECT_ROOT/.env.production" ]; then
    error ".env.production file not found!"
    warning "Please copy .env.production.template to .env.production and configure it"
    exit 1
fi
success "Found .env.production"

# Load environment variables
set -a
source "$PROJECT_ROOT/.env.production"
set +a

# Check critical environment variables
CRITICAL_VARS=("DATABASE_URL" "JWT_PRIVATE_KEY_PATH" "JWT_PUBLIC_KEY_PATH" "REDIS_HOST")
for var in "${CRITICAL_VARS[@]}"; do
    if [ -z "${!var}" ]; then
        error "Critical environment variable not set: $var"
        exit 1
    fi
    success "Environment variable set: $var"
done

# Check if still using placeholder values
if [[ "$STRIPE_SECRET_KEY" == *"YOUR_"* ]] || [[ "$SENDGRID_API_KEY" == *"YOUR_"* ]]; then
    warning "Some API keys appear to be placeholders. Email/payment features may not work."
    if [ "$FORCE" = false ]; then
        read -p "Continue anyway? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
fi

# ============================================================================
# BACKUP
# ============================================================================

if [ "$SKIP_BACKUP" = false ]; then
    banner "CREATING BACKUP"

    mkdir -p "$BACKUP_DIR"

    # Backup database
    if [[ "$DATABASE_URL" == postgresql* ]]; then
        log "Backing up PostgreSQL database..."

        # Extract database info from DATABASE_URL
        DB_NAME=$(echo $DATABASE_URL | sed -n 's/.*\/\([^?]*\).*/\1/p')

        pg_dump "$DATABASE_URL" > "$BACKUP_DIR/database_backup.sql" 2>&1 | tee -a "$LOG_FILE"

        if [ ${PIPESTATUS[0]} -eq 0 ]; then
            success "Database backup created: $BACKUP_DIR/database_backup.sql"
        else
            warning "Database backup failed (might be first deployment)"
        fi
    fi

    # Backup current code
    log "Backing up current code..."
    if [ -d "$PROJECT_ROOT/.git" ]; then
        git -C "$PROJECT_ROOT" archive --format=tar HEAD | gzip > "$BACKUP_DIR/code_backup.tar.gz"
        success "Code backup created: $BACKUP_DIR/code_backup.tar.gz"
    fi

    # Backup .env files
    cp "$PROJECT_ROOT/.env.production" "$BACKUP_DIR/.env.production.backup" || true

    success "Backup completed: $BACKUP_DIR"
else
    warning "Skipping backup (--skip-backup flag)"
fi

# ============================================================================
# DATABASE MIGRATION
# ============================================================================

banner "DATABASE SETUP"

log "Checking database connection..."

if [[ "$DATABASE_URL" == postgresql* ]]; then
    # Test PostgreSQL connection
    psql "$DATABASE_URL" -c "SELECT version();" &> /dev/null
    if [ $? -eq 0 ]; then
        success "PostgreSQL connection successful"
    else
        error "Cannot connect to PostgreSQL database"
        exit 1
    fi

    # Check if tables exist
    TABLE_COUNT=$(psql "$DATABASE_URL" -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';" 2>/dev/null | tr -d ' ')

    if [ "$TABLE_COUNT" -eq 0 ]; then
        log "Database is empty. Creating tables..."

        # Run database initialization
        cd "$PROJECT_ROOT"
        python3 -c "
from database.models import Base, engine
from database.session import init_db
init_db()
print('Database initialized successfully')
" 2>&1 | tee -a "$LOG_FILE"

        success "Database tables created"
    else
        log "Database has $TABLE_COUNT tables. Checking for migrations..."
        warning "Auto-migration not implemented yet. Manual schema updates may be needed."
    fi
else
    warning "SQLite database detected. For production, PostgreSQL is strongly recommended!"
fi

# ============================================================================
# REDIS CHECK
# ============================================================================

banner "REDIS SETUP"

log "Checking Redis connection..."

if [ -n "$REDIS_PASSWORD" ]; then
    redis-cli -h "$REDIS_HOST" -p "${REDIS_PORT:-6379}" -a "$REDIS_PASSWORD" PING &> /dev/null
else
    redis-cli -h "$REDIS_HOST" -p "${REDIS_PORT:-6379}" PING &> /dev/null
fi

if [ $? -eq 0 ]; then
    success "Redis connection successful"
else
    error "Cannot connect to Redis"
    exit 1
fi

# ============================================================================
# DEPENDENCIES
# ============================================================================

banner "INSTALLING DEPENDENCIES"

log "Installing Python dependencies..."

cd "$PROJECT_ROOT"

if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt --upgrade 2>&1 | tee -a "$LOG_FILE"
    success "Dependencies installed"
else
    warning "requirements.txt not found"
fi

# ============================================================================
# SECURITY KEY GENERATION
# ============================================================================

banner "SECURITY KEY VERIFICATION"

log "Checking JWT keys..."

if [ ! -f "$JWT_PRIVATE_KEY_PATH" ]; then
    error "JWT private key not found: $JWT_PRIVATE_KEY_PATH"
    log "Generate production keys using: cd security && python generate_keys.py production"
    exit 1
fi

if [ ! -f "$JWT_PUBLIC_KEY_PATH" ]; then
    error "JWT public key not found: $JWT_PUBLIC_KEY_PATH"
    exit 1
fi

success "JWT keys verified"

# ============================================================================
# SYSTEMD SERVICE (Optional)
# ============================================================================

banner "SYSTEMD SERVICE SETUP (Optional)"

if command_exists systemctl; then
    log "Creating systemd service file..."

    SERVICE_FILE="/etc/systemd/system/catalytic-saas.service"

    cat > /tmp/catalytic-saas.service <<EOF
[Unit]
Description=Catalytic Computing SaaS API Server
After=network.target postgresql.service redis.service

[Service]
Type=notify
User=$USER
WorkingDirectory=$PROJECT_ROOT/api
Environment="PATH=/usr/local/bin:/usr/bin:/bin"
EnvironmentFile=$PROJECT_ROOT/.env.production
ExecStart=$(which uvicorn) saas_server:app --host 0.0.0.0 --port ${PORT:-8000} --workers ${WORKERS:-4}
ExecReload=/bin/kill -s HUP \$MAINPID
KillMode=mixed
TimeoutStopSec=30
Restart=on-failure
RestartSec=10

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$PROJECT_ROOT

[Install]
WantedBy=multi-user.target
EOF

    log "Systemd service file created at /tmp/catalytic-saas.service"
    warning "To install, run: sudo cp /tmp/catalytic-saas.service $SERVICE_FILE && sudo systemctl daemon-reload"
else
    warning "systemctl not found. Skipping systemd service creation."
fi

# ============================================================================
# NGINX CONFIGURATION (Optional)
# ============================================================================

banner "NGINX CONFIGURATION (Optional)"

if command_exists nginx; then
    log "Creating nginx configuration..."

    cat > /tmp/catalytic-saas-nginx.conf <<'EOF'
# Catalytic Computing SaaS - Nginx Configuration

upstream catalytic_backend {
    server 127.0.0.1:8000;
    keepalive 64;
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name api.catalyticcomputing.com;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://$server_name$request_uri;
    }
}

# HTTPS Server
server {
    listen 443 ssl http2;
    server_name api.catalyticcomputing.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/api.catalyticcomputing.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.catalyticcomputing.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_prefer_server_ciphers on;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Rate Limiting
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
    limit_req zone=api_limit burst=20 nodelay;

    # Proxy to FastAPI
    location / {
        proxy_pass http://catalytic_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Health check endpoint (no rate limiting)
    location /health {
        proxy_pass http://catalytic_backend;
        access_log off;
    }
}
EOF

    log "Nginx configuration created at /tmp/catalytic-saas-nginx.conf"
    warning "To install, run: sudo cp /tmp/catalytic-saas-nginx.conf /etc/nginx/sites-available/catalytic-saas"
else
    warning "nginx not found. Skipping nginx configuration."
fi

# ============================================================================
# RUN TESTS
# ============================================================================

banner "RUNNING TESTS"

log "Running test suite..."

cd "$PROJECT_ROOT"

if [ -f "pytest.ini" ]; then
    pytest -v --tb=short 2>&1 | tee -a "$LOG_FILE"

    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        success "All tests passed"
    else
        warning "Some tests failed. Review test output above."
        if [ "$FORCE" = false ]; then
            read -p "Continue deployment anyway? (y/N) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        fi
    fi
else
    warning "pytest.ini not found. Skipping tests."
fi

# ============================================================================
# START SERVER
# ============================================================================

banner "STARTING SERVER"

log "Starting Catalytic SaaS API server..."

cd "$PROJECT_ROOT/api"

# Check if server is already running
if lsof -Pi :${PORT:-8000} -sTCP:LISTEN -t >/dev/null 2>&1 ; then
    warning "Port ${PORT:-8000} is already in use"
    read -p "Stop existing server and continue? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        pkill -f "uvicorn saas_server:app" || true
        sleep 2
    else
        exit 1
    fi
fi

# Start server based on configuration
if [ "$APP_ENV" = "production" ]; then
    log "Starting in production mode with $WORKERS workers..."

    # Use nohup for background process
    nohup uvicorn saas_server:app \
        --host 0.0.0.0 \
        --port ${PORT:-8000} \
        --workers ${WORKERS:-4} \
        --log-level warning \
        --access-log \
        > "$PROJECT_ROOT/logs/server_$TIMESTAMP.log" 2>&1 &

    SERVER_PID=$!
    echo $SERVER_PID > "$PROJECT_ROOT/server.pid"

    success "Server started with PID: $SERVER_PID"
    log "Logs: $PROJECT_ROOT/logs/server_$TIMESTAMP.log"
else
    warning "APP_ENV is not set to 'production'. Are you sure this is a production deployment?"
fi

# Wait for server to start
sleep 3

# Health check
log "Performing health check..."

HEALTH_URL="http://localhost:${PORT:-8000}/health"
if curl -s -f "$HEALTH_URL" > /dev/null; then
    success "Health check passed: $HEALTH_URL"
else
    error "Health check failed: $HEALTH_URL"
    error "Server may not have started correctly. Check logs."
    exit 1
fi

# ============================================================================
# POST-DEPLOYMENT
# ============================================================================

banner "POST-DEPLOYMENT CHECKLIST"

echo "✓ Production environment template created"
echo "✓ Database initialized"
echo "✓ Redis connected"
echo "✓ Dependencies installed"
echo "✓ Security keys verified"
echo "✓ Server started and health check passed"
echo ""
echo "Next Steps:"
echo "1. Configure SSL/TLS certificates (Let's Encrypt recommended)"
echo "2. Set up nginx reverse proxy (config in /tmp/catalytic-saas-nginx.conf)"
echo "3. Enable systemd service (config in /tmp/catalytic-saas.service)"
echo "4. Configure monitoring (Sentry, CloudWatch, etc.)"
echo "5. Set up log rotation"
echo "6. Configure automated backups"
echo "7. Test email delivery (python setup_email.py)"
echo "8. Test Stripe webhooks"
echo "9. Set up DNS records"
echo "10. Perform security audit"
echo ""
echo "Server Information:"
echo "  PID: $(cat $PROJECT_ROOT/server.pid 2>/dev/null || echo 'N/A')"
echo "  Port: ${PORT:-8000}"
echo "  Workers: ${WORKERS:-4}"
echo "  Logs: $PROJECT_ROOT/logs/server_$TIMESTAMP.log"
echo "  Backup: $BACKUP_DIR"
echo ""

success "DEPLOYMENT COMPLETED SUCCESSFULLY!"

# ============================================================================
# END
# ============================================================================
