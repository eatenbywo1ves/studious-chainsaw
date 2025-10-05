#!/bin/bash
# Catalytic Computing SaaS - Production Startup Script (Linux/Mac)
# Usage: ./start-production.sh

set -e

echo ""
echo "================================================================"
echo "  CATALYTIC COMPUTING SAAS - PRODUCTION STARTUP"
echo "================================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Python is installed
echo "[1/5] Checking Python..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[ERROR]${NC} Python 3 not found. Please install Python 3.10+"
    exit 1
fi
PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo -e "${GREEN}[OK]${NC} Python $PYTHON_VERSION"

# Check if Redis is running
echo ""
echo "[2/5] Checking Redis..."
if ! redis-cli ping &> /dev/null; then
    echo -e "${YELLOW}[WARN]${NC} Redis not running. Starting..."
    if command -v systemctl &> /dev/null; then
        sudo systemctl start redis
    elif command -v service &> /dev/null; then
        sudo service redis start
    else
        redis-server --daemonize yes
    fi
    sleep 3
fi

if redis-cli ping &> /dev/null; then
    echo -e "${GREEN}[OK]${NC} Redis is running"
else
    echo -e "${RED}[ERROR]${NC} Failed to start Redis"
    exit 1
fi

# Check if database is initialized
echo ""
echo "[3/5] Checking database..."
if [ ! -f "catalytic_saas.db" ] && [ -z "$DATABASE_URL" ]; then
    echo -e "${YELLOW}[WARN]${NC} Database not found. Initializing..."
    python3 init_production_db.py
    if [ $? -ne 0 ]; then
        echo -e "${RED}[ERROR]${NC} Database initialization failed"
        exit 1
    fi
else
    echo -e "${GREEN}[OK]${NC} Database configured"
fi

# Check environment variables
echo ""
echo "[4/5] Checking environment..."
if [ ! -f ".env" ]; then
    echo -e "${RED}[ERROR]${NC} .env file not found"
    echo "Please create .env file from .env.example"
    exit 1
fi
echo -e "${GREEN}[OK]${NC} Environment configured"

# Install dependencies if needed
if [ ! -d "venv" ]; then
    echo ""
    echo "Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    pip install -r api/requirements.txt
else
    source venv/bin/activate
fi

# Start backend API
echo ""
echo "[5/5] Starting backend API..."

# Check if using systemd or direct start
if [ "$1" == "--systemd" ]; then
    # Create systemd service
    cat > /tmp/catalytic-backend.service <<EOF
[Unit]
Description=Catalytic Computing Backend API
After=network.target redis.service

[Service]
Type=notify
User=$(whoami)
WorkingDirectory=$(pwd)
Environment="PATH=$(pwd)/venv/bin"
ExecStart=$(pwd)/venv/bin/gunicorn api.saas_server:app \\
    --workers 4 \\
    --worker-class uvicorn.workers.UvicornWorker \\
    --bind 0.0.0.0:8000 \\
    --access-logfile /var/log/catalytic/access.log \\
    --error-logfile /var/log/catalytic/error.log
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    sudo mv /tmp/catalytic-backend.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable catalytic-backend
    sudo systemctl start catalytic-backend

    echo -e "${GREEN}[OK]${NC} Backend started as systemd service"
else
    # Direct start with uvicorn
    uvicorn api.saas_server:app \
        --host 0.0.0.0 \
        --port 8000 \
        --workers 4 \
        --reload &

    BACKEND_PID=$!
    echo "Backend PID: $BACKEND_PID"

    # Wait for backend to start
    echo "Waiting for backend to start..."
    for i in {1..30}; do
        if curl -s http://localhost:8000/health > /dev/null 2>&1; then
            echo -e "${GREEN}[OK]${NC} Backend started successfully"
            break
        fi
        sleep 1
    done
fi

# Check backend health
echo ""
echo "Checking backend health..."
HEALTH=$(curl -s http://localhost:8000/health)
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[OK]${NC} Backend health check passed"
    echo "$HEALTH" | python3 -m json.tool
else
    echo -e "${RED}[ERROR]${NC} Backend health check failed"
    exit 1
fi

# Start frontend (optional)
echo ""
if [ -f "frontend/package.json" ]; then
    read -p "Start frontend? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cd frontend
        npm install
        npm run build
        npm start &
        FRONTEND_PID=$!
        echo "Frontend PID: $FRONTEND_PID"
        cd ..
    fi
fi

echo ""
echo "================================================================"
echo "  DEPLOYMENT COMPLETE!"
echo "================================================================"
echo ""
echo "Backend API: http://localhost:8000"
echo "API Docs: http://localhost:8000/docs"
echo "Health Check: http://localhost:8000/health"
echo ""
if [ ! -z "$FRONTEND_PID" ]; then
    echo "Frontend: http://localhost:3000"
fi
echo ""
echo "To stop services:"
echo "  kill $BACKEND_PID"
if [ ! -z "$FRONTEND_PID" ]; then
    echo "  kill $FRONTEND_PID"
fi
echo ""
echo "================================================================"
echo ""
