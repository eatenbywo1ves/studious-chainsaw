#!/bin/bash
# ML-SecTest Framework - Linux/Mac Deployment Script
# ===================================================

set -e  # Exit on error

echo ""
echo "============================================================"
echo "ML-SecTest Framework - Deployment Script"
echo "============================================================"
echo ""

# Check if Python 3.8+ is available
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is not installed"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "[INFO] Python version: $PYTHON_VERSION"

# Step 1: Create virtual environment
if [ ! -d "venv" ]; then
    echo ""
    echo "[STEP 1/5] Creating virtual environment..."
    python3 -m venv venv
    echo "[OK] Virtual environment created"
else
    echo "[STEP 1/5] Virtual environment already exists"
fi

# Step 2: Upgrade pip
echo ""
echo "[STEP 2/5] Upgrading pip..."
./venv/bin/python -m pip install --upgrade pip --quiet
echo "[OK] Pip upgraded successfully"

# Step 3: Install dependencies
echo ""
echo "[STEP 3/5] Installing dependencies..."
./venv/bin/python -m pip install -r requirements.txt --quiet
echo "[OK] Dependencies installed"

# Step 4: Validate installation
echo ""
echo "[STEP 4/5] Validating installation..."
./venv/bin/python -c "from core import SecurityOrchestrator; from agents import PromptInjectionAgent; from utils import ReportGenerator" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "[OK] Framework validated"
else
    echo "[ERROR] Framework validation failed"
    exit 1
fi

# Step 5: Test CLI
echo ""
echo "[STEP 5/5] Testing CLI..."
./venv/bin/python ml_sectest.py --help > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "[OK] CLI functional"
else
    echo "[WARNING] CLI test had issues"
fi

echo ""
echo "============================================================"
echo "Deployment Complete!"
echo "============================================================"
echo ""
echo "To use the framework:"
echo "  1. Activate environment: source venv/bin/activate"
echo "  2. List challenges: python ml_sectest.py list-challenges"
echo "  3. Scan target: python ml_sectest.py scan http://localhost:8000"
echo ""
echo "Environment: $(pwd)"
echo "Python: $(./venv/bin/python --version)"
echo ""
