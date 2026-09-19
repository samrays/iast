#!/usr/bin/env bash
# ==============================================================================
# Aegis IAST — Automated Setup Script for Linux & macOS (Bash)
# ==============================================================================
# Usage:
#   chmod +x setup.sh && ./setup.sh
# ==============================================================================

set -e

echo "=============================================================================="
echo "       Aegis IAST Platform — Automated Cross-Device Setup (Linux/macOS)       "
echo "=============================================================================="
echo ""

# 1. Check Python
echo "[1/5] Checking Python installation..."
PYTHON_BIN=""
for cmd in python3 python; do
    if command -v "$cmd" >/dev/null 2>&1; then
        PYTHON_BIN="$cmd"
        break
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo "  [ERROR] Python 3 is not installed or not in PATH."
    echo "  Please install Python 3.11 or higher."
    exit 1
fi
echo "  -> Found Python: $($PYTHON_BIN --version)"

# 2. Check Node.js and npm
echo "[2/5] Checking Node.js and npm..."
if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
    echo "  -> Found Node.js: $(node -v) (npm: $(npm -v))"
else
    echo "  [WARNING] Node.js or npm not detected in PATH."
    echo "  The Next.js dashboard requires Node.js >= 20."
fi

# 3. Setup Python Virtual Environment
echo "[3/5] Setting up Python virtual environment..."
VENV_DIR="apps/api/.venv"
if [ ! -f "$VENV_DIR/bin/python" ]; then
    echo "  -> Creating virtual environment at $VENV_DIR..."
    "$PYTHON_BIN" -m venv "$VENV_DIR"
else
    echo "  -> Virtual environment already exists at $VENV_DIR"
fi

VENV_PY="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"

echo "  -> Upgrading pip, setuptools, and wheel..."
"$VENV_PY" -m pip install --upgrade pip setuptools wheel --quiet

echo "  -> Installing Python requirements from requirements.txt..."
"$VENV_PIP" install -r requirements.txt

# 4. Setup Environment File (.env)
echo "[4/5] Checking environment configuration (.env)..."
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "  -> Created .env from .env.example"
    fi
else
    echo "  -> Existing .env file found."
fi

# 5. Setup Node Workspaces
echo "[5/5] Installing Node.js frontend workspace dependencies..."
if command -v npm >/dev/null 2>&1; then
    npm install
    echo "  -> Node dependencies installed successfully."
else
    echo "  -> Skipped npm install (npm not in PATH)."
fi

echo ""
echo "=============================================================================="
echo "                       SETUP COMPLETED SUCCESSFULLY!                          "
echo "=============================================================================="
echo ""
echo " To start the entire platform and run tests on Google Online Boutique:"
echo "   python3 start_boutique_demo.py"
echo "   # Or via npm:"
echo "   npm run demo:boutique"
echo ""
echo " Access Endpoints:"
echo "   - Security Dashboard   : http://localhost:3100 (owner@aegis.example / Password123!)"
echo "   - Control Plane API    : http://127.0.0.1:8000/docs"
echo "   - Online Boutique App  : http://localhost:8095"
echo ""
