# ==============================================================================
# Aegis IAST — Automated Setup Script for Windows (PowerShell)
# ==============================================================================
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\setup.ps1
# ==============================================================================

$ErrorActionPreference = "Stop"

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "       Aegis IAST Platform — Automated Cross-Device Setup (Windows)          " -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check Python installation
Write-Host "[1/5] Checking Python installation..." -ForegroundColor Yellow
$PYTHON_BIN = "python"
try {
    $pyVersion = & $PYTHON_BIN --version 2>&1
    Write-Host "  -> Found Python: $pyVersion" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Python is not installed or not in PATH." -ForegroundColor Red
    Write-Host "  Please install Python 3.11 or higher from https://python.org" -ForegroundColor Red
    Exit 1
}

# 2. Check Node.js and npm
Write-Host "[2/5] Checking Node.js and npm..." -ForegroundColor Yellow
try {
    $nodeVersion = & node --version 2>&1
    $npmVersion = & npm --version 2>&1
    Write-Host "  -> Found Node.js: $nodeVersion (npm: $npmVersion)" -ForegroundColor Green
} catch {
    Write-Host "  [WARNING] Node.js or npm not detected in PATH." -ForegroundColor Yellow
    Write-Host "  The Next.js dashboard requires Node.js >= 20. Install from https://nodejs.org" -ForegroundColor Yellow
}

# 3. Setup Python Virtual Environment
Write-Host "[3/5] Setting up Python virtual environment..." -ForegroundColor Yellow
$VENV_DIR = "apps\api\.venv"
if (-Not (Test-Path "$VENV_DIR\Scripts\python.exe")) {
    Write-Host "  -> Creating virtual environment at $VENV_DIR..."
    & $PYTHON_BIN -m venv $VENV_DIR
} else {
    Write-Host "  -> Virtual environment already exists at $VENV_DIR" -ForegroundColor Green
}

$VENV_PY = "$VENV_DIR\Scripts\python.exe"
$VENV_PIP = "$VENV_DIR\Scripts\pip.exe"

Write-Host "  -> Upgrading pip, setuptools, and wheel..."
& $VENV_PY -m pip install --upgrade pip setuptools wheel --quiet

Write-Host "  -> Installing Python requirements from requirements.txt..."
& $VENV_PIP install -r requirements.txt

# 4. Setup Environment File (.env)
Write-Host "[4/5] Checking environment configuration (.env)..." -ForegroundColor Yellow
if (-Not (Test-Path ".env")) {
    if (Test-Path ".env.example") {
        Copy-Item ".env.example" ".env"
        Write-Host "  -> Created .env from .env.example" -ForegroundColor Green
    }
} else {
    Write-Host "  -> Existing .env file found." -ForegroundColor Green
}

# 5. Setup Node Workspaces
Write-Host "[5/5] Installing Node.js frontend workspace dependencies..." -ForegroundColor Yellow
if (Get-Command npm -ErrorAction SilentlyContinue) {
    & npm install
    Write-Host "  -> Node dependencies installed successfully." -ForegroundColor Green
} else {
    Write-Host "  -> Skipped npm install (Node.js/npm not in PATH)." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "==============================================================================" -ForegroundColor Green
Write-Host "                       SETUP COMPLETED SUCCESSFULLY!                          " -ForegroundColor Green
Write-Host "==============================================================================" -ForegroundColor Green
Write-Host ""
Write-Host " To start the entire platform and run tests on Google Online Boutique:" -ForegroundColor Cyan
Write-Host "   python start_boutique_demo.py" -ForegroundColor White
Write-Host "   # Or via PowerShell:" -ForegroundColor White
Write-Host "   .\start_boutique_demo.ps1" -ForegroundColor White
Write-Host "   # Or via npm:" -ForegroundColor White
Write-Host "   npm run demo:boutique" -ForegroundColor White
Write-Host ""
Write-Host " Access Endpoints:" -ForegroundColor Cyan
Write-Host "   - Security Dashboard   : http://localhost:3100 (owner@aegis.example / Password123!)"
Write-Host "   - Control Plane API    : http://127.0.0.1:8000/docs"
Write-Host "   - Online Boutique App  : http://localhost:8095"
Write-Host ""
