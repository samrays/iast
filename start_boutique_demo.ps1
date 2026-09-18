# PowerShell Launcher for Aegis IAST & Google Online Boutique Demo
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " Starting Aegis IAST Platform & Google Online Boutique Demo...   " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

$VENV_PYTHON = ".\apps\api\.venv\Scripts\python.exe"
if (-Not (Test-Path $VENV_PYTHON)) {
    $VENV_PYTHON = "python"
}

& $VENV_PYTHON scripts/start_boutique_demo.py $args
