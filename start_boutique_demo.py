#!/usr/bin/env python3
"""Root launcher shortcut for Google Online Boutique + Aegis IAST demo."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from start_boutique_demo import main

if __name__ == "__main__":
    main()
