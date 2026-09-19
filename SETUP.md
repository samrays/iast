# Setting Up Aegis IAST on Another Device

This guide walks you through setting up and running the complete **Aegis IAST Platform** and the **Google Online Boutique** vulnerable application on a new device (Windows, Linux, or macOS).

---

## 1. System Prerequisites

Ensure the following runtimes are installed on your device:

| Tool | Minimum Version | Check Command | Download / Install |
| :--- | :--- | :--- | :--- |
| **Python** | `3.11` or higher | `python --version` | [python.org](https://www.python.org/downloads/) |
| **Node.js** | `20.x` or higher (22+ recommended) | `node -v` | [nodejs.org](https://nodejs.org/) |
| **npm** | `10.x` or higher | `npm -v` | Included with Node.js |
| **Git** | Any recent version | `git --version` | [git-scm.com](https://git-scm.com/) |

---

## 2. Quickstart (Automated Setup)

Run the automated setup script for your operating system. This script automatically provisions the Python virtual environment, installs all pip and npm dependencies, configures `.env`, and verifies the environment.

### Windows (PowerShell)
```powershell
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

### Linux / macOS (Bash)
```bash
chmod +x setup.sh
./setup.sh
```

---

## 3. Manual Step-by-Step Setup

If you prefer to configure the environment manually:

### Step 1: Clone the Repository
```bash
git clone <repository-url>
cd iast
```

### Step 2: Set Up the Python Virtual Environment
Create and activate a virtual environment in `apps/api/.venv` (or `.venv`):

```bash
# Windows
python -m venv apps/api/.venv
apps/api/.venv/Scripts/activate

# Linux / macOS
python3 -m venv apps/api/.venv
source apps/api/.venv/bin/activate
```

Upgrade pip, setuptools, and wheel:
```bash
pip install --upgrade pip setuptools wheel
```

### Step 3: Install Python Dependencies
Install all platform dependencies and monorepo packages in editable mode:
```bash
pip install -r requirements.txt
```

*(Optional: For running tests, linters, and type-checkers, also install `pip install -r requirements-dev.txt`)*

### Step 4: Install Node.js Frontend Dependencies
At the root of the repository:
```bash
npm install
```
*This installs dependencies for both `@aegis/dashboard` and `@aegis/ui` workspaces via npm workspaces.*

### Step 5: Configure Environment Variables
Copy the template `.env.example` to `.env`:

```bash
# Windows (CMD)
copy .env.example .env

# Windows (PowerShell)
Copy-Item .env.example .env

# Linux / macOS
cp .env.example .env
```

> **Note**: The default `.env` is pre-configured to use the local SQLite database (`aegis_demo.db`). No external PostgreSQL or Redis database is required to run the demo.

---

## 4. Running the Application

### Option A: Unified Launcher (Recommended)
Start the Control Plane API, Next.js Dashboard, all 5 Online Boutique microservices, and execute vulnerability tests in a single command:

```bash
# Python
python start_boutique_demo.py

# Or via PowerShell
.\start_boutique_demo.ps1

# Or via npm
npm run demo:boutique
```

#### Useful CLI Flags:
- `python start_boutique_demo.py --test-only`: Runs the 4-phase vulnerability test suite against the vulnerable app and exits cleanly.
- `python start_boutique_demo.py --mode BLOCK`: Starts the cluster in **Active Defense and Response (ADR)** blocking mode (`403 Forbidden` intercepts).
- `python start_boutique_demo.py --interval 0.5`: Adjusts simulated e-commerce background traffic speed.
- `python start_boutique_demo.py --count 25`: Runs 25 simulated transactions and exits.

---

### Option B: Running Individual Components Manually

If you prefer running components in separate terminals:

1. **Terminal 1: Control Plane API**
   ```bash
   # Windows
   apps/api/.venv/Scripts/python.exe -m uvicorn aegis_api.main:app --host 127.0.0.1 --port 8000

   # Linux/macOS
   apps/api/.venv/bin/python -m uvicorn aegis_api.main:app --host 127.0.0.1 --port 8000
   ```

2. **Terminal 2: Next.js Security Dashboard**
   ```bash
   npm run dev --workspace @aegis/dashboard
   ```

3. **Terminal 3: Google Online Boutique Microservices**
   ```bash
   python scripts/run_online_boutique.py
   ```

4. **Terminal 4: Run Tests / Background Traffic**
   ```bash
   # Execute full 4-phase vulnerability harness
   python tests/online-boutique/test_boutique_harness.py

   # Or stream continuous realistic traffic
   python scripts/run_boutique_traffic.py --interval 1.0
   ```

---

## 5. Access Points & Credentials

| Service | URL | Description |
| :--- | :--- | :--- |
| **Aegis Security Dashboard** | [http://localhost:3100](http://localhost:3100) | Live findings, SSE alerts, executive posture |
| **Control Plane API & Docs** | [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) | Interactive Swagger / OpenAPI documentation |
| **Online Boutique Storefront** | [http://localhost:8095](http://localhost:8095) | Vulnerable e-commerce app & interactive ADR sandbox |
| **Recommendation Service** | `http://127.0.0.1:8091` | Microservice (SQLi & Path Traversal sinks) |
| **Email Service** | `http://127.0.0.1:8092` | Microservice (Log Injection & XXE sinks) |
| **Ad Service** | `http://127.0.0.1:8093` | Microservice (Reflected XSS & CMDi sinks) |
| **Currency Service** | `http://127.0.0.1:8094` | Microservice (SSRF & Header Injection sinks) |

### Default Login Credentials
- **Email**: `owner@aegis.example`
- **Password**: `Password123!`
- **Organization Slug**: `aegis-demo-corp`

---

## 6. Verifying the Setup

To verify that the installation is completely healthy:

```bash
# 1. Run Python agent unit tests
python -m pytest agents/runtime/python-agent/tests/

# 2. Run Dashboard unit tests
npm run test --workspace @aegis/dashboard

# 3. Check Hexagonal Architecture Layering Constraints
python scripts/check_layering.py
```

---

## 7. Troubleshooting

- **Port Conflicts (`WinError 10048` or `EADDRINUSE`)**:
  - Ports used: `8000` (API), `3100` (Dashboard), `8091-8095` (Boutique microservices).
  - Stop any existing services or check with `netstat -ano | findstr :8000`.
- **PowerShell Execution Policy**:
  - If PowerShell blocks running `.ps1` scripts, run:
    ```powershell
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    ```
- **SQLite Database Path**:
  - If you encounter database connection errors, ensure `.env` contains:
    `AEGIS_DATABASE_URL=sqlite+aiosqlite:///./aegis_demo.db`
    The unified launcher `start_boutique_demo.py` automatically resolves this to an absolute path for you.
