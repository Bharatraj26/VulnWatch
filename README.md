# VulnWatch — Automated Web Security Testing & CI/CD Platform

> **Educational Project** — Phase 1 & 2 Foundation. Controlled, passive security checks for authorized and local test targets only.

---

## Overview

**VulnWatch** is an educational web security testing and CI/CD platform designed to demonstrate automated software quality assurance, passive security verification, and automated build/deployment pipelines using Jenkins.

**Technology Stack:**
- **Backend:** Python + Flask
- **Frontend / UI:** HTML, CSS, and JavaScript (React + Vite + Tailwind, compiled into static web assets)
- **Database:** SQLite (local file persistence)
- **Testing:** Pytest (automated unit and API integration tests)
- **Version Control:** Git & GitHub
- **CI/CD:** Jenkins (Windows-native pipeline execution without containerization)
- **Security & Quality:** Ruff (linting & formatting) + Bandit (static application security testing)

*Note: In accordance with project requirements, this application runs natively on the Windows host environment. No external third-party paid APIs or cloud dependencies are required.*

---

## Project Structure

```
VulnWatch/
├── backend/                  # Flask application source
│   ├── app/
│   │   ├── api/v1/          # Modular API Blueprints
│   │   │   └── endpoints/   # Health, Scans, Reports endpoints
│   │   ├── core/            # Configuration and SQLite database manager
│   │   └── main.py          # Application entry point
│   ├── .env.example         # Environment template
│   ├── requirements.txt     # Python backend dependencies
│   └── run.py               # Backend startup script
├── frontend/                 # Web dashboard source (HTML, CSS, JS)
│   ├── src/                 # React, TypeScript, Tailwind source
│   ├── dist/                # Production-ready compiled HTML/CSS/JS assets
│   ├── package.json         # Frontend dependencies and build scripts
│   └── vite.config.ts       # Dev proxy configuration
├── tests/                    # Automated test suite
│   └── backend/             # Pytest integration tests
├── docs/                     # Project documentation
├── Jenkinsfile               # Jenkins CI/CD declarative pipeline (Windows-native)
├── pytest.ini                # Pytest configuration
├── run.py                    # Root convenience launcher
├── .gitignore                # Git ignore configuration
└── README.md                 # Project documentation
```

---

## Prerequisites

| Tool | Minimum Version | Notes |
|------|----------------|-------|
| Python | 3.11+ | Python 3.11, 3.12, or 3.13 on Windows |
| Node.js & npm | 18.x+ / 9.x+ | Required for frontend build |
| Git | 2.x+ | Version control |
| Jenkins | 2.400+ | Running on or targeting a Windows agent |

---

## Quick Start (Local Development)

### 1. Backend Setup (Python + Flask)

```powershell
# Navigate to backend directory
cd backend

# Create and activate Python virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create .env from template
copy .env.example .env

# Run the Flask server
python run.py
```

The Flask API and web server will be live at: **http://127.0.0.1:8000**  
Health Check: **http://127.0.0.1:8000/api/health**

---

### 2. Frontend Setup (Web Dashboard)

You can run the web dashboard in two modes:

#### Option A: Production Mode (Served directly by Flask)
Run the production build once, and Flask will automatically serve the full web interface at `http://127.0.0.1:8000`:
```powershell
cd frontend
npm install
npm run build
```
Once built, open **http://127.0.0.1:8000** in your browser.

#### Option B: Frontend Development Server (with hot reloading)
```powershell
cd frontend
npm install
npm run dev
```
The development server will be available at: **http://localhost:5173** (with API requests proxied to `http://127.0.0.1:8000`).

---

## Automated Testing & Quality Checks

### Running Tests (Pytest)
```powershell
# From project root
backend\venv\Scripts\pytest -v
```

### Running Code Quality Checks (Ruff)
```powershell
backend\venv\Scripts\ruff check backend/ tests/
```

### Running Security Analysis (Bandit)
```powershell
backend\venv\Scripts\bandit -r backend/app/ -ll
```

---

## API Endpoints (Phase 3 Active)

| Method | Path | Description | Status |
|--------|------|-------------|--------|
| `GET` | `/api/health` | Service health status check | Active |
| `GET` | `/api/scans` | Retrieve list of all scans from SQLite | Active |
| `GET` | `/api/scans/<scan_id>` | Retrieve specific scan details with findings | Active |
| `POST` | `/api/scans` | Execute passive security checks against authorized local target | Active |
| `GET` | `/api/scans/stats` | Summary statistics for dashboard KPI cards | Active |
| `GET` | `/api/reports` | Retrieve all security reports from SQLite | Active |
| `GET` | `/api/reports/<id_or_scan_id>` | Retrieve detailed audit report with findings, evidence & recommendations | Active |

---

## Phase 3: Web Security Scanner Architecture

### 1. Authorized Target Validation & SSRF Prevention
- Restricts target execution strictly to `localhost`, loopback addresses (`127.0.0.0/8`, `::1`), and explicitly configured authorized test hosts.
- Rejects cloud metadata addresses (`169.254.169.254`), non-loopback private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and arbitrary external public endpoints.
- Enforces safe redirect handling (`SafeRedirectHandler`) to ensure redirects cannot escape to disallowed destinations.

### 2. Defensive Security Checks
- **Transport Security:** Evaluates HTTP vs HTTPS usage and validates TLS certificate validity/expiration.
- **HTTP Security Headers:** Inspects presence and configuration of `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.
- **Cookie Attributes:** When `Set-Cookie` headers are returned, inspects `Secure`, `HttpOnly`, and `SameSite` flags.
- **Server Configuration:** Identifies information disclosure in `Server` and `X-Powered-By` banners, and checks for insecure HTTP methods (e.g. `TRACE`).
- **Project Dependency Audit:** Inspects local VulnWatch dependencies against known advisory baselines without external paid services.

### 3. Documented Security Scoring Methodology
Scores start at **100 points** with deterministic, documented deductions based on severity weights:
- **Critical:** -25 points (e.g. Severe transport compromise)
- **High:** -15 points (e.g. Missing CSP, missing HSTS on HTTPS, missing Secure/HttpOnly on sensitive cookies)
- **Medium:** -8 points (e.g. Missing X-Frame-Options, cleartext HTTP, insecure TRACE method)
- **Low:** -3 points (e.g. Missing X-Content-Type-Options, Referrer-Policy, or Server version disclosure)
- **Info:** 0 points (informational notes)

**Formula:** `Score = max(0, min(100, 100 - sum(deductions)))`  
**Grade Scale:**
- `85 – 100`: Grade A (Strong defensive posture)
- `70 – 84`: Grade B (Satisfactory posture)
- `50 – 69`: Grade C (Moderate defensive gaps)
- `30 – 49`: Grade D (Elevated exposure)
- `0 – 29`: Grade F (High risk; widespread missing controls)

Findings are explicitly categorized as either **`missing_control`** (defensive mitigation absent) or **`vulnerability`** (confirmed exploitable condition).

## Jenkins CI/CD Pipeline (Windows Native Deployment)

The included `Jenkinsfile` runs directly on a Windows Jenkins agent using native PowerShell and batch execution.

### Pipeline Stages

1. **Checkout:** Retrieves source code from GitHub via Git.
2. **Install Dependencies:** Creates `backend/venv` if not present, upgrades `pip`, and installs all packages from `requirements.txt`.
3. **Build Frontend:** Executes `npm ci` and `npm run build` inside `frontend/` to compile static HTML, CSS, and JS into `frontend/dist`.
4. **Code Quality Checks:** Executes `ruff check backend/ tests/`.
5. **Security Analysis:** Executes `bandit -r backend/app/ -ll` for static security vulnerability detection.
6. **Automated Tests:** Executes `pytest -v --junitxml=reports/pytest-results.xml` and archives test results in Jenkins.
7. **Deploy Application:**
   - Detects and cleanly stops any existing VulnWatch instance on port `8000`.
   - Spawns the Flask application as a persistent Windows background process using Python.
   - Executes an automated loopback health check (`http://127.0.0.1:8000/api/health`) to confirm deployment health before completing.

---

### Windows & Jenkins Service Requirements

When deploying directly on Windows via Jenkins, observe the following configuration requirements:

1. **Jenkins ProcessTreeKiller:**
   - By default, Jenkins terminates child processes spawned by build steps when a job finishes.
   - The pipeline sets `BUILD_ID = 'dontKillMe'` in the environment block to allow the Flask server to continue running in the background after the build completes.

2. **Windows Service Account & Interactive Sessions:**
   - If Jenkins runs as a Windows Service under the `Local System` account, network access to loopback (`127.0.0.1`) is permitted, but the process runs without a visible desktop window.
   - If dedicated service management is preferred in enterprise environments, the application can alternatively be registered as a Windows Service using `NSSM` (Non-Sucking Service Manager) or Windows Task Scheduler:
     ```powershell
     # Optional: register as Windows Service with NSSM
     nssm install VulnWatch "D:\VulnWatch\backend\venv\Scripts\python.exe" "run.py"
     nssm set VulnWatch AppDirectory "D:\VulnWatch"
     nssm start VulnWatch
     ```

3. **Windows Firewall / Port Permissions:**
   - Ensure inbound traffic on port `8000` is allowed if accessing the dashboard from other machines on the local network:
     ```powershell
     New-NetFirewallRule -DisplayName "VulnWatch Port 8000" -Direction Inbound -LocalPort 8000 -Protocol TCP -Action Allow
     ```

---

## Safety & Ethics Policy

- VulnWatch is strictly an educational tool.
- Offensive security functionality (SQL injection exploitation, credential brute-forcing, XSS payloads) is prohibited.
- Scanning is restricted to local (`localhost`, `127.0.0.1`) and explicitly owned/authorized applications.

<!-- Jenkins auto-trigger test -->
