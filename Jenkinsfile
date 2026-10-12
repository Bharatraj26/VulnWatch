/*
 * VulnWatch — Jenkins CI/CD Pipeline (Windows Native Execution)
 * ===============================================================
 * Automated pipeline for Python + Flask, HTML/CSS/JS, SQLite stack.
 *
 * Requirements on Windows Jenkins Agent:
 *   - Git (configured in Jenkins tool configuration)
 *   - Python 3.11+ available in system PATH
 *   - Node.js 18+ & npm available in system PATH (for building frontend assets)
 *
 * Pipeline Stages:
 *   1. Checkout: Retrieve source code from GitHub
 *   2. Setup & Dependencies: Create Python venv and install requirements
 *   3. Build Frontend: Compile UI assets into frontend/dist
 *   4. Code Quality Checks: Ruff static analysis
 *   5. Security Analysis: Bandit static security audit
 *   6. Automated Tests: Pytest unit & integration tests
 *   7. Deploy: Direct Windows deployment using Python (stops previous instance, launches app, verifies health)
 */
 