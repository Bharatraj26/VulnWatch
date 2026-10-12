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

pipeline {
    agent any

    environment {
        PYTHON_VENV   = "${WORKSPACE}\\backend\\venv"
        PYTHON_EXE    = "${PYTHON_VENV}\\Scripts\\python.exe"
        PIP_EXE       = "${PYTHON_VENV}\\Scripts\\pip.exe"
        RUFF_EXE      = "${PYTHON_VENV}\\Scripts\\ruff.exe"
        BANDIT_EXE    = "${PYTHON_VENV}\\Scripts\\bandit.exe"
        PYTEST_EXE    = "${PYTHON_VENV}\\Scripts\\pytest.exe"
        APP_PORT      = '8000'
        APP_HOST      = '127.0.0.1'
        // Prevent Jenkins ProcessTreeKiller from stopping the background application process
        BUILD_ID      = 'dontKillMe'
    }

    stages {

        stage('Checkout') {
            steps {
                echo '=== Stage 1: Retrieving source code from repository ==='
                checkout scm
                echo '✔ Source code checkout complete.'
            }
        }

        stage('Install Dependencies') {
            steps {
                echo '=== Stage 2: Installing Python and Frontend dependencies ==='
                bat '''
                    @echo off
                    if not exist "%PYTHON_VENV%\\Scripts\\python.exe" (
                        echo [*] Creating Python virtual environment...
                        python -m venv "%PYTHON_VENV%"
                    )
                    echo [*] Upgrading pip and installing backend dependencies...
                    "%PIP_EXE%" install --upgrade pip --quiet
                    "%PIP_EXE%" install -r backend\\requirements.txt --quiet
                    echo ✔ Backend dependencies installed successfully.
                '''
            }
        }

        stage('Build Frontend') {
            steps {
                echo '=== Stage 3: Building static web frontend (HTML/CSS/JS) ==='
                dir('frontend') {
                    bat '''
                        @echo off
                        echo [*] Installing frontend packages...
                        call npm ci --prefer-offline --no-audit
                        echo [*] Running TypeScript type check...
                        call npm run type-check
                        echo [*] Building production web assets...
                        call npm run build
                        echo ✔ Frontend built successfully to frontend/dist.
                    '''
                }
            }
        }

        stage('Code Quality Checks') {
            steps {
                echo '=== Stage 4: Running code quality checks (Ruff) ==='
                bat '''
                    @echo off
                    "%RUFF_EXE%" check backend\\ tests\\
                    echo ✔ Code quality checks passed with zero issues.
                '''
            }
        }

        stage('Security Analysis') {
            steps {
                echo '=== Stage 5: Running security audit (Bandit) ==='
                bat '''
                    @echo off
                    "%BANDIT_EXE%" -r backend\\app\\ -ll
                    echo ✔ Security checks passed (no medium/high severity vulnerabilities).
                '''
            }
        }

        stage('Automated Tests') {
            steps {
                echo '=== Stage 6: Running automated tests (Pytest) ==='
                bat '''
                    @echo off
                    if not exist "reports" mkdir reports
                    "%PYTEST_EXE%" -v --junitxml=reports\\pytest-results.xml
                    echo ✔ All tests executed successfully.
                '''
            }
            post {
                always {
                    junit testResults: 'reports/pytest-results.xml', allowEmptyResults: true
                }
            }
        }

        stage('Deploy Application') {
            steps {
                echo '=== Stage 7: Deploying Flask application directly on Windows ==='
                powershell '''
                    $ErrorActionPreference = "Stop"
                    $port = $env:APP_PORT
                    $hostAddr = $env:APP_HOST

                    Write-Host "[*] Checking for existing VulnWatch process on port $port..."
                    $connections = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
                    if ($connections) {
                        foreach ($conn in $connections) {
                            $procId = $conn.OwningProcess
                            Write-Host "[*] Stopping existing process PID: $procId listening on port $port"
                            Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
                        }
                        Start-Sleep -Seconds 2
                    }

                    Write-Host "[*] Launching VulnWatch Flask application on $hostAddr:$port..."
                    $pythonExe = $env:PYTHON_EXE
                    $workspace = $env:WORKSPACE
                    $runScript = Join-Path $workspace "run.py"

                    # Start process in background
                    $processInfo = New-Object System.Diagnostics.ProcessStartInfo
                    $processInfo.FileName = $pythonExe
                    $processInfo.Arguments = "`"$runScript`""
                    $processInfo.WorkingDirectory = $workspace
                    $processInfo.UseShellExecute = $true
                    $processInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
                    [System.Diagnostics.Process]::Start($processInfo) | Out-Null

                    Write-Host "[*] Waiting for application to initialize..."
                    Start-Sleep -Seconds 3

                    # Health check verification
                    $healthUrl = "http://${hostAddr}:${port}/api/health"
                    Write-Host "[*] Verifying deployment health: $healthUrl"
                    $health = Invoke-RestMethod -Uri $healthUrl -Method Get -TimeoutSec 10
                    if ($health.status -eq "ok") {
                        Write-Host "✔ VulnWatch deployed and healthy! Service: $($health.service)"
                    } else {
                        throw "Health check returned unexpected status: $($health.status)"
                    }
                '''
            }
        }

    }

    post {
        success {
            echo '=================================================='
            echo '✅ VulnWatch pipeline completed successfully!'
            echo 'Application is live at: http://127.0.0.1:8000'
            echo 'Health check: http://127.0.0.1:8000/api/health'
            echo '=================================================='
        }
        failure {
            echo '❌ Pipeline failed. Review the console log above for details.'
        }
    }
}
