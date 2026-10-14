
pipeline {
    agent any

    environment {
        PYTHON_HOME = 'C:\\Users\\hp\\AppData\\Local\\Programs\\Python\\Python313'
        PYTHON_VENV = "${WORKSPACE}\\backend\\venv"
        PYTHON_EXE = "${WORKSPACE}\\backend\\venv\\Scripts\\python.exe"
        RUFF_EXE = "${WORKSPACE}\\backend\\venv\\Scripts\\ruff.exe"
        BANDIT_EXE = "${WORKSPACE}\\backend\\venv\\Scripts\\bandit.exe"
        PYTEST_EXE = "${WORKSPACE}\\backend\\venv\\Scripts\\pytest.exe"
    }

    stages {
        stage('Verify Tools') {
            steps {
                bat '''
                    @echo off
                    "%PYTHON_HOME%\\python.exe" --version
                    if errorlevel 1 exit /b 1
                    where.exe git
                    if errorlevel 1 exit /b 1
                    where.exe npm
                    if errorlevel 1 exit /b 1
                    call npm --version
                    if errorlevel 1 exit /b 1
                '''
            }
        }

        stage('Install Backend Dependencies') {
            steps {
                bat '''
                    @echo off
                    if not exist "%PYTHON_VENV%\\Scripts\\python.exe" (
                        "%PYTHON_HOME%\\python.exe" -m venv "%PYTHON_VENV%"
                        if errorlevel 1 exit /b 1
                    )
                    "%PYTHON_EXE%" -m pip install --upgrade pip
                    if errorlevel 1 exit /b 1
                    "%PYTHON_EXE%" -m pip install -r backend\\requirements.txt
                    if errorlevel 1 exit /b 1
                '''
            }
        }

        stage('Build Frontend') {
            steps {
                dir('frontend') {
                    bat '''
                        @echo off
                        call npm ci --no-audit
                        if errorlevel 1 exit /b 1
                        call npm run type-check
                        if errorlevel 1 exit /b 1
                        call npm run build
                        if errorlevel 1 exit /b 1
                    '''
                }
            }
        }

        stage('Code Quality - Ruff') {
            steps {
                bat '''
                    @echo off
                    "%PYTHON_EXE%" -m ruff check backend\\ tests\\
                    if errorlevel 1 exit /b 1
                '''
            }
        }

        stage('Security - Bandit') {
            steps {
                bat '''
                    @echo off
                    "%PYTHON_EXE%" -m bandit -r backend\\app\\ -ll
                    if errorlevel 1 exit /b 1
                '''
            }
        }

        stage('Automated Tests - Pytest') {
            steps {
                bat '''
                    @echo off
                    if not exist reports mkdir reports
                    "%PYTHON_EXE%" -m pytest -v --junitxml=reports\\pytest-results.xml
                    if errorlevel 1 exit /b 1
                '''
            }
            post {
                always {
                    junit testResults: 'reports/pytest-results.xml',
                          allowEmptyResults: true
                }
            }
        }

         stage('Deploy VulnWatch') {
            steps {
                powershell '''
                    $ErrorActionPreference = "Stop"
                    & "$env:WORKSPACE\\scripts\\deploy.ps1"
                    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
                        throw "Deployment failed."
                    }
                '''
            }
        }
    }

    post {
        success {
            echo 'VulnWatch CI checks and deployment completed successfully.'
        }
        failure {
            echo 'VulnWatch pipeline failed. Review the stage logs.'
        }
    }
}
