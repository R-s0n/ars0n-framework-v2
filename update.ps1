$ErrorActionPreference = "Stop"

$REPO_URL = "https://github.com/R-s0n/ars0n-framework-v2.git"
$API_URL = "https://api.github.com/repos/R-s0n/ars0n-framework-v2/releases/latest"

function Write-Banner {
    Write-Host ""
    Write-Host "  +============================================+" -ForegroundColor Cyan
    Write-Host "  |      Ars0n Framework v2 - Updater          |" -ForegroundColor Cyan
    Write-Host "  +============================================+" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Info    { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Green }
function Write-Warn    { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err     { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

function Test-Prerequisites {
    Write-Info "Checking prerequisites..."

    $dockerPath = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $dockerPath) {
        Write-Err "Docker is not installed. Please install Docker Desktop first."
        exit 1
    }

    $gitPath = Get-Command git -ErrorAction SilentlyContinue
    if (-not $gitPath) {
        Write-Err "Git is not installed. Please install Git first."
        exit 1
    }

    try {
        docker info 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Docker not running" }
    } catch {
        Write-Err "Docker daemon is not running. Please start Docker Desktop."
        exit 1
    }

    Write-Info "All prerequisites met."
}

function Get-LatestVersion {
    Write-Info "Fetching latest release version..."
    try {
        $response = Invoke-RestMethod -Uri $API_URL -Method Get -ErrorAction Stop
        $script:LatestTag = $response.tag_name
        Write-Info "Latest release: $script:LatestTag"
    } catch {
        Write-Warn "Could not fetch latest release tag from GitHub API. Falling back to main branch."
        $script:LatestTag = "main"
    }
}

function Stop-Containers {
    Write-Info "Stopping running containers..."
    try {
        $running = docker ps --filter "name=ars0n-framework" --format "{{.Names}}" 2>$null
        if ($running) {
            docker compose down 2>$null
            if ($LASTEXITCODE -ne 0) {
                docker-compose down 2>$null
            }
            Write-Info "Containers stopped."
        } else {
            Write-Info "No running containers found."
        }
    } catch {
        Write-Warn "Could not stop containers: $_"
    }
}

function Backup-CustomFiles {
    $timestamp = Get-Date -Format "yyyyMMddHHmmss"
    $script:BackupDir = ".ars0n-backup-$timestamp"
    New-Item -ItemType Directory -Path $script:BackupDir -Force | Out-Null

    if (Test-Path "docker-compose.yml") {
        Copy-Item "docker-compose.yml" "$script:BackupDir\docker-compose.yml"
    }

    if (Test-Path "wordlists") {
        Copy-Item -Recurse "wordlists" "$script:BackupDir\wordlists"
    }

    Write-Info "Backup saved to $script:BackupDir"
}

function Update-ViaGit {
    if (Test-Path ".git") {
        Write-Info "Git repository detected. Updating via git..."

        $currentRemote = git remote get-url origin 2>$null
        if (-not $currentRemote) {
            git remote add origin $REPO_URL
        }

        $diffOutput = git diff --quiet 2>$null
        $diffCachedOutput = git diff --cached --quiet 2>$null
        $hasDiff = $LASTEXITCODE -ne 0

        git diff --quiet 2>$null
        $hasUnstaged = $LASTEXITCODE -ne 0
        git diff --cached --quiet 2>$null
        $hasStaged = $LASTEXITCODE -ne 0

        if ($hasUnstaged -or $hasStaged) {
            Write-Warn "Local changes detected. Stashing them..."
            $timestamp = Get-Date -Format "yyyyMMddHHmmss"
            git stash push -m "ars0n-update-$timestamp"
            Write-Info "Changes stashed. You can restore them later with 'git stash pop'."
        } else {
            Write-Info "No local changes detected."
        }

        git fetch origin --tags

        if ($script:LatestTag -eq "main") {
            git checkout main
            git pull origin main
        } else {
            git checkout $script:LatestTag
        }
    } else {
        Write-Info "Not a git repository. Initializing git for updates..."

        git init
        git remote add origin $REPO_URL
        git fetch origin --tags

        if ($script:LatestTag -eq "main") {
            git checkout -f origin/main
            git checkout -B main
            git branch --set-upstream-to=origin/main main
        } else {
            git checkout -f $script:LatestTag
        }
    }

    Write-Info "Code updated to $script:LatestTag"
}

function Rebuild-Containers {
    Write-Info "Rebuilding and starting containers (this may take a while)..."

    $composeV2 = docker compose version 2>$null
    if ($LASTEXITCODE -eq 0) {
        docker compose up --build -d
    } else {
        docker-compose up --build -d
    }

    Write-Info "Containers rebuilt and started."
}

function Confirm-Update {
    Write-Info "Verifying update..."
    Start-Sleep -Seconds 10

    $running = docker ps --filter "name=ars0n-framework" --format "{{.Names}}"
    $count = ($running | Measure-Object).Count

    if ($count -gt 0) {
        Write-Info "$count containers running."
        Write-Info "Framework should be accessible at http://localhost"
    } else {
        Write-Warn "No containers appear to be running. Check logs with: docker compose logs"
    }
}

Write-Banner
Test-Prerequisites
Get-LatestVersion

Write-Host ""
Write-Info "This will update your Ars0n Framework to version: $LatestTag"
Write-Info "Your scan data and settings (stored in Docker volumes) will be preserved."
Write-Host ""

$confirm = Read-Host "Continue with update? (y/N)"
if ($confirm -ne "y" -and $confirm -ne "Y") {
    Write-Info "Update cancelled."
    exit 0
}

Write-Host ""
Stop-Containers
Backup-CustomFiles
Update-ViaGit
Rebuild-Containers
Confirm-Update

Write-Host ""
Write-Host "+============================================+" -ForegroundColor Green
Write-Host "|          Update Complete!                   |" -ForegroundColor Green
Write-Host "+============================================+" -ForegroundColor Green
Write-Host ""
Write-Info "Version: $LatestTag"
Write-Info "Access the framework at: http://localhost"
Write-Info "If you customized docker-compose.yml, check $BackupDir for your backup."
Write-Host ""
