#!/bin/bash
set -e

REPO_URL="https://github.com/R-s0n/ars0n-framework-v2.git"
API_URL="https://api.github.com/repos/R-s0n/ars0n-framework-v2/releases/latest"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_banner() {
    echo -e "${CYAN}"
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║     Ars0n Framework v2 - Updater         ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info()    { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

check_prerequisites() {
    log_info "Checking prerequisites..."

    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi

    if ! command -v git &> /dev/null; then
        log_error "Git is not installed. Please install Git first."
        exit 1
    fi

    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running. Please start Docker."
        exit 1
    fi

    log_info "All prerequisites met."
}

get_latest_version() {
    log_info "Fetching latest release version..."
    LATEST_TAG=$(curl -s "$API_URL" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

    if [ -z "$LATEST_TAG" ]; then
        log_warn "Could not fetch latest release tag from GitHub API. Falling back to main branch."
        LATEST_TAG="main"
    else
        log_info "Latest release: $LATEST_TAG"
    fi
}

stop_containers() {
    log_info "Stopping running containers..."
    if docker compose ps --quiet 2>/dev/null | grep -q .; then
        docker compose down 2>/dev/null || docker-compose down 2>/dev/null || true
        log_info "Containers stopped."
    elif docker-compose ps --quiet 2>/dev/null | grep -q .; then
        docker-compose down 2>/dev/null || true
        log_info "Containers stopped."
    else
        log_info "No running containers found."
    fi
}

backup_custom_files() {
    BACKUP_DIR=".ars0n-backup-$(date +%Y%m%d%H%M%S)"
    mkdir -p "$BACKUP_DIR"

    if [ -f "docker-compose.yml" ]; then
        cp docker-compose.yml "$BACKUP_DIR/docker-compose.yml"
    fi

    if [ -d "wordlists" ]; then
        cp -r wordlists "$BACKUP_DIR/wordlists"
    fi

    log_info "Backup saved to $BACKUP_DIR"
}

update_via_git() {
    if [ -d ".git" ]; then
        log_info "Git repository detected. Updating via git..."

        CURRENT_REMOTE=$(git remote get-url origin 2>/dev/null || echo "")
        if [ -z "$CURRENT_REMOTE" ]; then
            git remote add origin "$REPO_URL"
        fi

        if git diff --quiet && git diff --cached --quiet; then
            log_info "No local changes detected."
        else
            log_warn "Local changes detected. Stashing them..."
            git stash push -m "ars0n-update-$(date +%Y%m%d%H%M%S)"
            log_info "Changes stashed. You can restore them later with 'git stash pop'."
        fi

        git fetch origin --tags

        if [ "$LATEST_TAG" = "main" ]; then
            git checkout main
            git pull origin main
        else
            git checkout "$LATEST_TAG"
        fi
    else
        log_info "Not a git repository. Initializing git for updates..."

        git init
        git remote add origin "$REPO_URL"
        git fetch origin --tags

        if [ "$LATEST_TAG" = "main" ]; then
            git checkout -f origin/main
            git checkout -B main
            git branch --set-upstream-to=origin/main main
        else
            git checkout -f "$LATEST_TAG"
        fi
    fi

    log_info "Code updated to $LATEST_TAG"
}

rebuild_containers() {
    log_info "Rebuilding and starting containers (this may take a while)..."

    if command -v docker compose &> /dev/null 2>&1 && docker compose version &> /dev/null 2>&1; then
        docker compose up --build -d
    else
        docker-compose up --build -d
    fi

    log_info "Containers rebuilt and started."
}

verify_update() {
    log_info "Verifying update..."
    sleep 10

    RUNNING=$(docker ps --filter "name=ars0n-framework" --format "{{.Names}}" | wc -l)
    if [ "$RUNNING" -gt 0 ]; then
        log_info "$RUNNING containers running."
        log_info "Framework should be accessible at http://localhost"
    else
        log_warn "No containers appear to be running. Check logs with: docker compose logs"
    fi
}

print_banner
check_prerequisites
get_latest_version

echo ""
log_info "This will update your Ars0n Framework to version: $LATEST_TAG"
log_info "Your scan data and settings (stored in Docker volumes) will be preserved."
echo ""
read -p "Continue with update? (y/N): " CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    log_info "Update cancelled."
    exit 0
fi

echo ""
stop_containers
backup_custom_files
update_via_git
rebuild_containers
verify_update

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         Update Complete!                  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
log_info "Version: $LATEST_TAG"
log_info "Access the framework at: http://localhost"
log_info "If you customized docker-compose.yml, check $BACKUP_DIR for your backup."
echo ""
