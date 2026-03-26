#!/usr/bin/env bash
# install_recon_tools.sh – Install missing recon tools for bug bounty
# Usage: ./install_recon_tools.sh

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# Tools to install (list of binary names and optional install methods)
declare -A TOOLS=(
    [subfinder]="go_install"
    [amass]="apt|brew|go_install"
    [httpx]="go_install"
    [katana]="go_install"
    [waybackurls]="go_install"
    [gau]="go_install"
    [nuclei]="go_install"
)

# ---- Helper functions ----
command_exists() {
    command -v "$1" &>/dev/null
}

install_go() {
    if command_exists go; then
        log_info "Go already installed: $(go version)"
        return 0
    fi
    log_warn "Go not found. Attempting to install..."
    # Detect OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        GO_VERSION="1.22.2"  # Use latest stable
        ARCH=$(uname -m)
        if [[ "$ARCH" == "x86_64" ]]; then ARCH="amd64"; fi
        if [[ "$ARCH" == "aarch64" ]]; then ARCH="arm64"; fi
        TARBALL="go${GO_VERSION}.linux-${ARCH}.tar.gz"
        wget -q "https://golang.org/dl/${TARBALL}" || curl -sLO "https://golang.org/dl/${TARBALL}"
        sudo tar -C /usr/local -xzf "${TARBALL}"
        rm "${TARBALL}"
        # Add to PATH in .zprofile (for Zsh)
        if ! grep -q "/usr/local/go/bin" ~/.zprofile 2>/dev/null; then
            echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zprofile
            echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zprofile
        fi
        export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
        log_info "Go installed. Please reload your shell or run: source ~/.zprofile"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        brew install go || log_error "Failed to install Go via Homebrew. Please install manually."
        # On macOS, Homebrew usually handles PATH, but ensure .zprofile includes go/bin
        if ! grep -q "/usr/local/go/bin" ~/.zprofile 2>/dev/null && ! grep -q "/opt/homebrew/bin/go" ~/.zprofile 2>/dev/null; then
            echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.zprofile
        fi
        export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    else
        log_error "Unsupported OS. Please install Go manually: https://golang.org/dl/"
    fi
}

install_via_go() {
    local tool=$1
    log_info "Installing $tool via 'go install'..."
    # Ensure GOPATH/bin is in PATH
    export PATH=$PATH:$(go env GOPATH)/bin
    go install -v "github.com/projectdiscovery/${tool}@latest" || \
    go install -v "github.com/tomnomnom/${tool}@latest" || \
    go install -v "github.com/lc/${tool}@latest" || \
    go install -v "github.com/OWASP/Amass/v3/...@master" || \
    log_error "Failed to install $tool via go install"
}

install_via_apt() {
    local tool=$1
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command_exists apt; then
            log_info "Installing $tool via apt..."
            sudo apt update -qq
            sudo apt install -y "$tool"
        else
            log_error "No apt found. Cannot install $tool via package manager."
        fi
    else
        log_error "apt not available on this OS."
    fi
}

install_via_brew() {
    local tool=$1
    if [[ "$OSTYPE" == "darwin"* ]]; then
        if command_exists brew; then
            log_info "Installing $tool via Homebrew..."
            brew install "$tool"
        else
            log_error "Homebrew not found. Please install Homebrew first: https://brew.sh/"
        fi
    else
        log_error "Homebrew only available on macOS."
    fi
}

install_tool() {
    local tool=$1
    local methods=$2

    if command_exists "$tool"; then
        log_info "$tool is already installed: $(which $tool)"
        return 0
    fi

    log_warn "$tool not found. Attempting installation..."

    IFS='|' read -ra METHOD_ARRAY <<< "$methods"
    for method in "${METHOD_ARRAY[@]}"; do
        case "$method" in
            go_install)
                install_via_go "$tool" && return 0
                ;;
            apt)
                install_via_apt "$tool" && return 0
                ;;
            brew)
                install_via_brew "$tool" && return 0
                ;;
        esac
    done

    log_error "Could not install $tool. Please install manually."
}

# ---- Main ----
main() {
    log_info "Starting tool installation check..."

    # Ensure Go is installed (required for most tools)
    if ! command_exists go; then
        install_go
        # After installing Go, re-source PATH (if script can't, user must do manually)
        export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    fi

    # Install each tool
    for tool in "${!TOOLS[@]}"; do
        install_tool "$tool" "${TOOLS[$tool]}"
    done

    log_info "All tools are now installed."
    log_info "If you installed Go or added new binaries, please run: source ~/.zprofile"
}

main "$@"