#!/usr/bin/env bash
# ==============================================================================
#  install_tools.sh — Auto-installer for recon.sh dependencies
#  Run: bash install_tools.sh
# ==============================================================================

set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[-]${NC} $*"; exit 1; }

echo -e "${GREEN}"
cat <<'EOF'
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
  Tool Installer
EOF
echo -e "${NC}"

# ── Check OS ───────────────────────────────────────────────────────────────────
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    error "Unsupported OS: $OSTYPE"
fi
info "Detected OS: ${OS}"

# ── Check / install Go ─────────────────────────────────────────────────────────
info "Checking Go..."
if ! command -v go &>/dev/null; then
    warn "Go not found. Installing..."
    if [[ "$OS" == "linux" ]]; then
        GO_VERSION="1.22.3"
        curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf /tmp/go.tar.gz
        echo 'export PATH=$PATH:/usr/local/go/bin:$(go env GOPATH)/bin' >> ~/.bashrc
        export PATH=$PATH:/usr/local/go/bin
        success "Go ${GO_VERSION} installed"
    else
        warn "Please install Go manually from https://go.dev/dl/ then re-run this script."
        exit 1
    fi
else
    success "Go found: $(go version)"
fi

# Ensure GOPATH/bin is in PATH
export PATH=$PATH:$(go env GOPATH)/bin
grep -q 'GOPATH' ~/.bashrc 2>/dev/null || \
    echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc

# ── System packages ────────────────────────────────────────────────────────────
info "Installing system packages..."
if command -v apt &>/dev/null; then
    sudo apt update -qq
    sudo apt install -y nmap chromium-browser python3 curl dnsutils 2>/dev/null || \
    sudo apt install -y nmap chromium python3 curl dnsutils 2>/dev/null || true
    success "System packages installed"
elif command -v brew &>/dev/null; then
    brew install nmap python3 2>/dev/null || true
    success "Homebrew packages installed"
else
    warn "Could not detect apt or brew — install nmap, python3, curl manually"
fi

# ── Go tools ───────────────────────────────────────────────────────────────────
GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/sensepost/gowitness@latest"
)

info "Installing Go tools (this may take a few minutes)..."
for tool in "${GO_TOOLS[@]}"; do
    name=$(basename "${tool%@*}")
    info "Installing ${name}..."
    go install "${tool}" && success "${name} installed" || warn "Failed to install ${name}"
done

# ── Nuclei templates ───────────────────────────────────────────────────────────
if command -v nuclei &>/dev/null; then
    info "Updating nuclei templates..."
    nuclei -update-templates -silent && success "Nuclei templates updated"
fi

# ── Final check ────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}═══════════════════════════════════════${NC}"
echo -e "${GREEN}  Installation complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════${NC}"
echo ""
info "Checking installed tools:"
for t in subfinder assetfinder httpx nmap nuclei gau waybackurls gowitness python3 curl; do
    if command -v "$t" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $t"
    else
        echo -e "  ${YELLOW}✗${NC} $t (not found — may need to restart terminal)"
    fi
done
echo ""
info "Run: source ~/.bashrc   (or restart your terminal)"
info "Then: chmod +x recon.sh && ./recon.sh yourdomain.com"
