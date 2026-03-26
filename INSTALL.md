# 🛠️ Installation Guide

## Prerequisites

- Linux (Ubuntu/Debian/Kali recommended) or macOS
- `bash` 4.0+
- `go` 1.21+ (for Go-based tools)
- `python3` (usually pre-installed)
- `curl`, `dig`, `host` (usually pre-installed)

---

## Option 1 — One-Command Auto Installer

Run this script to install all tools automatically:

```bash
bash install_tools.sh
```

> The script installs Go tools and system packages. Run with `sudo` for apt packages.

---

## Option 2 — Manual Install

### Step 1: Install Go (if not already installed)

```bash
# Ubuntu / Debian / Kali
sudo apt update
sudo apt install golang-go -y

# Or download the latest Go from:
# https://go.dev/dl/
```

Verify:
```bash
go version
```

Make sure your Go bin is in PATH:
```bash
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
```

---

### Step 2: Install Go-based Tools

```bash
# Subdomain enumeration
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest

# Live host probing
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Vulnerability scanning
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Historical URL mining
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest

# Screenshots
go install github.com/sensepost/gowitness@latest
```

---

### Step 3: Install System Tools

```bash
# Ubuntu / Debian / Kali
sudo apt update
sudo apt install -y nmap chromium-browser python3 curl dnsutils

# macOS (Homebrew)
brew install nmap chromium python3
```

---

### Step 4: Update Nuclei Templates

```bash
nuclei -update-templates
```

---

### Step 5: Clone and Run

```bash
git clone https://github.com/YOUR_USERNAME/recon.git
cd recon
chmod +x recon.sh
./recon.sh example.com
```

---

## Kali Linux (Recommended for Security Testing)

Most tools are already available on Kali. Just install the Go tools:

```bash
sudo apt install golang-go nmap -y
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/sensepost/gowitness@latest

nuclei -update-templates
```

---

## Verifying Installation

Run the tool against a safe test target (your own domain or a legal test environment):

```bash
./recon.sh yourdomain.com
```

The tool will print which tools were found and which are missing — it runs fine with only partial installs.

---

## Troubleshooting

| Problem | Solution |
|---------|---------|
| `command not found: subfinder` | Run `source ~/.bashrc` or restart terminal |
| `go: command not found` | Install Go and add to PATH |
| Permission denied | Run `chmod +x recon.sh` |
| nmap needs sudo | Run `sudo ./recon.sh example.com` for full nmap access |
| nuclei templates missing | Run `nuclei -update-templates` |
