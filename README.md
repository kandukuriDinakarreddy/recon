# 🔍 RECON — Automated Security Reconnaissance Tool

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/shell-bash-green?style=for-the-badge&logo=gnu-bash" />
  <img src="https://img.shields.io/badge/license-MIT-yellow?style=for-the-badge" />
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey?style=for-the-badge" />
</p>

```
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
  Automated Reconnaissance Tool v2.0
  Parallel · Screenshots · JSON+HTML · CVSS v3.1
```

---

## ⚡ What It Does

**recon.sh** is a full-featured automated reconnaissance tool for security professionals and bug bounty hunters. Point it at a domain and it will:

- 🌐 **Enumerate subdomains** using subfinder + assetfinder  
- ✅ **Probe live hosts** with httpx  
- 🔓 **Scan open ports** via nmap (with service/version detection)  
- 🕵️ **Mine historical URLs** from gau + Wayback Machine  
- 💣 **Scan vulnerabilities** using nuclei templates  
- 🚨 **Detect misconfigurations** (CORS, missing headers, exposed .git, .env, etc.)  
- 🏴 **Find subdomain takeover** candidates  
- 📸 **Take screenshots** of live hosts (gowitness / cutycapt / chromium)  
- 📊 **Score every finding** with a real CVSS v3.1 base score calculator  
- 📝 **Generate reports** in Text, JSON, and interactive HTML  

All scans run in **parallel** with a configurable thread pool for maximum speed.

---

## 🖥️ Demo Output

```
[*] Target     : example.com
[*] Threads    : 15
[*] Output dir : ./recon_example.com_20240101_120000
[*] Started at : Mon Jan  1 12:00:00 2024

════════════════════════════════════════════════
  RECONNAISSANCE COMPLETE
════════════════════════════════════════════════

  Target:                              example.com
  Subdomains discovered:               42
  Live hosts:                          18
  Open ports:                          73
  Screenshots captured:                18

    CRITICAL (CVSS 9.0–10.0):         2
    HIGH     (CVSS 7.0–8.9):          5
    MEDIUM   (CVSS 4.0–6.9):          11
    LOW      (CVSS 0.1–3.9):          7

  Reports:
  📄 Text : ./recon_example.com_20240101_120000/REPORT_example.com.txt
  📊 JSON : ./recon_example.com_20240101_120000/REPORT_example.com.json
  🌐 HTML : ./recon_example.com_20240101_120000/REPORT_example.com.html
  📸 Shots: ./recon_example.com_20240101_120000/screenshots/
```

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/recon.git
cd recon

# Make executable
chmod +x recon.sh

# Run against a target (use only on domains you own or have permission to test)
./recon.sh example.com

# Custom thread count
./recon.sh example.com --threads 25
```

---

## 📋 Usage

```
./recon.sh <domain> [--threads N]

Arguments:
  <domain>        Target domain (e.g. example.com)
  --threads N     Number of parallel threads (default: 15)

Examples:
  ./recon.sh example.com
  ./recon.sh target.org --threads 30
```

---

## 🛠️ Required & Optional Tools

The script **auto-detects** which tools are installed and gracefully falls back if any are missing. Install as many as possible for best coverage.

| Tool | Purpose | Install |
|------|---------|---------|
| `subfinder` | Subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `assetfinder` | Subdomain enumeration | `go install github.com/tomnomnom/assetfinder@latest` |
| `httpx` | Live host probing | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `nmap` | Port scanning | `sudo apt install nmap` |
| `nuclei` | Vulnerability scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `gau` | Historical URL mining | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| `waybackurls` | Wayback Machine URLs | `go install github.com/tomnomnom/waybackurls@latest` |
| `gowitness` | Screenshots | `go install github.com/sensepost/gowitness@latest` |
| `python3` | CVSS score calculation | Usually pre-installed |
| `curl` / `dig` / `host` | DNS / HTTP checks | Usually pre-installed |

> 💡 See [INSTALL.md](INSTALL.md) for a one-command setup script.

---

## 📁 Output Structure

Every scan creates a timestamped folder:

```
recon_<target>_<timestamp>/
├── subdomains/
│   ├── subfinder.txt
│   ├── assetfinder.txt
│   └── all_subs.txt          # deduplicated
├── ports/
│   └── nmap_full.txt
├── vulns/
│   ├── nuclei_results.txt
│   └── misconfigs.txt
├── urls/
│   ├── gau.txt
│   ├── wayback.txt
│   └── juicy_urls.txt        # backups, configs, API keys
├── screenshots/              # PNG screenshots of live hosts
├── findings.tsv              # raw findings with CVSS scores
├── REPORT_<target>.txt       # plain text report
├── REPORT_<target>.json      # machine-readable JSON report
└── REPORT_<target>.html      # interactive HTML report
```

---

## 🔒 CVSS v3.1 Scoring

Every finding is assigned a real **CVSS v3.1 base score** using a pure-Python calculator (no external libraries needed). Findings are categorised as:

| Score Range | Severity |
|-------------|---------|
| 9.0 – 10.0 | 🔴 CRITICAL |
| 7.0 – 8.9  | 🟠 HIGH |
| 4.0 – 6.9  | 🟡 MEDIUM |
| 0.1 – 3.9  | 🟢 LOW |

Example finding types and their profiles:

| Finding | CVSS Score |
|---------|-----------|
| Subdomain Takeover | 9.8 CRITICAL |
| Exposed .git / .env | 7.5 HIGH |
| CORS Misconfiguration | 7.1 HIGH |
| Open DB Port | 9.8 CRITICAL |
| Missing HSTS | 3.1 LOW |

---

## ⚠️ Legal Disclaimer

> **This tool is for authorised security testing ONLY.**  
> Only run this against domains you **own** or have **explicit written permission** to test.  
> Unauthorised scanning may be illegal under the Computer Misuse Act, CFAA, or equivalent laws in your country.  
> The author takes no responsibility for misuse.

---

## 🤝 Contributing

Pull requests are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for full text.

---

## 👤 Author

Made with ❤️ and a lot of terminal windows.  
If this tool helped you, drop a ⭐ on GitHub!
