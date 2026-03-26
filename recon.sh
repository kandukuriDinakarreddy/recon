#!/usr/bin/env bash
# ==============================================================================
#  recon.sh — Automated Security Reconnaissance Tool v2.0
#  Author  : github.com/YOUR_USERNAME
#  License : MIT
#  Features: Parallel scanning · Screenshots · JSON+HTML reports · CVSS scoring
#  Usage   : ./recon.sh <domain> [--threads N]
#
#  CHANGELOG
#  v2.0 — Parallel scanning, HTML/JSON reports, CVSS v3.1 scoring, screenshots
#  v1.0 — Initial release
#
#  LEGAL: For authorised security testing ONLY.
#         Only scan targets you own or have explicit written permission to test.
# ==============================================================================

set -euo pipefail

# ── Colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

# ── Banner ─────────────────────────────────────────────────────────────────────
banner() {
cat <<'EOF'
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
  Automated Reconnaissance Tool v2.0
  Parallel · Screenshots · JSON+HTML · CVSS
EOF
}

# ── Logging helpers ────────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[-]${NC} $*"; }
section() {
    echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  $*${NC}"
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════${NC}"
}

# ── Argument parsing ───────────────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
    echo -e "${RED}Usage:${NC} $0 <domain> [--threads N]"
    echo -e "  Example: $0 example.com --threads 20"
    exit 1
fi

TARGET="${1,,}"
THREADS=15
shift
while [[ $# -gt 0 ]]; do
    case "$1" in
        --threads) THREADS="$2"; shift 2 ;;
        *) shift ;;
    esac
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_DIR="$(pwd)/recon_${TARGET}_${TIMESTAMP}"
SUBS_DIR="${BASE_DIR}/subdomains"
PORTS_DIR="${BASE_DIR}/ports"
VULN_DIR="${BASE_DIR}/vulns"
URLS_DIR="${BASE_DIR}/urls"
SHOTS_DIR="${BASE_DIR}/screenshots"
REPORT_TXT="${BASE_DIR}/REPORT_${TARGET}.txt"
REPORT_JSON="${BASE_DIR}/REPORT_${TARGET}.json"
REPORT_HTML="${BASE_DIR}/REPORT_${TARGET}.html"
LOG="${BASE_DIR}/recon.log"

mkdir -p "${SUBS_DIR}" "${PORTS_DIR}" "${VULN_DIR}" "${URLS_DIR}" "${SHOTS_DIR}"
exec 2>>"${LOG}"

banner
echo ""
info "Target     : ${BOLD}${TARGET}${NC}"
info "Threads    : ${BOLD}${THREADS}${NC}"
info "Output dir : ${BASE_DIR}"
info "Started at : $(date)"
echo ""

# ── Tool check ─────────────────────────────────────────────────────────────────
TOOLS_AVAILABLE=(); TOOLS_MISSING=()
check_tool() {
    if command -v "$1" &>/dev/null; then TOOLS_AVAILABLE+=("$1"); success "Found: $1"
    else TOOLS_MISSING+=("$1"); warn "Not found: $1 (degraded fallback will run)"
    fi
}
section "Checking Installed Tools"
for t in subfinder assetfinder httpx nmap gau waybackurls nuclei \
          gowitness cutycapt chromium-browser google-chrome curl dig host python3; do
    check_tool "$t"
done

# ── Parallel worker pool ───────────────────────────────────────────────────────
PARALLEL_PIDS=()
parallel_flush() {
    for pid in "${PARALLEL_PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
    PARALLEL_PIDS=()
}
run_parallel() {
    local input="$1" max_jobs="$2" func="$3"
    local count=0
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        "$func" "${line}" &
        PARALLEL_PIDS+=($!)
        (( ++count ))
        if (( count % max_jobs == 0 )); then parallel_flush; fi
    done < "${input}"
    parallel_flush
}

# ── Mutex for safe parallel writes ────────────────────────────────────────────
LOCK_DIR="${BASE_DIR}/.locks"
mkdir -p "${LOCK_DIR}"
acquire_lock() { while ! mkdir "${LOCK_DIR}/$1" 2>/dev/null; do sleep 0.05; done; }
release_lock() { rmdir "${LOCK_DIR}/$1" 2>/dev/null || true; }
safe_append() { acquire_lock "append"; echo "$2" >> "$1"; release_lock "append"; }

# ── CVSS v3.1 base score calculator (Python) ──────────────────────────────────
cvss_score() {
    python3 - "$@" <<'PYEOF' 2>/dev/null || echo "5.0 MEDIUM"
import sys, math
av,ac,pr,ui,s,c,i,a = sys.argv[1:9]
AV  = {"N":0.85,"A":0.62,"L":0.55,"P":0.2}
AC  = {"L":0.77,"H":0.44}
PR_U= {"N":0.85,"L":0.62,"H":0.27}
PR_C= {"N":0.85,"L":0.68,"H":0.50}
UI  = {"N":0.85,"R":0.62}
CIA = {"N":0.0,"L":0.22,"H":0.56}
sc  = s == "C"
pvs = PR_C if sc else PR_U
iss = 1-(1-CIA[c])*(1-CIA[i])*(1-CIA[a])
imp = (7.52*(iss-0.029)-3.25*((iss-0.02)**15)) if sc else 6.42*iss
exp = 8.22*AV[av]*AC[ac]*pvs[pr]*UI[ui]
if imp<=0: base=0.0
elif sc:   base=min(1.08*(imp+exp),10.0)
else:      base=min(imp+exp,10.0)
base=math.ceil(base*10)/10
if   base==0: sev="NONE"
elif base<4:  sev="LOW"
elif base<7:  sev="MEDIUM"
elif base<9:  sev="HIGH"
else:         sev="CRITICAL"
print(f"{base} {sev}")
PYEOF
}

# ── CVSS profiles per finding type ────────────────────────────────────────────
cvss_for_finding() {
    case "$1" in
        SUBDOMAIN_TAKEOVER)    cvss_score N L N N C H H H ;;
        EXPOSED_GIT)           cvss_score N L N N U H H N ;;
        EXPOSED_ENV)           cvss_score N L N N U H H N ;;
        CORS_MISCONFIGURATION) cvss_score N L N R C H H N ;;
        SQL_BACKUP_EXPOSED)    cvss_score N L N N U H H N ;;
        ADMIN_PANEL_200)       cvss_score N L N N U H H N ;;
        EXPOSED_PHPMYADMIN)    cvss_score N L N N U H H H ;;
        EXPOSED_GRAPHQL)       cvss_score N L N N U L L N ;;
        DIRECTORY_LISTING)     cvss_score N L N N U L N N ;;
        MISSING_HTTPS)         cvss_score N H N N U L L N ;;
        MISSING_HSTS)          cvss_score N H N N U L N N ;;
        MISSING_CSP)           cvss_score N H N R U L N N ;;
        MISSING_XFRAME)        cvss_score N H N R U L N N ;;
        VERSION_DISCLOSURE)    cvss_score N L N N U N L N ;;
        OPEN_PORT_DB)          cvss_score N L N N U H H H ;;
        OPEN_PORT_TELNET)      cvss_score N L N N U H H H ;;
        NUCLEI_CRITICAL)       echo "9.5 CRITICAL" ;;
        NUCLEI_HIGH)           echo "7.5 HIGH" ;;
        NUCLEI_MEDIUM)         echo "5.0 MEDIUM" ;;
        NUCLEI_LOW)            echo "2.5 LOW" ;;
        *)                     echo "3.5 LOW" ;;
    esac
}

# ── Shared findings log: SEVERITY\tCVSS\tTYPE\tTARGET\tDETAIL ─────────────────
FINDINGS="${BASE_DIR}/findings.tsv"
touch "${FINDINGS}"

add_finding() {
    local ftype="$1" ftarget="$2" fdetail="$3"
    local cvss_result score sev
    cvss_result=$(cvss_for_finding "${ftype}")
    score=$(echo "${cvss_result}" | awk '{print $1}')
    sev=$(echo "${cvss_result}"   | awk '{print $2}')
    acquire_lock "findings"
    printf '%s\t%s\t%s\t%s\t%s\n' "${sev}" "${score}" "${ftype}" "${ftarget}" "${fdetail}" >> "${FINDINGS}"
    release_lock "findings"
}

# ── Built-in DNS wordlist ──────────────────────────────────────────────────────
BUILTIN_WORDLIST=(www mail ftp smtp pop imap api dev staging test admin portal vpn remote
                  cdn assets static media blog shop store git jenkins ci cd app mobile
                  auth login dashboard panel manage control beta stage prod uat api2 m ns1 ns2)

# ==============================================================================
# STEP 1 — SUBDOMAIN DISCOVERY
# ==============================================================================
section "Step 1 — Subdomain Discovery"
info "Discovering subdomains (parallel sources) …"

ALL_SUBS="${SUBS_DIR}/all_subdomains_raw.txt"; touch "${ALL_SUBS}"

if command -v subfinder &>/dev/null; then
    info "Running subfinder …"
    subfinder -d "${TARGET}" -silent -o "${SUBS_DIR}/subfinder.txt" 2>>"${LOG}" || true
    cat "${SUBS_DIR}/subfinder.txt" >> "${ALL_SUBS}" 2>/dev/null || true
    success "subfinder: $(wc -l < "${SUBS_DIR}/subfinder.txt" 2>/dev/null || echo 0) results"
fi

if command -v assetfinder &>/dev/null; then
    info "Running assetfinder …"
    assetfinder --subs-only "${TARGET}" > "${SUBS_DIR}/assetfinder.txt" 2>>"${LOG}" || true
    cat "${SUBS_DIR}/assetfinder.txt" >> "${ALL_SUBS}" 2>/dev/null || true
    success "assetfinder: $(wc -l < "${SUBS_DIR}/assetfinder.txt" 2>/dev/null || echo 0) results"
fi

info "Querying crt.sh …"
CRTSH_OUT="${SUBS_DIR}/crtsh.txt"
curl -sk "https://crt.sh/?q=%25.${TARGET}&output=json" \
    | grep -oP '"name_value":"\K[^"]+' \
    | tr ',' '\n' | sed 's/^\*\.//; s/ //g' \
    | grep -E "\.${TARGET//./\\.}$" | sort -u > "${CRTSH_OUT}" 2>/dev/null || true
cat "${CRTSH_OUT}" >> "${ALL_SUBS}" 2>/dev/null || true
success "crt.sh: $(wc -l < "${CRTSH_OUT}" 2>/dev/null || echo 0) results"

info "Parallel DNS brute-force (${#BUILTIN_WORDLIST[@]} prefixes) …"
BRUTE_OUT="${SUBS_DIR}/dns_bruteforce.txt"; touch "${BRUTE_OUT}"
BRUTE_QUEUE="${BASE_DIR}/.brute_queue.tmp"
printf '%s\n' "${BUILTIN_WORDLIST[@]}" > "${BRUTE_QUEUE}"

dns_probe_word() {
    local sub="${1}.${TARGET}"
    local result=""
    if command -v dig &>/dev/null; then
        result=$(dig +short +time=3 +tries=1 "${sub}" A 2>/dev/null | head -1)
    elif command -v host &>/dev/null; then
        result=$(host -W 3 "${sub}" 2>/dev/null | grep "has address" | awk '{print $NF}' | head -1)
    fi
    [[ -n "${result:-}" ]] && safe_append "${BRUTE_OUT}" "${sub}"
}
export -f dns_probe_word safe_append acquire_lock release_lock
export TARGET BRUTE_OUT LOCK_DIR
run_parallel "${BRUTE_QUEUE}" "${THREADS}" dns_probe_word
cat "${BRUTE_OUT}" >> "${ALL_SUBS}" 2>/dev/null || true
success "DNS brute-force: $(wc -l < "${BRUTE_OUT}") results"

FINAL_SUBS="${SUBS_DIR}/subdomains.txt"
sort -u "${ALL_SUBS}" | grep -E "\.?${TARGET//./\\.}$" | grep -v '^\*' > "${FINAL_SUBS}" || true
TOTAL_SUBS=$(wc -l < "${FINAL_SUBS}")
success "Unique subdomains: ${BOLD}${TOTAL_SUBS}${NC}"

# ==============================================================================
# STEP 2 — LIVE HOST DETECTION (parallel)
# ==============================================================================
section "Step 2 — Live Host Detection (parallel)"
LIVE_HOSTS="${BASE_DIR}/live_hosts.txt"; touch "${LIVE_HOSTS}"
HTTPX_OUT="${BASE_DIR}/httpx_results.txt"; touch "${HTTPX_OUT}"

if command -v httpx &>/dev/null; then
    info "Using httpx -threads ${THREADS} …"
    httpx -l "${FINAL_SUBS}" -silent -threads "${THREADS}" \
          -status-code -title -tech-detect -follow-redirects \
          -o "${HTTPX_OUT}" 2>>"${LOG}" || true
    grep -oP 'https?://[^\s]+' "${HTTPX_OUT}" | sort -u > "${LIVE_HOSTS}" 2>/dev/null || true
else
    warn "httpx not found — parallel curl probe …"
    curl_probe() {
        local sub="$1"
        for scheme in https http; do
            local url="${scheme}://${sub}" code
            code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 6 --connect-timeout 4 "${url}" 2>/dev/null || echo "000")
            if [[ "${code}" =~ ^(2|3|4)[0-9]{2}$ ]]; then
                acquire_lock "live"
                echo "${url}" >> "${LIVE_HOSTS}"
                echo "${url} [${code}]" >> "${HTTPX_OUT}"
                release_lock "live"
                break
            fi
        done
    }
    export -f curl_probe safe_append acquire_lock release_lock
    export LIVE_HOSTS HTTPX_OUT LOCK_DIR
    run_parallel "${FINAL_SUBS}" "${THREADS}" curl_probe
    sort -u "${LIVE_HOSTS}" -o "${LIVE_HOSTS}"
fi

TOTAL_LIVE=$(wc -l < "${LIVE_HOSTS}")
success "Live hosts: ${BOLD}${TOTAL_LIVE}${NC}"

# ==============================================================================
# STEP 3 — PORT SCANNING (parallel)
# ==============================================================================
section "Step 3 — Port Scanning (parallel)"
PORT_REPORT="${PORTS_DIR}/port_scan.txt"; touch "${PORT_REPORT}"
OPEN_PORTS_FILE="${PORTS_DIR}/open_ports.tsv"; touch "${OPEN_PORTS_FILE}"
SCAN_TARGETS="${PORTS_DIR}/scan_targets.txt"
sed -E 's~https?://~~; s~/.*~~; s~:.*~~' "${LIVE_HOSTS}" | sort -u > "${SCAN_TARGETS}" 2>/dev/null || true
DANGEROUS_PORTS=(21 23 3306 5432 6379 27017 9200)

if command -v nmap &>/dev/null; then
    info "Running nmap …"
    [[ $(wc -l < "${SCAN_TARGETS}") -gt 0 ]] && \
    nmap -iL "${SCAN_TARGETS}" --open -sV \
         --script=banner,http-title,ssl-cert \
         -p 21,22,23,25,53,80,110,143,443,445,993,995,3000,3306,3389,5432,5900,6379,8080,8443,8888,9200,9300,27017 \
         -T4 --min-parallelism "${THREADS}" --max-retries 1 --host-timeout 90s \
         -oN "${PORT_REPORT}" 2>>"${LOG}" || true
    # Parse into TSV
    current_host="unknown"
    while IFS= read -r line; do
        if [[ "${line}" =~ "Nmap scan report for" ]]; then
            current_host=$(echo "${line}" | awk '{print $NF}')
        fi
        if [[ "${line}" =~ ^([0-9]+)/tcp[[:space:]]+open ]]; then
            port=$(echo "${line}" | awk '{print $1}' | cut -d/ -f1)
            service=$(echo "${line}" | awk '{print $3}')
            version=$(echo "${line}" | awk '{$1=$2=$3=""; print $0}' | sed 's/^ *//')
            printf '%s\t%s\t%s\t%s\n' "${current_host}" "${port}" "${service}" "${version}" >> "${OPEN_PORTS_FILE}"
            for dp in "${DANGEROUS_PORTS[@]}"; do
                if [[ "${port}" == "${dp}" ]]; then
                    ftype="OPEN_PORT_DB"
                    [[ "${dp}" == "23" ]] && ftype="OPEN_PORT_TELNET"
                    add_finding "${ftype}" "${current_host}:${port}" "${service} on port ${dp}"
                fi
            done
        fi
    done < "${PORT_REPORT}" 2>/dev/null || true
else
    warn "nmap not found — parallel /dev/tcp scan …"
    COMMON_PORTS=(21 22 23 25 53 80 110 143 443 445 3306 3389 5432 6379 8080 8443 9200 27017)
    tcp_scan_host() {
        local host="$1"
        for port in "${COMMON_PORTS[@]}"; do
            if (echo >/dev/tcp/"${host}"/"${port}") 2>/dev/null; then
                acquire_lock "ports"
                printf '%s\t%s\ttcp\topen\n' "${host}" "${port}" >> "${OPEN_PORTS_FILE}"
                release_lock "ports"
                for dp in "${DANGEROUS_PORTS[@]}"; do
                    if [[ "${port}" == "${dp}" ]]; then
                        ftype="OPEN_PORT_DB"; [[ "${dp}" == "23" ]] && ftype="OPEN_PORT_TELNET"
                        add_finding "${ftype}" "${host}:${port}" "Exposed port ${dp}"
                    fi
                done
            fi
        done
    }
    export -f tcp_scan_host add_finding safe_append acquire_lock release_lock cvss_for_finding cvss_score
    export OPEN_PORTS_FILE FINDINGS LOCK_DIR COMMON_PORTS DANGEROUS_PORTS
    run_parallel "${SCAN_TARGETS}" "${THREADS}" tcp_scan_host
fi

OPEN_PORTS=$(wc -l < "${OPEN_PORTS_FILE}")
success "Open ports: ${BOLD}${OPEN_PORTS}${NC}"

# ==============================================================================
# STEP 4 — TECHNOLOGY FINGERPRINTING (parallel)
# ==============================================================================
section "Step 4 — Technology Fingerprinting (parallel)"
TECH_REPORT="${BASE_DIR}/technologies.txt"; touch "${TECH_REPORT}"

if command -v httpx &>/dev/null && [[ -s "${HTTPX_OUT}" ]]; then
    grep -oP '\[[^\]]+\]' "${HTTPX_OUT}" | sort | uniq -c | sort -rn >> "${TECH_REPORT}" || true
else
    fingerprint_host() {
        local url="$1"
        local hdrs out="${url}:"
        hdrs=$(curl -sk -I --max-time 8 "${url}" 2>/dev/null)
        for h in Server X-Powered-By X-Generator X-CMS X-Drupal-Cache; do
            local val
            val=$(echo "${hdrs}" | grep -i "^${h}:" | cut -d: -f2- | tr -d '\r\n ' || true)
            [[ -n "${val}" ]] && out+=" [${h}: ${val}]"
        done
        acquire_lock "tech"; echo "${out}" >> "${TECH_REPORT}"; release_lock "tech"
    }
    export -f fingerprint_host safe_append acquire_lock release_lock TECH_REPORT LOCK_DIR
    run_parallel "${LIVE_HOSTS}" "${THREADS}" fingerprint_host
fi
success "Technology fingerprinting complete"

# ==============================================================================
# STEP 5 — HISTORICAL URLS
# ==============================================================================
section "Step 5 — Historical URL Collection"
HISTORICAL_URLS="${URLS_DIR}/historical_urls.txt"; touch "${HISTORICAL_URLS}"

if command -v gau &>/dev/null; then
    info "Running gau …"; gau "${TARGET}" --o "${HISTORICAL_URLS}" 2>>"${LOG}" || true
elif command -v waybackurls &>/dev/null; then
    info "Running waybackurls …"; echo "${TARGET}" | waybackurls > "${HISTORICAL_URLS}" 2>>"${LOG}" || true
else
    info "Wayback CDX API …"
    curl -sk "http://web.archive.org/cdx/search/cdx?url=*.${TARGET}/*&output=text&fl=original&collapse=urlkey&limit=2000" \
        > "${HISTORICAL_URLS}" 2>/dev/null || true
fi
JUICY="${URLS_DIR}/juicy_endpoints.txt"
grep -iE "\.(php|asp|aspx|jsp|json|xml|env|sql|bak|config|log|backup|git|yaml|yml)(\?|$|#)" \
    "${HISTORICAL_URLS}" | sort -u > "${JUICY}" 2>/dev/null || true
success "URLs: $(wc -l < "${HISTORICAL_URLS}")  Juicy: $(wc -l < "${JUICY}")"

# ==============================================================================
# STEP 6 — VULNERABILITY SCANNING (parallel)
# ==============================================================================
section "Step 6 — Vulnerability Scanning (parallel)"
VULN_REPORT="${VULN_DIR}/nuclei_results.txt"; touch "${VULN_REPORT}"

if command -v nuclei &>/dev/null; then
    info "Running nuclei …"
    nuclei -l "${LIVE_HOSTS}" -severity low,medium,high,critical \
           -c "${THREADS}" -o "${VULN_REPORT}" -silent -timeout 15 2>>"${LOG}" || true
    while IFS= read -r line; do
        sev_raw=$(echo "${line}" | grep -oP '\[(critical|high|medium|low)\]' | tr -d '[]' | tr '[:lower:]' '[:upper:]' || echo "LOW")
        tgt=$(echo "${line}" | grep -oP 'https?://\S+' | head -1 || echo "unknown")
        add_finding "NUCLEI_${sev_raw}" "${tgt}" "${line}"
    done < "${VULN_REPORT}" 2>/dev/null || true
    success "nuclei: $(wc -l < "${VULN_REPORT}") findings"
else
    warn "nuclei not found — parallel manual checks …"
    MANUAL_VULN="${VULN_DIR}/manual_checks.txt"; touch "${MANUAL_VULN}"
    manual_vuln_check() {
        local url="$1"
        local headers
        headers=$(curl -sk -I --max-time 8 "${url}" 2>/dev/null)
        for h in "Strict-Transport-Security" "X-Frame-Options" "X-Content-Type-Options" "Content-Security-Policy"; do
            if ! echo "${headers}" | grep -qi "${h}"; then
                local ftype="MISSING_HSTS"
                [[ "${h}" == "X-Frame-Options" ]] && ftype="MISSING_XFRAME"
                [[ "${h}" == "Content-Security-Policy" ]] && ftype="MISSING_CSP"
                add_finding "${ftype}" "${url}" "Missing header: ${h}"
                acquire_lock "vuln"; echo "[MISSING_HEADER] ${url} — ${h}" >> "${MANUAL_VULN}"; release_lock "vuln"
            fi
        done
        if [[ "${url}" == http://* ]]; then
            local hcode
            hcode=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "${url/http:/https:}" 2>/dev/null || echo "000")
            if [[ "${hcode}" == "000" ]]; then
                add_finding "MISSING_HTTPS" "${url}" "No HTTPS available"
                acquire_lock "vuln"; echo "[MISSING_HTTPS] ${url}" >> "${MANUAL_VULN}"; release_lock "vuln"
            fi
        fi
        declare -A PATH_TYPES=(
            [/.git/config]="EXPOSED_GIT" [/.env]="EXPOSED_ENV"
            [/wp-config.php]="EXPOSED_ENV" [/config.php]="EXPOSED_ENV"
            [/phpinfo.php]="VERSION_DISCLOSURE" [/server-status]="VERSION_DISCLOSURE"
            [/backup.zip]="SQL_BACKUP_EXPOSED" [/backup.sql]="SQL_BACKUP_EXPOSED"
        )
        for path in "${!PATH_TYPES[@]}"; do
            local code
            code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "${url}${path}" 2>/dev/null || echo "000")
            if [[ "${code}" =~ ^(200|206)$ ]]; then
                add_finding "${PATH_TYPES[$path]}" "${url}${path}" "Accessible HTTP ${code}"
                acquire_lock "vuln"; echo "[EXPOSED] ${url}${path}" >> "${MANUAL_VULN}"; release_lock "vuln"
            fi
        done
        local srv
        srv=$(echo "${headers}" | grep -i "^Server:" || true)
        if echo "${srv}" | grep -qE "[0-9]+\.[0-9]+"; then
            add_finding "VERSION_DISCLOSURE" "${url}" "${srv}"
            acquire_lock "vuln"; echo "[VERSION] ${url} — ${srv}" >> "${MANUAL_VULN}"; release_lock "vuln"
        fi
    }
    export -f manual_vuln_check add_finding safe_append acquire_lock release_lock cvss_for_finding cvss_score
    export MANUAL_VULN FINDINGS LOCK_DIR
    run_parallel "${LIVE_HOSTS}" "${THREADS}" manual_vuln_check
    cat "${MANUAL_VULN}" >> "${VULN_REPORT}"
    success "Manual checks: $(wc -l < "${MANUAL_VULN}") findings"
fi

# ==============================================================================
# STEP 7 — MISCONFIGURATION (parallel)
# ==============================================================================
section "Step 7 — Misconfiguration Detection (parallel)"
MISCONFIG="${VULN_DIR}/misconfigurations.txt"; touch "${MISCONFIG}"

check_misconfig() {
    local url="$1"
    local cors
    cors=$(curl -sk -H "Origin: https://evil.com" -I --max-time 8 "${url}" 2>/dev/null \
           | grep -i "Access-Control-Allow-Origin" | grep -i "evil.com" || true)
    if [[ -n "${cors}" ]]; then
        add_finding "CORS_MISCONFIGURATION" "${url}" "Reflects arbitrary Origin"
        acquire_lock "misconfig"; echo "[CORS] ${url}" >> "${MISCONFIG}"; release_lock "misconfig"
    fi
    local body
    body=$(curl -sk --max-time 8 "${url}" 2>/dev/null | head -50)
    if echo "${body}" | grep -qiE "Index of |Directory listing"; then
        add_finding "DIRECTORY_LISTING" "${url}" "Directory listing enabled"
        acquire_lock "misconfig"; echo "[DIR_LIST] ${url}" >> "${MISCONFIG}"; release_lock "misconfig"
    fi
}
export -f check_misconfig add_finding safe_append acquire_lock release_lock cvss_for_finding cvss_score
export MISCONFIG FINDINGS LOCK_DIR
run_parallel "${LIVE_HOSTS}" "${THREADS}" check_misconfig
success "Misconfiguration findings: $(wc -l < "${MISCONFIG}")"

# ==============================================================================
# STEP 8 — ADMIN PANEL / API (parallel)
# ==============================================================================
section "Step 8 — Admin Panel & API Detection (parallel)"
ADMIN_REPORT="${VULN_DIR}/admin_apis.txt"; touch "${ADMIN_REPORT}"
ADMIN_PATHS=(/admin /administrator /admin.php /wp-admin /wp-login.php /login /dashboard
             /portal /manage /console /api /api/v1 /api/v2 /swagger /swagger-ui.html
             /openapi.json /graphql /graphiql /phpmyadmin /pma /myadmin /dbadmin
             /cpanel /webmail /jenkins /gitlab /kibana /_cat/indices /solr/admin)

probe_admin_paths() {
    local url="$1"
    for path in "${ADMIN_PATHS[@]}"; do
        local code
        code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "${url}${path}" 2>/dev/null || echo "000")
        if [[ "${code}" =~ ^(200|301|302|401|403)$ ]]; then
            local ftype="ADMIN_PANEL_200"
            [[ "${path}" =~ (phpmyadmin|pma|myadmin) ]] && ftype="EXPOSED_PHPMYADMIN"
            [[ "${path}" =~ (graphql|graphiql) ]] && ftype="EXPOSED_GRAPHQL"
            add_finding "${ftype}" "${url}${path}" "HTTP ${code}"
            acquire_lock "admin"; echo "[${ftype}] ${url}${path} — ${code}" >> "${ADMIN_REPORT}"; release_lock "admin"
        fi
    done
}
export -f probe_admin_paths add_finding safe_append acquire_lock release_lock cvss_for_finding cvss_score
export ADMIN_REPORT FINDINGS LOCK_DIR ADMIN_PATHS
run_parallel "${LIVE_HOSTS}" "${THREADS}" probe_admin_paths
success "Admin/API findings: $(wc -l < "${ADMIN_REPORT}")"

# ==============================================================================
# STEP 9 — SUBDOMAIN TAKEOVER (parallel)
# ==============================================================================
section "Step 9 — Subdomain Takeover Detection (parallel)"
TAKEOVER="${VULN_DIR}/takeover_candidates.txt"; touch "${TAKEOVER}"

check_takeover() {
    local sub="$1"
    local body
    body=$(curl -sk --max-time 8 "http://${sub}" 2>/dev/null || true)
    declare -A TS=(
        ["GitHub_Pages"]="There isn't a GitHub Pages site here"
        ["Heroku"]="No such app"
        ["Shopify"]="Sorry, this shop is currently unavailable"
        ["Tumblr"]="Whatever you were looking for doesn't currently exist"
        ["Fastly"]="Fastly error: unknown domain"
        ["Pantheon"]="The gods are wise, but do not know of the site"
        ["Zendesk"]="Help Center Closed"
        ["Unbounce"]="The requested URL was not found on this server"
        ["Amazon_S3"]="NoSuchBucket"
        ["Azure"]="404 Web Site not found"
        ["WP_Engine"]="The site you were looking for couldn't be found"
        ["Ghost"]="The thing you were looking for is no longer here"
        ["ReadTheDocs"]="unknown to Read the Docs"
        ["Surge"]="project not found"
    )
    for svc in "${!TS[@]}"; do
        if echo "${body}" | grep -q "${TS[$svc]}"; then
            add_finding "SUBDOMAIN_TAKEOVER" "${sub}" "Matches ${svc} signature"
            acquire_lock "takeover"; echo "[TAKEOVER] ${svc}: ${sub}" >> "${TAKEOVER}"; release_lock "takeover"
        fi
    done
}
export -f check_takeover add_finding safe_append acquire_lock release_lock cvss_for_finding cvss_score
export TAKEOVER FINDINGS LOCK_DIR
run_parallel "${FINAL_SUBS}" "${THREADS}" check_takeover
success "Takeover candidates: $(wc -l < "${TAKEOVER}")"

# ==============================================================================
# STEP 10 — SCREENSHOTS (parallel)
# ==============================================================================
section "Step 10 — Website Screenshots (parallel)"
SHOT_INDEX="${SHOTS_DIR}/index.txt"; touch "${SHOT_INDEX}"

take_screenshot() {
    local url="$1"
    local safe_name filename
    safe_name=$(echo "${url}" | sed 's~https\?://~~; s~/~_~g; s~[^a-zA-Z0-9._-]~_~g')
    filename="${SHOTS_DIR}/${safe_name}.png"

    if command -v gowitness &>/dev/null; then
        gowitness single --url "${url}" --screenshot-path "${filename}" --timeout 15 2>/dev/null || true
    elif command -v cutycapt &>/dev/null; then
        cutycapt --url="${url}" --out="${filename}" --delay=2000 --max-wait=15000 2>/dev/null || true
    elif command -v chromium-browser &>/dev/null; then
        chromium-browser --headless --disable-gpu --no-sandbox \
            --screenshot="${filename}" --window-size=1280,800 "${url}" 2>/dev/null || true
    elif command -v google-chrome &>/dev/null; then
        google-chrome --headless --disable-gpu --no-sandbox \
            --screenshot="${filename}" --window-size=1280,800 "${url}" 2>/dev/null || true
    fi

    if [[ -f "${filename}" && -s "${filename}" ]]; then
        acquire_lock "shots"; echo "${url}|${filename}" >> "${SHOT_INDEX}"; release_lock "shots"
    fi
}
export -f take_screenshot safe_append acquire_lock release_lock SHOTS_DIR SHOT_INDEX LOCK_DIR
run_parallel "${LIVE_HOSTS}" "$(( THREADS / 3 + 1 ))" take_screenshot

TOTAL_SHOTS=$(wc -l < "${SHOT_INDEX}" 2>/dev/null || echo 0)
success "Screenshots: ${BOLD}${TOTAL_SHOTS}${NC}"
[[ "${TOTAL_SHOTS}" -eq 0 ]] && warn "No screenshot tool found — install gowitness, cutycapt, or chromium."

# ==============================================================================
# COLLECT STATS
# ==============================================================================
count_sev() { grep -c "^$1	" "${FINDINGS}" 2>/dev/null || echo 0; }
COUNT_CRITICAL=$(count_sev "CRITICAL")
COUNT_HIGH=$(count_sev "HIGH")
COUNT_MEDIUM=$(count_sev "MEDIUM")
COUNT_LOW=$(count_sev "LOW")
TOTAL_FINDINGS_COUNT=$(wc -l < "${FINDINGS}" 2>/dev/null || echo 0)
TOTAL_URLS=$(wc -l < "${HISTORICAL_URLS}" 2>/dev/null || echo 0)

# ==============================================================================
# STEP 11 — JSON REPORT
# ==============================================================================
section "Step 11 — JSON Report"

subs_json=$(awk '{printf "\"%s\",", $0}' "${FINAL_SUBS}" | sed 's/,$//' || true)
live_json=$(awk '{printf "\"%s\",", $0}' "${LIVE_HOSTS}" | sed 's/,$//' || true)
ports_json=$(awk -F'\t' '{printf "{\"host\":\"%s\",\"port\":\"%s\",\"service\":\"%s\"},", $1,$2,$3}' \
             "${OPEN_PORTS_FILE}" | sed 's/,$//' || true)
shots_json=$(awk -F'|' '{printf "{\"url\":\"%s\",\"file\":\"%s\"},", $1,$2}' \
             "${SHOT_INDEX}" | sed 's/,$//' || true)
findings_json=""
while IFS=$'\t' read -r sev score ftype ftarget fdetail; do
    fdetail_esc=$(echo "${fdetail}" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\n' ' ')
    findings_json+="{\"severity\":\"${sev}\",\"cvss\":${score},\"type\":\"${ftype}\","
    findings_json+="\"target\":\"${ftarget}\",\"detail\":\"${fdetail_esc}\"},"
done < "${FINDINGS}" 2>/dev/null || true
findings_json="${findings_json%,}"

python3 - > "${REPORT_JSON}" 2>/dev/null <<PYEOF || true
import json, datetime
data = {
  "meta": {"tool":"recon.sh v2.0","target":"${TARGET}",
           "generated":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","threads":${THREADS}},
  "summary": {
    "total_subdomains":${TOTAL_SUBS},"live_hosts":${TOTAL_LIVE},
    "open_ports":${OPEN_PORTS},"historical_urls":${TOTAL_URLS},
    "screenshots":${TOTAL_SHOTS},
    "findings":{"total":${TOTAL_FINDINGS_COUNT},"critical":${COUNT_CRITICAL},
                "high":${COUNT_HIGH},"medium":${COUNT_MEDIUM},"low":${COUNT_LOW}}
  },
  "subdomains":[${subs_json}],
  "live_hosts":[${live_json}],
  "open_ports":[${ports_json}],
  "screenshots":[${shots_json}],
  "findings":[${findings_json}]
}
print(json.dumps(data, indent=2, ensure_ascii=False))
PYEOF
success "JSON report written"

# ==============================================================================
# STEP 12 — HTML REPORT
# ==============================================================================
section "Step 12 — HTML Report"

# Build findings table rows
FINDINGS_ROWS=""
while IFS=$'\t' read -r sev score ftype ftarget fdetail; do
    color="#888"
    case "${sev}" in CRITICAL) color="#c0392b";; HIGH) color="#e67e22";; MEDIUM) color="#e6b800";; LOW) color="#27ae60";; esac
    fdetail_h=$(echo "${fdetail}" | sed 's/</\&lt;/g; s/>/\&gt;/g')
    ftarget_h=$(echo "${ftarget}" | sed 's/</\&lt;/g; s/>/\&gt;/g')
    FINDINGS_ROWS+="<tr data-sev=\"${sev}\"><td><span class=\"badge\" style=\"background:${color}\">${sev}</span></td>"
    FINDINGS_ROWS+="<td><strong>${score}</strong></td><td>${ftype}</td>"
    FINDINGS_ROWS+="<td class=\"mono\">${ftarget_h}</td><td>${fdetail_h}</td></tr>"
done < "${FINDINGS}" 2>/dev/null || true

# Build screenshot cards (inline base64)
SHOT_CARDS=""
while IFS='|' read -r surl sfile; do
    [[ ! -f "${sfile}" ]] && continue
    b64=$(base64 -w0 "${sfile}" 2>/dev/null || true)
    [[ -z "${b64}" ]] && continue
    surl_h=$(echo "${surl}" | sed 's/</\&lt;/g; s/>/\&gt;/g')
    SHOT_CARDS+="<div class=\"shot-card\"><img src=\"data:image/png;base64,${b64}\" loading=\"lazy\" alt=\"${surl_h}\"/>"
    SHOT_CARDS+="<div class=\"shot-url\"><a href=\"${surl_h}\" target=\"_blank\">${surl_h}</a></div></div>"
done < "${SHOT_INDEX}" 2>/dev/null || true

SUBS_LIST=$(awk '{printf "<li>%s</li>", $0}' "${FINAL_SUBS}" 2>/dev/null || true)
LIVE_LIST=$(awk '{printf "<li><a href=\"%s\" target=\"_blank\">%s</a></li>", $0,$0}' "${LIVE_HOSTS}" 2>/dev/null || true)
PORT_ROWS=$(awk -F'\t' '{printf "<tr><td class=\"mono\">%s</td><td>%s</td><td>%s</td><td>%s</td></tr>", $1,$2,$3,$4}' "${OPEN_PORTS_FILE}" 2>/dev/null || true)

pct_crit=$(python3 -c "print(round(${COUNT_CRITICAL}*100/max(${TOTAL_FINDINGS_COUNT},1)))" 2>/dev/null || echo 0)
pct_high=$(python3 -c "print(round(${COUNT_HIGH}*100/max(${TOTAL_FINDINGS_COUNT},1)))"     2>/dev/null || echo 0)
pct_med=$( python3 -c "print(round(${COUNT_MEDIUM}*100/max(${TOTAL_FINDINGS_COUNT},1)))"  2>/dev/null || echo 0)
pct_low=$( python3 -c "print(round(${COUNT_LOW}*100/max(${TOTAL_FINDINGS_COUNT},1)))"     2>/dev/null || echo 0)

cat > "${REPORT_HTML}" <<HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Recon Report — ${TARGET}</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;
      --accent:#58a6ff;--crit:#ff4444;--high:#ff8c00;--med:#ffd700;--low:#3fb950}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.6}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.mono{font-family:'Fira Code',monospace;font-size:.85em}
header{background:linear-gradient(135deg,#1a1f35,#0d1117);padding:2rem;border-bottom:1px solid var(--border)}
header h1{font-size:2rem;color:var(--accent);margin-bottom:.3rem}
header .meta{color:var(--muted);font-size:.9rem}
.container{max-width:1400px;margin:0 auto;padding:1.5rem}
section.block{margin-bottom:2.5rem}
h2{font-size:1.25rem;color:var(--accent);border-bottom:1px solid var(--border);padding-bottom:.4rem;margin-bottom:1rem}
h3{font-size:.95rem;color:var(--muted);margin-bottom:.5rem}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem;margin-bottom:1.5rem}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.2rem;text-align:center}
.stat-card .num{font-size:2.2rem;font-weight:700;line-height:1}
.stat-card .lbl{font-size:.78rem;color:var(--muted);margin-top:.3rem;text-transform:uppercase;letter-spacing:.05em}
.c-blue .num{color:var(--accent)}.c-crit .num{color:var(--crit)}.c-high .num{color:var(--high)}
.c-med .num{color:var(--med)}.c-low .num{color:var(--low)}
.sev-bar{display:flex;height:20px;border-radius:10px;overflow:hidden;margin-bottom:1.5rem;
         background:var(--card);border:1px solid var(--border)}
.sb-c{background:var(--crit)}.sb-h{background:var(--high)}.sb-m{background:var(--med)}.sb-l{background:var(--low)}
.table-wrap{overflow-x:auto;border-radius:8px;border:1px solid var(--border)}
table{width:100%;border-collapse:collapse;font-size:.87rem}
th{background:#1c2230;padding:.65rem 1rem;text-align:left;color:var(--muted);font-weight:600;white-space:nowrap}
td{padding:.55rem 1rem;border-top:1px solid var(--border);vertical-align:top;word-break:break-all}
tr:hover td{background:#1c2230}
.badge{display:inline-block;padding:.15rem .6rem;border-radius:4px;font-size:.72rem;font-weight:700;color:#fff}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem}
@media(max-width:768px){.two-col{grid-template-columns:1fr}}
.list-box{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem;
          max-height:300px;overflow-y:auto}
.list-box ul{list-style:none;font-size:.83rem}
.list-box ul li{padding:.25rem 0;border-bottom:1px solid #1e2530;font-family:monospace}
.list-box ul li:last-child{border:none}
.shots-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:1rem}
.shot-card{background:var(--card);border:1px solid var(--border);border-radius:8px;overflow:hidden}
.shot-card img{width:100%;display:block;max-height:195px;object-fit:cover;cursor:zoom-in}
.shot-url{padding:.45rem .75rem;font-size:.75rem;font-family:monospace;color:var(--muted);
          white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.filter-bar{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:.8rem}
.filter-btn{padding:.3rem .85rem;border-radius:20px;border:1px solid var(--border);
            background:var(--card);color:var(--text);cursor:pointer;font-size:.8rem;transition:.15s}
.filter-btn.active,.filter-btn:hover{background:var(--accent);color:#000;border-color:var(--accent)}
.search-box{width:100%;padding:.5rem .9rem;background:var(--card);border:1px solid var(--border);
            border-radius:8px;color:var(--text);font-size:.9rem;margin-bottom:.8rem}
footer{text-align:center;padding:2rem;color:var(--muted);font-size:.8rem;border-top:1px solid var(--border);margin-top:2rem}
/* lightbox */
#lb{display:none;position:fixed;inset:0;background:rgba(0,0,0,.9);z-index:999;align-items:center;justify-content:center;cursor:zoom-out}
#lb img{max-width:95vw;max-height:95vh;border-radius:8px}
#lb.open{display:flex}
</style>
</head>
<body>
<div id="lb" onclick="this.classList.remove('open')"><img id="lb-img" src="" alt=""/></div>

<header>
  <h1>🔍 Reconnaissance Report</h1>
  <div class="meta">
    <strong>Target:</strong> ${TARGET} &nbsp;·&nbsp;
    <strong>Generated:</strong> $(date) &nbsp;·&nbsp;
    <strong>Threads:</strong> ${THREADS} &nbsp;·&nbsp;
    <strong>Tool:</strong> recon.sh v2.0
  </div>
</header>

<div class="container">

<section class="block">
  <h2>Executive Summary</h2>
  <div class="stats">
    <div class="stat-card c-blue"><div class="num">${TOTAL_SUBS}</div><div class="lbl">Subdomains</div></div>
    <div class="stat-card c-blue"><div class="num">${TOTAL_LIVE}</div><div class="lbl">Live Hosts</div></div>
    <div class="stat-card c-blue"><div class="num">${OPEN_PORTS}</div><div class="lbl">Open Ports</div></div>
    <div class="stat-card c-blue"><div class="num">${TOTAL_SHOTS}</div><div class="lbl">Screenshots</div></div>
    <div class="stat-card c-crit"><div class="num">${COUNT_CRITICAL}</div><div class="lbl">Critical</div></div>
    <div class="stat-card c-high"><div class="num">${COUNT_HIGH}</div><div class="lbl">High</div></div>
    <div class="stat-card c-med"><div class="num">${COUNT_MEDIUM}</div><div class="lbl">Medium</div></div>
    <div class="stat-card c-low"><div class="num">${COUNT_LOW}</div><div class="lbl">Low</div></div>
  </div>
  <h3>Severity Distribution</h3>
  <div class="sev-bar">
    <div class="sb-c" style="width:${pct_crit}%" title="Critical ${COUNT_CRITICAL}"></div>
    <div class="sb-h" style="width:${pct_high}%" title="High ${COUNT_HIGH}"></div>
    <div class="sb-m" style="width:${pct_med}%"  title="Medium ${COUNT_MEDIUM}"></div>
    <div class="sb-l" style="width:${pct_low}%"  title="Low ${COUNT_LOW}"></div>
  </div>
</section>

<section class="block">
  <h2>Findings — CVSS v3.1 Scored</h2>
  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterFindings('ALL',this)">All (${TOTAL_FINDINGS_COUNT})</button>
    <button class="filter-btn" onclick="filterFindings('CRITICAL',this)" style="--accent:var(--crit)">&#x25cf; Critical (${COUNT_CRITICAL})</button>
    <button class="filter-btn" onclick="filterFindings('HIGH',this)"     style="--accent:var(--high)">&#x25cf; High (${COUNT_HIGH})</button>
    <button class="filter-btn" onclick="filterFindings('MEDIUM',this)"   style="--accent:var(--med)">&#x25cf; Medium (${COUNT_MEDIUM})</button>
    <button class="filter-btn" onclick="filterFindings('LOW',this)"      style="--accent:var(--low)">&#x25cf; Low (${COUNT_LOW})</button>
  </div>
  <input class="search-box" type="text" placeholder="Search findings…" oninput="searchFindings(this.value)"/>
  <div class="table-wrap">
  <table id="ftbl">
    <thead><tr><th>Severity</th><th>CVSS Score</th><th>Finding Type</th><th>Target</th><th>Detail</th></tr></thead>
    <tbody id="fbody">
      ${FINDINGS_ROWS:-<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:2rem">No findings</td></tr>}
    </tbody>
  </table>
  </div>
</section>

<section class="block">
  <h2>Discovery Results</h2>
  <div class="two-col">
    <div><h3>Subdomains (${TOTAL_SUBS})</h3>
      <div class="list-box"><ul>${SUBS_LIST:-<li style="color:var(--muted)">None</li>}</ul></div></div>
    <div><h3>Live Hosts (${TOTAL_LIVE})</h3>
      <div class="list-box"><ul>${LIVE_LIST:-<li style="color:var(--muted)">None</li>}</ul></div></div>
  </div>
</section>

<section class="block">
  <h2>Open Ports (${OPEN_PORTS})</h2>
  <div class="table-wrap"><table>
    <thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Version / Banner</th></tr></thead>
    <tbody>${PORT_ROWS:-<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:2rem">No open ports found</td></tr>}</tbody>
  </table></div>
</section>

<section class="block">
  <h2>Screenshots (${TOTAL_SHOTS})</h2>
  $(if [[ -n "${SHOT_CARDS}" ]]; then echo "<div class=\"shots-grid\">${SHOT_CARDS}</div>"
    else echo "<p style=\"color:var(--muted)\">No screenshots. Install <code>gowitness</code>, <code>cutycapt</code>, or <code>chromium</code>.</p>"; fi)
</section>

<section class="block">
  <h2>Output Files</h2>
  <div class="table-wrap"><table>
    <thead><tr><th>File</th><th>Description</th></tr></thead>
    <tbody>
      <tr><td class="mono">${FINAL_SUBS}</td><td>Deduplicated subdomain list</td></tr>
      <tr><td class="mono">${LIVE_HOSTS}</td><td>Confirmed live HTTP/HTTPS hosts</td></tr>
      <tr><td class="mono">${PORT_REPORT}</td><td>Full port scan results</td></tr>
      <tr><td class="mono">${TECH_REPORT}</td><td>Technology fingerprinting output</td></tr>
      <tr><td class="mono">${HISTORICAL_URLS}</td><td>Historical/archived URLs</td></tr>
      <tr><td class="mono">${JUICY}</td><td>Juicy endpoints (backups, configs…)</td></tr>
      <tr><td class="mono">${VULN_REPORT}</td><td>Vulnerability scan raw output</td></tr>
      <tr><td class="mono">${MISCONFIG}</td><td>Misconfiguration findings</td></tr>
      <tr><td class="mono">${ADMIN_REPORT}</td><td>Admin panels &amp; API endpoints</td></tr>
      <tr><td class="mono">${TAKEOVER}</td><td>Subdomain takeover candidates</td></tr>
      <tr><td class="mono">${REPORT_JSON}</td><td>Machine-readable JSON report</td></tr>
      <tr><td class="mono">${SHOTS_DIR}/</td><td>Website screenshots directory</td></tr>
    </tbody>
  </table></div>
</section>

</div>
<footer>recon.sh v2.0 &nbsp;·&nbsp; Target: ${TARGET} &nbsp;·&nbsp; $(date) &nbsp;·&nbsp; For authorised security testing only.</footer>

<script>
// Sort findings by CVSS desc on load
(function(){
  const tb=document.getElementById('fbody');
  if(!tb)return;
  [...tb.querySelectorAll('tr')].sort((a,b)=>
    parseFloat(b.cells[1]?.textContent||0)-parseFloat(a.cells[1]?.textContent||0)
  ).forEach(r=>tb.appendChild(r));
})();

let activeSev='ALL';
function filterFindings(sev,btn){
  activeSev=sev;
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  if(btn)btn.classList.add('active');
  applyFilters();
}
function searchFindings(q){applyFilters(q);}
function applyFilters(q){
  const query=(q||'').toLowerCase();
  document.querySelectorAll('#fbody tr').forEach(row=>{
    const sevMatch=activeSev==='ALL'||row.dataset.sev===activeSev;
    const textMatch=!query||row.textContent.toLowerCase().includes(query);
    row.style.display=(sevMatch&&textMatch)?'':'none';
  });
}
// Lightbox for screenshots
document.querySelectorAll('.shot-card img').forEach(img=>{
  img.addEventListener('click',e=>{
    document.getElementById('lb-img').src=e.target.src;
    document.getElementById('lb').classList.add('open');
  });
});
</script>
</body></html>
HTMLEOF
success "HTML report written"

# ==============================================================================
# PLAIN TEXT REPORT
# ==============================================================================
{
printf '%s\n' "$(printf '=%.0s' {1..65})"
printf '%s\n' "       AUTOMATED RECONNAISSANCE REPORT v2.0"
printf '%s\n' "       Generated: $(date)"
printf '%s\n' "$(printf '=%.0s' {1..65})"
printf '\n  Target: %s\n  Threads: %s\n\n' "${TARGET}" "${THREADS}"
printf '%s\n' "$(printf '─%.0s' {1..65})"
printf '  DISCOVERY\n'; printf '%s\n' "$(printf '─%.0s' {1..65})"
printf '  %-36s %s\n' "Subdomains:" "${TOTAL_SUBS}" "Live hosts:" "${TOTAL_LIVE}" \
    "Open ports:" "${OPEN_PORTS}" "Historical URLs:" "${TOTAL_URLS}" "Screenshots:" "${TOTAL_SHOTS}"
printf '\n%s\n' "$(printf '─%.0s' {1..65})"
printf '  VULNERABILITY SUMMARY (CVSS v3.1)\n'; printf '%s\n' "$(printf '─%.0s' {1..65})"
printf '  %-36s %s\n' "Total findings:" "${TOTAL_FINDINGS_COUNT}" \
    "  CRITICAL (9.0-10.0):" "${COUNT_CRITICAL}" "  HIGH (7.0-8.9):" "${COUNT_HIGH}" \
    "  MEDIUM (4.0-6.9):" "${COUNT_MEDIUM}" "  LOW (0.1-3.9):" "${COUNT_LOW}"
printf '\n%s\n' "$(printf '─%.0s' {1..65})"
printf '  ALL FINDINGS (sorted by CVSS)\n'; printf '%s\n' "$(printf '─%.0s' {1..65})"
sort -t$'\t' -k2 -rn "${FINDINGS}" 2>/dev/null | \
    awk -F'\t' '{printf "  [%-8s] CVSS %-4s  %-28s  %s\n  => %s\n\n",$1,$2,$3,$4,$5}' || printf '  None\n'
printf '\n%s\n' "$(printf '─%.0s' {1..65})"
printf '  REPORTS\n'; printf '%s\n' "$(printf '─%.0s' {1..65})"
printf '  Text : %s\n  JSON : %s\n  HTML : %s\n  Shots: %s/\n' \
    "${REPORT_TXT}" "${REPORT_JSON}" "${REPORT_HTML}" "${SHOTS_DIR}"
printf '\n%s\n' "$(printf '=%.0s' {1..65})"
printf '  Completed: %s\n' "$(date)"
printf '%s\n' "$(printf '=%.0s' {1..65})"
} > "${REPORT_TXT}"

# ==============================================================================
# TERMINAL SUMMARY
# ==============================================================================
echo ""
echo -e "${BOLD}${GREEN}$(printf '=%.0s' {1..60})${NC}"
echo -e "${BOLD}${GREEN}  RECONNAISSANCE COMPLETE${NC}"
echo -e "${BOLD}${GREEN}$(printf '=%.0s' {1..60})${NC}"
echo ""
printf "${CYAN}  %-36s${NC} ${BOLD}%s${NC}\n" "Target:"                  "${TARGET}"
printf "${CYAN}  %-36s${NC} ${BOLD}%s${NC}\n" "Subdomains discovered:"   "${TOTAL_SUBS}"
printf "${CYAN}  %-36s${NC} ${BOLD}%s${NC}\n" "Live hosts:"              "${TOTAL_LIVE}"
printf "${CYAN}  %-36s${NC} ${BOLD}%s${NC}\n" "Open ports:"              "${OPEN_PORTS}"
printf "${CYAN}  %-36s${NC} ${BOLD}%s${NC}\n" "Screenshots captured:"    "${TOTAL_SHOTS}"
echo ""
printf "${RED}    %-34s${NC} ${BOLD}%s${NC}\n"    "CRITICAL (CVSS 9.0–10.0):" "${COUNT_CRITICAL}"
printf "${YELLOW}    %-34s${NC} ${BOLD}%s${NC}\n" "HIGH     (CVSS 7.0–8.9):"  "${COUNT_HIGH}"
printf "${BLUE}    %-34s${NC} ${BOLD}%s${NC}\n"   "MEDIUM   (CVSS 4.0–6.9):"  "${COUNT_MEDIUM}"
printf "${GREEN}    %-34s${NC} ${BOLD}%s${NC}\n"  "LOW      (CVSS 0.1–3.9):"  "${COUNT_LOW}"
echo ""
echo -e "${BOLD}  Reports:${NC}"
echo -e "  📄 Text : ${CYAN}${REPORT_TXT}${NC}"
echo -e "  📊 JSON : ${CYAN}${REPORT_JSON}${NC}"
echo -e "  🌐 HTML : ${CYAN}${REPORT_HTML}${NC}"
echo -e "  📸 Shots: ${CYAN}${SHOTS_DIR}/${NC}"
echo ""
echo -e "${BOLD}${GREEN}$(printf '=%.0s' {1..60})${NC}"

if [[ ${#TOOLS_MISSING[@]} -gt 0 ]]; then
    echo ""
    warn "Install these tools for better coverage:"
    for t in "${TOOLS_MISSING[@]}"; do
        case "${t}" in
            gowitness)        echo "    go install github.com/sensepost/gowitness@latest" ;;
            chromium-browser) echo "    sudo apt install chromium-browser" ;;
            nmap)             echo "    sudo apt install nmap" ;;
            subfinder)        echo "    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" ;;
            httpx)            echo "    go install github.com/projectdiscovery/httpx/cmd/httpx@latest" ;;
            nuclei)           echo "    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" ;;
            assetfinder)      echo "    go install github.com/tomnomnom/assetfinder@latest" ;;
            gau)              echo "    go install github.com/lc/gau/v2/cmd/gau@latest" ;;
        esac
    done
fi
echo ""
info "Elapsed: $(( SECONDS / 60 ))m $(( SECONDS % 60 ))s"
