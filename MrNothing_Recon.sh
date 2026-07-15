#!/usr/bin/env bash
#
# MrNothing_Recon.sh — Bug bounty subdomain recon pipeline
#         by Mr.Nothing
#
#   1. Subdomain enumeration              (subfinder)
#   2. Dedup (in place) + alive-check     (sort, httpx)
#   3. Resolve alive hosts to IPs         (dnsx -- IPv4/IPv6, for scanning)
#   4. Screenshots                        (gowitness)
#   5. Fast port scan                     (naabu if installed, else nmap)
#   6. Service/version detection          (nmap -sV, scoped to the ports
#                                           found open in step 5)
#
# Usage:
#   ./MrNothing_Recon.sh <domain>
#   ./MrNothing_Recon.sh example.com
#
# Only run this against targets you're authorized to test — your own
# infrastructure, or assets explicitly in-scope for a bug bounty / VDP /
# pentest engagement you're part of.
#
set -uo pipefail

# ------------------------- Config (tweak as needed) -------------------------
TOP_PORTS=5000        # port depth for naabu/nmap. Use 65535 or "-p-" for full range (much slower)
HTTPX_THREADS=50
NAABU_RATE=1000          # packets/sec for naabu
NMAP_MIN_RATE=1000       # --min-rate for nmap (speeds up the scan significantly)

# ------------------------------- UI helpers ----------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${BLUE}[*]${NC} $1"; }
good() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
fail() { echo -e "${RED}[!]${NC} $1"; }
have() { command -v "$1" >/dev/null 2>&1; }

# ------------------------------ Timing helpers --------------------------------

fmt_duration() {
    local total=$1 h m s
    h=$(( total / 3600 ))
    m=$(( (total % 3600) / 60 ))
    s=$(( total % 60 ))
    if   [ "$h" -gt 0 ]; then printf "%dh %02dm %02ds" "$h" "$m" "$s"
    elif [ "$m" -gt 0 ]; then printf "%dm %02ds" "$m" "$s"
    else                      printf "%ds" "$s"
    fi
}

SCRIPT_START=$(date +%s)
STEP_START=$SCRIPT_START

# Call at the top of a step to reset its start marker
step_begin() { STEP_START=$(date +%s); }

# Call at the end of a step to print that step's elapsed time + running total
step_end() {
    local label="$1" now elapsed total_elapsed
    now=$(date +%s)
    elapsed=$(( now - STEP_START ))
    total_elapsed=$(( now - SCRIPT_START ))
    info "${label} took $(fmt_duration "$elapsed")  (elapsed so far: $(fmt_duration "$total_elapsed"))"
}

banner() {
    echo -e "${YELLOW}"
    cat << "EOF"
 __  __             _   _       _   _     _             
|  \/  |           | \ | |     | | | |   (_)            
| \  / |_ __ ______|  \| | ___ | |_| |__  _ _ __   __ _ 
| |\/| | '__|______| . ` |/ _ \| __| '_ \| | '_ \ / _` |
| |  | | |         | |\  | (_) | |_| | | | | | | | (_| |
|_|  |_|_|         |_| \_|\___/ \__|_| |_|_|_| |_|\__, |  
                                                    _/ |
                                                   |___/ 
EOF
    echo -e "${GREEN}                 R E C O N   T O O L${NC}"
    
    echo
}
banner

# ------------------------------- Input check ----------------------------------
if [ $# -lt 1 ]; then
    fail "Usage: $0 <domain>"
    fail "Example: $0 example.com"
    exit 1
fi

# Strip a scheme/path if the user pasted a URL instead of a bare domain
DOMAIN="${1#http://}"
DOMAIN="${DOMAIN#https://}"
DOMAIN="${DOMAIN%%/*}"

# ------------------------------ Tool checks -----------------------------------
MISSING=0
for t in subfinder nmap; do
    have "$t" || { fail "$t is required but not installed."; MISSING=1; }
done
[ "$MISSING" -eq 1 ] && exit 1

HAVE_HTTPX=0; have httpx && HAVE_HTTPX=1
HAVE_NAABU=0; have naabu && HAVE_NAABU=1
HAVE_DNSX=0; have dnsx && HAVE_DNSX=1
HAVE_GOWITNESS=0; have gowitness && HAVE_GOWITNESS=1

[ "$HAVE_HTTPX" -eq 0 ] && warn "httpx not found -- alive-check will use a basic curl fallback. Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
[ "$HAVE_NAABU" -eq 0 ] && warn "naabu not found -- falling back to nmap for port discovery (slower). Install: go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
[ "$HAVE_DNSX" -eq 0 ] && warn "dnsx not found -- IP resolution will use a getent/dig fallback. Install: go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
[ "$HAVE_GOWITNESS" -eq 0 ] && warn "gowitness not found -- screenshots will be skipped. Install: go install github.com/sensepost/gowitness@latest"

# ------------------------------ Output setup ----------------------------------
TS=$(date +%Y%m%d_%H%M%S)
OUTDIR="recon_${DOMAIN}_${TS}"
SCREENSHOT_DIR="${OUTDIR}/screenshots"
mkdir -p "$OUTDIR" "$SCREENSHOT_DIR" || { fail "Could not create output directory"; exit 1; }

RAW_SUBS="${OUTDIR}/subs_raw.txt"
ALIVE_SUBS="${OUTDIR}/alive_subs.txt"
CLEAN_HOSTS="${OUTDIR}/clean_hosts.txt"
RESOLVED_IPS="${OUTDIR}/resolved_ips.txt"
PORT_SCAN_FILE="Port_scan_alive_subs"
SERVICE_SCAN_FILE="Service_Scan_alive_subs"
OPEN_PORTS_MAP="${OUTDIR}/.open_ports_map.txt"

echo "=============================================================="
echo " Mr.Nothing Recon Tool  --  target: ${DOMAIN}"
echo " Output dir: ${OUTDIR}/"
echo "=============================================================="

# ==============================================================================
# STEP 1 -- Subdomain enumeration (subfinder)
# ==============================================================================
step_begin
info "[1/6] Enumerating subdomains with subfinder..."
subfinder -d "$DOMAIN" -all -silent -o "$RAW_SUBS"

RAW_COUNT=$(wc -l < "$RAW_SUBS" 2>/dev/null | tr -d ' ')
good "subfinder found ${RAW_COUNT:-0} subdomains -> ${RAW_SUBS}"
step_end "[1/6] Subdomain enumeration"

if [ "${RAW_COUNT:-0}" -eq 0 ]; then
    fail "No subdomains found for ${DOMAIN}. Exiting."
    exit 1
fi

# ==============================================================================
# STEP 2 -- Dedup (in place), alive-check
# ==============================================================================
step_begin
info "[2/6] Removing duplicate subdomains..."
sort -u "$RAW_SUBS" -o "$RAW_SUBS"
DEDUP_COUNT=$(wc -l < "$RAW_SUBS" | tr -d ' ')
good "${DEDUP_COUNT} unique subdomains (deduped in place) -> ${RAW_SUBS}"

if [ "$HAVE_HTTPX" -eq 1 ]; then
    info "Probing for alive subdomains with httpx..."
    httpx -l "$RAW_SUBS" -silent -threads "$HTTPX_THREADS" -o "$ALIVE_SUBS"
else
    warn "httpx missing -- using a basic curl fallback (slower, less accurate)"
    : > "$ALIVE_SUBS"
    while IFS= read -r sub; do
        for scheme in https http; do
            code=$(curl -ks -o /dev/null --max-time 5 -w "%{http_code}" "${scheme}://${sub}")
            if [[ "$code" =~ ^[23][0-9]{2}$ ]]; then
                echo "${scheme}://${sub}" >> "$ALIVE_SUBS"
                break
            fi
        done
    done < "$RAW_SUBS"
fi

ALIVE_COUNT=$(wc -l < "$ALIVE_SUBS" 2>/dev/null | tr -d ' ')
good "${ALIVE_COUNT:-0} alive subdomains -> ${ALIVE_SUBS}"
step_end "[2/6] Dedup + alive-check"

if [ "${ALIVE_COUNT:-0}" -eq 0 ]; then
    fail "No alive subdomains found. Skipping screenshots and scans."
    exit 0
fi

# Bare hostnames (scheme/path/port stripped) -- used as input to resolution
sed -E 's~^https?://~~; s~/.*$~~; s~:[0-9]+$~~' "$ALIVE_SUBS" | sort -u > "$CLEAN_HOSTS"

# ==============================================================================
# STEP 3 -- Resolve alive hosts to IPv4/IPv6 addresses for scanning
# ==============================================================================
step_begin
info "[3/6] Resolving alive subdomains to IP addresses..."
: > "$RESOLVED_IPS"

if [ "$HAVE_DNSX" -eq 1 ]; then
    # -resp-only prints just the resolved IPs; -a/-aaaa cover both address
    # families so naabu/nmap get IPv4 and IPv6 targets, not hostnames.
    dnsx -l "$CLEAN_HOSTS" -a -aaaa -resp-only -silent -o "$RESOLVED_IPS"
else
    warn "dnsx missing -- using a getent/dig fallback for IP resolution"
    while IFS= read -r host; do
        # IPv4
        getent ahostsv4 "$host" 2>/dev/null | awk '{print $1}' | sort -u
        # IPv6
        getent ahostsv6 "$host" 2>/dev/null | awk '{print $1}' | sort -u
    done < "$CLEAN_HOSTS" | sort -u > "$RESOLVED_IPS"
fi

sort -u "$RESOLVED_IPS" -o "$RESOLVED_IPS"
RESOLVED_COUNT=$(wc -l < "$RESOLVED_IPS" 2>/dev/null | tr -d ' ')
good "${RESOLVED_COUNT:-0} unique IPs (IPv4/IPv6) resolved -> ${RESOLVED_IPS}"

if [ "${RESOLVED_COUNT:-0}" -eq 0 ]; then
    warn "No IPs resolved -- falling back to bare hostnames for scanning."
    cp "$CLEAN_HOSTS" "$RESOLVED_IPS"
fi

# From here on, scans target resolved IPs instead of hostnames
SCAN_TARGETS="$RESOLVED_IPS"
step_end "[3/6] IP resolution"

# ==============================================================================
# STEP 4 -- Screenshots (gowitness)
# ==============================================================================
step_begin
info "[4/6] Taking screenshots of alive subdomains with gowitness..."
if [ "$HAVE_GOWITNESS" -eq 1 ]; then
    # Flag syntax varies across gowitness versions -- try the newer subcommand
    # form first, then fall back to the older flat form.
    gowitness scan file -f "$ALIVE_SUBS" --screenshot-path "$SCREENSHOT_DIR" 2>/dev/null \
        || gowitness file -f "$ALIVE_SUBS" -P "$SCREENSHOT_DIR" 2>/dev/null \
        || warn "gowitness invocation failed -- check 'gowitness --help' for your installed version's syntax"
    good "Screenshots saved -> ${SCREENSHOT_DIR}/"
else
    warn "gowitness not installed -- skipping screenshots."
fi
step_end "[4/6] Screenshots"

# ==============================================================================
# STEP 5 -- Fast port scan
# ==============================================================================
step_begin
info "[5/6] Port scanning ${RESOLVED_COUNT:-0} resolved IPs (top ${TOP_PORTS} ports)..."
: > "$OPEN_PORTS_MAP"

if [ "$HAVE_NAABU" -eq 1 ]; then
    info "Using naabu for fast port discovery (-exclude-cdn skips full scans on CDN/WAF-fronted hosts)..."
    # naabu's -top-ports flag only accepts preset tiers (100/1000/full), not
    # arbitrary numbers -- use an explicit port range so any TOP_PORTS value works.
    naabu -l "$SCAN_TARGETS" -p "1-${TOP_PORTS}" -exclude-cdn -rate "$NAABU_RATE" \
          -silent -o "${OUTDIR}/${PORT_SCAN_FILE}"

    # naabu's raw output is "host:port" per line -- group by host for step 6
    if [ -f "${OUTDIR}/${PORT_SCAN_FILE}" ]; then
        awk -F: '{
            if ($1 in ports) { ports[$1] = ports[$1] "," $2 }
            else             { ports[$1] = $2 }
        }
        END { for (h in ports) print h ":" ports[h] }' "${OUTDIR}/${PORT_SCAN_FILE}" > "$OPEN_PORTS_MAP"
    else
        fail "naabu did not produce an output file -- port scan may have failed. Check the [FTL]/error output above."
    fi
else
    info "Using nmap for port discovery (-T4, --min-rate ${NMAP_MIN_RATE}, top ${TOP_PORTS})..."
    # -Pn: treat all hosts as up (we already confirmed they're alive over HTTP;
    # many hosts drop ICMP, which would otherwise cause nmap to skip them)
    nmap -iL "$SCAN_TARGETS" -Pn -T4 --top-ports "$TOP_PORTS" --min-rate "$NMAP_MIN_RATE" \
         -oN "${OUTDIR}/${PORT_SCAN_FILE}" -oG "${OUTDIR}/.nmap_grep_tmp" > /dev/null

    # Parse nmap's greppable output into the same format
    awk -F'\t' '
    /Ports:/ {
        split($1, hp, " "); ip = hp[2]
        pf = ""
        for (i=1; i<=NF; i++) if ($i ~ /^Ports:/) pf = $i
        sub(/^Ports: /, "", pf)
        n = split(pf, parr, ", ")
        op = ""
        for (i=1; i<=n; i++) {
            split(parr[i], pinfo, "/")
            if (pinfo[2] == "open") op = (op == "" ? pinfo[1] : op "," pinfo[1])
        }
        if (op != "") print ip ":" op
    }' "${OUTDIR}/.nmap_grep_tmp" > "$OPEN_PORTS_MAP"

    rm -f "${OUTDIR}/.nmap_grep_tmp"
fi

OPEN_HOST_COUNT=$(wc -l < "$OPEN_PORTS_MAP" | tr -d ' ')
good "Port scan complete -> ${OUTDIR}/${PORT_SCAN_FILE}  (${OPEN_HOST_COUNT} hosts with open ports)"
step_end "[5/6] Port scan"

# ==============================================================================
# STEP 6 -- Service / version detection
# ==============================================================================
step_begin
info "[6/6] Running service/version detection on discovered open ports..."

SERVICE_OUT="${OUTDIR}/${SERVICE_SCAN_FILE}"
: > "$SERVICE_OUT"

if [ ! -s "$OPEN_PORTS_MAP" ]; then
    warn "No open ports discovered in step 5 -- nothing to version-scan."
else
    TOTAL_SCAN_HOSTS=$(wc -l < "$OPEN_PORTS_MAP" | tr -d ' ')
    HOST_IDX=0
    while IFS=: read -r host ports; do
        [ -z "$ports" ] && continue
        HOST_IDX=$(( HOST_IDX + 1 ))
        HOST_START=$(date +%s)
        echo "    -> (${HOST_IDX}/${TOTAL_SCAN_HOSTS}) ${host}  (ports: ${ports})"
        {
            echo "==== ${host} ===="
            nmap -sV -Pn -p "$ports" "$host"
            echo
        } >> "$SERVICE_OUT"
        HOST_ELAPSED=$(( $(date +%s) - HOST_START ))
        echo "       done in $(fmt_duration "$HOST_ELAPSED")"
    done < "$OPEN_PORTS_MAP"
    good "Service scan complete -> ${SERVICE_OUT}"
fi
step_end "[6/6] Service/version detection"

# ==============================================================================
# Summary
# ==============================================================================
echo "=============================================================="
good "Recon complete for ${DOMAIN}"
TOTAL_RUNTIME=$(( $(date +%s) - SCRIPT_START ))
echo "    Total runtime:        $(fmt_duration "$TOTAL_RUNTIME")"
echo "    Raw subdomains:       ${RAW_COUNT}"
echo "    Unique subdomains:    ${DEDUP_COUNT}"
echo "    Alive subdomains:     ${ALIVE_COUNT}"
echo "    Resolved IPs:         ${RESOLVED_COUNT:-0}"
echo "    Hosts w/ open ports:  ${OPEN_HOST_COUNT}"
echo
echo "    Output directory:     ${OUTDIR}/"
echo "      |-- subs_raw.txt          (all subfinder results, deduped in place)"
echo "      |-- alive_subs.txt        (alive subdomains)"
echo "      |-- clean_hosts.txt       (bare hostnames)"
echo "      |-- resolved_ips.txt      (IPv4/IPv6 addresses used for scanning)"
echo "      |-- screenshots/          (gowitness screenshots of alive subs)"
echo "      |-- ${PORT_SCAN_FILE}"
echo "      \`-- ${SERVICE_SCAN_FILE}"
echo "=============================================================="
