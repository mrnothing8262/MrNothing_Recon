#!/usr/bin/env bash
#
# MrNothing_Recon.sh (v2.2-dig-gobuster) — Bug bounty subdomain recon pipeline
#         by Mr.Nothing
#
#   1a. Subdomain enumeration    (subfinder only, no brute‑force)
#   1b. (Optional) Active brute‑force subdomain discovery (gobuster + wordlist)
#   2. Dedup (in place) + alive-check     (sort, httpx)
#   3. Wildcard‑DNS check, then resolve ALL discovered subdomains to
#      IPv4/IPv6 (dig +short with parallel workers). Hosts that resolve
#      only to the wildcard's answer are excluded from scanning.
#   4. Screenshots                        (gowitness)  [background]
#   5. Fast port scan                     (naabu if installed, else nmap)
#   6. Service/version detection          (nmap -sV, scoped to open ports)
#
# Usage:
#   ./MrNothing_Recon.sh <domain>
#   ./MrNothing_Recon.sh -w subdomains.txt example.com
#
# Options:
#   -w <wordlist>    Active subdomain brute‑force wordlist (requires gobuster)
#
# Only run this against targets you're authorized to test.

set -uo pipefail

# ------------------------- Config (tweak as needed) -------------------------
TOP_PORTS=1000              # port depth for naabu/nmap
HTTPX_THREADS=50
NAABU_RATE=1000             # packets/sec for naabu
NMAP_MIN_RATE=1000          # --min-rate for nmap
SERVICE_SCAN_CONCURRENCY=5  # parallel nmap -sV jobs
NMAP_HOST_TIMEOUT="120s"    # per-host cap for nmap -sV

SUBFINDER_TIMEOUT="10m"
HTTPX_TIMEOUT="15m"

DNS_RESOLVE_THREADS=20      # parallel dig workers (adjust based on system load)

NMAP_SERVICES_FILE=""       # leave blank to auto-detect; set to override
WILDCARD_PROBE_COUNT=3      # random non-existent labels to test for wildcard DNS

GOBUSTER_THREADS=50         # gobuster concurrency

# ------------------------------- UI helpers ----------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${BLUE}[*]${NC} $1"; }
good()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
fail()  { echo -e "${RED}[!]${NC} $1"; }
have()  { command -v "$1" >/dev/null 2>&1; }

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

step_begin() { STEP_START=$(date +%s); }
step_end() {
    local label="$1" now elapsed total_elapsed
    now=$(date +%s)
    elapsed=$(( now - STEP_START ))
    total_elapsed=$(( now - SCRIPT_START ))
    info "${label} took $(fmt_duration "$elapsed")  (elapsed so far: $(fmt_duration "$total_elapsed"))"
}

run_with_timeout() {
    local duration="$1"; shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "$duration" "$@"
    else
        "$@"
    fi
}

gen_top_ports() {
    local n="$1"
    [ -r "$NMAP_SERVICES_FILE" ] || return 1
    awk '$1 !~ /^#/ && $2 ~ /\/tcp$/ { split($2, a, "/"); print $3, a[1] }' "$NMAP_SERVICES_FILE" \
        | sort -rn -k1,1 \
        | head -n "$n" \
        | awk '{print $2}' \
        | paste -sd, -
}

find_nmap_services() {
    local candidates=(
        "/usr/share/nmap/nmap-services"
        "/opt/homebrew/share/nmap/nmap-services"
        "/usr/local/share/nmap/nmap-services"
        "/opt/local/share/nmap/nmap-services"
    )
    for c in "${candidates[@]}"; do
        [ -r "$c" ] && { echo "$c"; return 0; }
    done
    return 1
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
    echo -e "${GREEN}                 R E C O N   T O O L   ( v 2 . 2 - d i g - g o b u s t e r )${NC}"
    echo
}
banner

# ------------------------------- Input parsing --------------------------------
DOMAIN=""
BRUTE_WORDLIST=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -w) BRUTE_WORDLIST="$2"; shift 2 ;;
        -*) fail "Unknown option: $1"; exit 1 ;;
        *)  DOMAIN="$1"; shift ;;
    esac
done

if [ -z "$DOMAIN" ]; then
    fail "Usage: $0 [-w <subdom-wordlist>] <domain>"
    fail "Example: $0 -w subdomains.txt example.com"
    exit 1
fi

DOMAIN="${DOMAIN#http://}"
DOMAIN="${DOMAIN#https://}"
DOMAIN="${DOMAIN%%/*}"

case "$DOMAIN" in
    -*|"") fail "Invalid domain: '${DOMAIN}'"; exit 1 ;;
esac

# ------------------------------ Tool checks -----------------------------------
MISSING=0
for t in subfinder nmap dig; do
    have "$t" || { fail "$t is required but not installed."; MISSING=1; }
done
[ "$MISSING" -eq 1 ] && exit 1

HAVE_HTTPX=0; have httpx && HAVE_HTTPX=1
HAVE_NAABU=0; have naabu && HAVE_NAABU=1
HAVE_GOWITNESS=0; have gowitness && HAVE_GOWITNESS=1
HAVE_GOBUSTER=0; have gobuster && HAVE_GOBUSTER=1

[ "$HAVE_HTTPX" -eq 0 ] && warn "httpx not found -- alive-check will use a parallel curl fallback. Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
[ "$HAVE_NAABU" -eq 0 ] && warn "naabu not found -- falling back to nmap for port discovery. Install: go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
[ "$HAVE_GOWITNESS" -eq 0 ] && warn "gowitness not found -- screenshots will be skipped. Install: go install github.com/sensepost/gowitness@latest"

if ! command -v timeout >/dev/null 2>&1; then
    warn "timeout not found -- step time limits will be ignored (install coreutils)."
fi

# Active brute‑force checks
if [ -n "$BRUTE_WORDLIST" ]; then
    if [ "$HAVE_GOBUSTER" -eq 0 ]; then
        fail "Active subdomain brute‑force requested (-w) but gobuster is not installed. Install: go install github.com/OJ/gobuster/v3@latest"
        exit 1
    fi
    if [ ! -r "$BRUTE_WORDLIST" ]; then
        fail "Brute‑force wordlist not found: $BRUTE_WORDLIST"
        exit 1
    fi
fi

if [ -z "$NMAP_SERVICES_FILE" ] || [ ! -r "$NMAP_SERVICES_FILE" ]; then
    NMAP_SERVICES_FILE="$(find_nmap_services)" || NMAP_SERVICES_FILE=""
    [ -z "$NMAP_SERVICES_FILE" ] && warn "Could not locate nmap-services -- naabu will use built-in top-1000 tier."
fi

# ------------------------------ Output setup ----------------------------------
TS=$(date +%Y%m%d_%H%M%S)
OUTDIR="recon_${DOMAIN}_${TS}"
SCREENSHOT_DIR="${OUTDIR}/screenshots"
mkdir -p "$OUTDIR" "$SCREENSHOT_DIR" || { fail "Could not create output directory"; exit 1; }

RAW_SUBS="${OUTDIR}/subs_raw.txt"
ALIVE_SUBS="${OUTDIR}/alive_subs.txt"
CLEAN_HOSTS="${OUTDIR}/clean_hosts.txt"
RESOLVED_IPS="${OUTDIR}/resolved_ips.txt"
HOST_IP_MAP="${OUTDIR}/host_ip_map.txt"
WILDCARD_FILTERED_HOSTS="${OUTDIR}/wildcard_filtered_hosts.txt"
PORT_SCAN_FILE="port_scan_all_hosts.txt"
SERVICE_SCAN_FILE="service_scan_all_hosts.txt"
OPEN_PORTS_MAP="${OUTDIR}/.open_ports_map.txt"
WILDCARD_IPS="${OUTDIR}/.wildcard_ips.txt"
HOST_IP_PAIRS="${OUTDIR}/.host_ip_pairs.tsv"
IPV4_TARGETS="${OUTDIR}/.targets_v4.txt"
IPV6_TARGETS="${OUTDIR}/.targets_v6.txt"

echo "=============================================================="
echo " Mr.Nothing Recon Tool  --  target: ${DOMAIN}"
echo " Output dir: ${OUTDIR}/"
[ -n "$BRUTE_WORDLIST" ] && echo " Subdomain brute-force wordlist: ${BRUTE_WORDLIST}"
echo "=============================================================="

cleanup() {
    rm -rf "${OUTDIR}"/.svc_* "${OUTDIR}"/.top_ports.txt "${OUTDIR}"/.dns_* "${OUTDIR}"/.alive_* 2>/dev/null
}
trap cleanup EXIT

# ==============================================================================
# STEP 1a -- Passive subdomain enumeration (subfinder)
# ==============================================================================
step_begin
info "[1a/6] Enumerating subdomains with subfinder..."
run_with_timeout "$SUBFINDER_TIMEOUT" subfinder -d "$DOMAIN" -all -silent -o "$RAW_SUBS"
sf_status=$?
if [ "$sf_status" -eq 124 ]; then
    warn "subfinder timed out after ${SUBFINDER_TIMEOUT} -- results may be incomplete."
elif [ "$sf_status" -ne 0 ]; then
    warn "subfinder exited with status ${sf_status} -- results may be incomplete."
fi

RAW_COUNT=$(wc -l < "$RAW_SUBS" 2>/dev/null | tr -d ' ')
good "subfinder found ${RAW_COUNT:-0} subdomains (pre-dedup) -> ${RAW_SUBS}"
step_end "[1a/6] Subdomain enumeration (passive)"

# ==============================================================================
# STEP 1b -- Active subdomain brute‑force with gobuster (optional)
# ==============================================================================
if [ -n "$BRUTE_WORDLIST" ]; then
    step_begin
    info "[1b/6] Brute‑forcing subdomains with gobuster dns..."
    BRUTE_OUT="${OUTDIR}/brute_subs.txt"
    run_with_timeout "30m" gobuster dns -d "$DOMAIN" -w "$BRUTE_WORDLIST" \
        -t "$GOBUSTER_THREADS" --no-color -o "$BRUTE_OUT" 2>/dev/null
    gb_status=$?
    if [ "$gb_status" -ne 0 ]; then
        warn "gobuster exited with status ${gb_status} -- results may be incomplete."
    fi
    # gobuster output format: "found: sub.example.com" -> extract subdomain
    if [ -f "$BRUTE_OUT" ]; then
        grep -Po 'found:\s+\K.*' "$BRUTE_OUT" > "${BRUTE_OUT}.clean"
        mv "${BRUTE_OUT}.clean" "$BRUTE_OUT"
    fi
    BRUTE_COUNT=$(wc -l < "$BRUTE_OUT" 2>/dev/null | tr -d ' ')
    good "gobuster found ${BRUTE_COUNT:-0} new subdomains -> ${BRUTE_OUT}"
    cat "$BRUTE_OUT" >> "$RAW_SUBS"
    step_end "[1b/6] Active subdomain brute‑force"
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
    run_with_timeout "$HTTPX_TIMEOUT" httpx -l "$RAW_SUBS" -silent -threads "$HTTPX_THREADS" -o "$ALIVE_SUBS"
    hx_status=$?
    [ "$hx_status" -eq 124 ] && warn "httpx timed out after ${HTTPX_TIMEOUT} -- alive-host list may be incomplete."
    [ "$hx_status" -ne 0 ] && [ "$hx_status" -ne 124 ] && warn "httpx exited with status ${hx_status} -- alive-host list may be incomplete."
else
    warn "httpx missing -- using a parallel curl fallback (slower/less accurate)."
    : > "$ALIVE_SUBS"
    probe_host() {
        local sub="$1" scheme code
        for scheme in https http; do
            code=$(curl -ks -L -o /dev/null --max-time 8 -w "%{http_code}" "${scheme}://${sub}" 2>/dev/null)
            if [[ "$code" =~ ^(2[0-9]{2}|3[0-9]{2}|401|403)$ ]]; then
                echo "${scheme}://${sub}"
                return 0
            fi
        done
        return 1
    }
    export -f probe_host

    # Fix: write each worker's output to a unique temp file, then concatenate
    tmpdir=$(mktemp -d "${OUTDIR}/.alive_XXXXXX")
    xargs -a "$RAW_SUBS" -d '\n' -P "$HTTPX_THREADS" -I{} bash -c '
        out="$1/$$_${RANDOM}.txt"
        probe_host "$2" > "$out" 2>/dev/null
    ' _ "$tmpdir" {}
    cat "$tmpdir"/*.txt 2>/dev/null >> "$ALIVE_SUBS"
    rm -rf "$tmpdir"
    sort -u "$ALIVE_SUBS" -o "$ALIVE_SUBS"
fi

ALIVE_COUNT=$(wc -l < "$ALIVE_SUBS" 2>/dev/null | tr -d ' ')
good "${ALIVE_COUNT:-0} alive subdomains -> ${ALIVE_SUBS}"
step_end "[2/6] Dedup + alive-check"

if [ "${ALIVE_COUNT:-0}" -eq 0 ]; then
    warn "No HTTP-alive subdomains found -- screenshots will be skipped."
fi

# Prepare clean hostname list for later resolution
sort -u "$RAW_SUBS" -o "$CLEAN_HOSTS"

# ==============================================================================
# STEP 3 -- Wildcard‑DNS check + resolve ALL subdomains to IPv4/IPv6 (dig)
# ==============================================================================
step_begin
info "[3/6] Checking ${DOMAIN} for wildcard DNS using dig..."

: > "$WILDCARD_IPS"
: > "$WILDCARD_FILTERED_HOSTS"

# Generate random probe labels
probe_file=$(mktemp)
for i in $(seq 1 "$WILDCARD_PROBE_COUNT"); do
    printf 'wc-probe-%s-%d-%s.%s\n' "$(date +%s)$$" "$RANDOM" "$i" "$DOMAIN"
done > "$probe_file"

# Resolve probes with dig (A + AAAA), collect unique IPs
while IFS= read -r lbl; do
    dig +short +time=3 +tries=2 "$lbl" A   2>/dev/null
    dig +short +time=3 +tries=2 "$lbl" AAAA 2>/dev/null
done < "$probe_file" | sort -u > "$WILDCARD_IPS"
rm -f "$probe_file"

if [ -s "$WILDCARD_IPS" ]; then
    warn "Wildcard DNS detected on ${DOMAIN} -- random non-existent labels resolve to: $(paste -sd, "$WILDCARD_IPS")"
    warn "Hosts that resolve ONLY to that IP set will be excluded as wildcard ghosts (see ${WILDCARD_FILTERED_HOSTS})."
else
    info "No wildcard DNS detected."
fi

info "Resolving all discovered subdomains to IP addresses using dig (${DNS_RESOLVE_THREADS} parallel workers)..."
: > "$HOST_IP_PAIRS"

resolve_host_dig() {
    local host="$1"
    dig +short +time=3 +tries=2 "$host" A 2>/dev/null | while read -r ip; do
        [ -n "$ip" ] && printf '%s\t%s\n' "$host" "$ip"
    done
    dig +short +time=3 +tries=2 "$host" AAAA 2>/dev/null | while read -r ip; do
        [ -n "$ip" ] && printf '%s\t%s\n' "$host" "$ip"
    done
}
export -f resolve_host_dig

# Fix: use per‑worker temp files to avoid interleaving
tmpdir=$(mktemp -d "${OUTDIR}/.dns_XXXXXX")
xargs -a "$CLEAN_HOSTS" -P "$DNS_RESOLVE_THREADS" -I{} bash -c '
    out="$1/$$_${RANDOM}.txt"
    resolve_host_dig "$2" > "$out"
' _ "$tmpdir" {}
cat "$tmpdir"/*.txt 2>/dev/null >> "$HOST_IP_PAIRS"
rm -rf "$tmpdir"
sort -u "$HOST_IP_PAIRS" -o "$HOST_IP_MAP"

# Filter out hosts that resolve exclusively to wildcard IPs
awk -v wcfile="$WILDCARD_IPS" -v filtered_out="$WILDCARD_FILTERED_HOSTS" '
BEGIN {
    while ((getline line < wcfile) > 0) if (line != "") wc[line] = 1
}
{
    host = $1; ip = $2
    key = host SUBSEP ip
    if (key in seen) next
    seen[key] = 1
    order[++n] = key
    pair_host[n] = host; pair_ip[n] = ip
    total[host]++
    if (ip in wc) matched[host]++
}
END {
    for (i = 1; i <= n; i++) {
        h = pair_host[i]; ip = pair_ip[i]
        if (total[h] > 0 && matched[h] == total[h]) {
            if (!(h in reported)) { print h >> filtered_out; reported[h] = 1 }
        } else {
            print ip
        }
    }
}' "$HOST_IP_PAIRS" | sort -u > "$RESOLVED_IPS"

sort -u "$WILDCARD_FILTERED_HOSTS" -o "$WILDCARD_FILTERED_HOSTS" 2>/dev/null

RESOLVED_COUNT=$(wc -l < "$RESOLVED_IPS" 2>/dev/null | tr -d ' ')
WILDCARD_FILTERED_COUNT=$(wc -l < "$WILDCARD_FILTERED_HOSTS" 2>/dev/null | tr -d ' ')
good "${RESOLVED_COUNT:-0} unique IPs (IPv4/IPv6) resolved -> ${RESOLVED_IPS}"
[ "${WILDCARD_FILTERED_COUNT:-0}" -gt 0 ] && warn "${WILDCARD_FILTERED_COUNT} host(s) excluded as wildcard ghosts -> ${WILDCARD_FILTERED_HOSTS}"

USED_HOSTNAME_FALLBACK=0
if [ "${RESOLVED_COUNT:-0}" -eq 0 ]; then
    warn "No IPs resolved via dig — falling back to bare hostnames for scanning."
    cp "$CLEAN_HOSTS" "$RESOLVED_IPS"
    if [ -s "$WILDCARD_IPS" ]; then
        warn "Wildcard IPs were detected; scans may include hosts that resolve to those IPs (DNS failure)."
    fi
    RESOLVED_COUNT=$(wc -l < "$RESOLVED_IPS" | tr -d ' ')
    USED_HOSTNAME_FALLBACK=1
fi

SCAN_TARGETS="$RESOLVED_IPS"
step_end "[3/6] Wildcard check + IP resolution"

# ==============================================================================
# STEP 4 -- Screenshots (gowitness) in background
# ==============================================================================
STEP4_START=$(date +%s)
GOWITNESS_LOG="${OUTDIR}/.gowitness.log"
GOWITNESS_PID=""
if [ "$HAVE_GOWITNESS" -eq 1 ] && [ -s "$ALIVE_SUBS" ]; then
    info "[4/6] Taking screenshots with gowitness (running in background)..."
    (
        gowitness scan file -f "$ALIVE_SUBS" --screenshot-path "$SCREENSHOT_DIR" \
            || gowitness file -f "$ALIVE_SUBS" -P "$SCREENSHOT_DIR"
    ) > "$GOWITNESS_LOG" 2>&1 &
    GOWITNESS_PID=$!
else
    warn "gowitness not installed or no alive hosts -- skipping screenshots."
fi

# ==============================================================================
# STEP 5 -- Fast port scan (naabu / nmap)
# ==============================================================================
step_begin
info "[5/6] Port scanning ${RESOLVED_COUNT:-0} resolved targets (top ${TOP_PORTS} ports)..."
: > "$OPEN_PORTS_MAP"

if [ "$HAVE_NAABU" -eq 1 ]; then
    info "Using naabu for fast port discovery (-exclude-cdn skips CDN/WAF-fronted hosts)..."
    TOP_PORTS_LIST="${OUTDIR}/.top_ports.txt"
    if gen_top_ports "$TOP_PORTS" | tr ',' '\n' > "$TOP_PORTS_LIST" 2>/dev/null && [ -s "$TOP_PORTS_LIST" ]; then
        naabu -l "$SCAN_TARGETS" -ports-file "$TOP_PORTS_LIST" -exclude-cdn -rate "$NAABU_RATE" \
              -silent -o "${OUTDIR}/${PORT_SCAN_FILE}"
    else
        warn "Could not generate a custom top-ports list -- falling back to naabu top-1000."
        naabu -l "$SCAN_TARGETS" -top-ports 1000 -exclude-cdn -rate "$NAABU_RATE" \
              -silent -o "${OUTDIR}/${PORT_SCAN_FILE}"
    fi
    naabu_status=$?
    [ "$naabu_status" -ne 0 ] && warn "naabu exited with status ${naabu_status} (needs CAP_NET_RAW or root)."

    if [ -s "${OUTDIR}/${PORT_SCAN_FILE}" ]; then
        awk '{
            line = $0
            idx = 0
            for (i = length(line); i >= 1; i--) {
                if (substr(line, i, 1) == ":") { idx = i; break }
            }
            if (idx == 0) next
            host = substr(line, 1, idx - 1)
            port = substr(line, idx + 1)
            if (host in ports) { ports[host] = ports[host] "," port }
            else                { ports[host] = port }
        }
        END { for (h in ports) print h ":" ports[h] }' "${OUTDIR}/${PORT_SCAN_FILE}" > "$OPEN_PORTS_MAP"
    else
        fail "naabu produced no output -- port scan failed or found nothing open."
    fi
else
    info "Using nmap for port discovery (-T4, --min-rate ${NMAP_MIN_RATE})..."
    : > "$IPV4_TARGETS"; : > "$IPV6_TARGETS"
    awk -v v4out="$IPV4_TARGETS" -v v6out="$IPV6_TARGETS" \
        '{ if ($0 ~ /:/) print > v6out; else print > v4out }' "$SCAN_TARGETS"

    NMAP_V4_LOG="${OUTDIR}/.nmap_v4.log"; NMAP_V6_LOG="${OUTDIR}/.nmap_v6.log"
    NMAP_V4_GREP="${OUTDIR}/.nmap_grep_v4"; NMAP_V6_GREP="${OUTDIR}/.nmap_grep_v6"
    nmap_status=0

    if [ -s "$IPV4_TARGETS" ]; then
        nmap -iL "$IPV4_TARGETS" -Pn -T4 --top-ports "$TOP_PORTS" --min-rate "$NMAP_MIN_RATE" \
             -oN "$NMAP_V4_LOG" -oG "$NMAP_V4_GREP" > /dev/null 2>&1 || nmap_status=1
    fi
    if [ -s "$IPV6_TARGETS" ]; then
        nmap -6 -iL "$IPV6_TARGETS" -Pn -T4 --top-ports "$TOP_PORTS" --min-rate "$NMAP_MIN_RATE" \
             -oN "$NMAP_V6_LOG" -oG "$NMAP_V6_GREP" > /dev/null 2>&1 || nmap_status=1
    fi
    [ "$nmap_status" -ne 0 ] && warn "one or more nmap invocations exited non-zero -- results may be incomplete."

    cat "$NMAP_V4_LOG" "$NMAP_V6_LOG" > "${OUTDIR}/${PORT_SCAN_FILE}" 2>/dev/null
    cat "$NMAP_V4_GREP" "$NMAP_V6_GREP" > "${OUTDIR}/.nmap_grep_tmp" 2>/dev/null
    rm -f "$NMAP_V4_LOG" "$NMAP_V6_LOG" "$NMAP_V4_GREP" "$NMAP_V6_GREP"

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

# Wait for screenshots background job
if [ -n "$GOWITNESS_PID" ]; then
    wait "$GOWITNESS_PID"
    GW_STATUS=$?
    STEP4_ELAPSED=$(( $(date +%s) - STEP4_START ))
    if [ "$GW_STATUS" -eq 0 ]; then
        good "[4/6] Screenshots saved -> ${SCREENSHOT_DIR}/  (took $(fmt_duration "$STEP4_ELAPSED"))"
    else
        warn "[4/6] gowitness failed after $(fmt_duration "$STEP4_ELAPSED") -- see ${GOWITNESS_LOG}"
    fi
fi

# ==============================================================================
# STEP 6 -- Service / version detection
# ==============================================================================
step_begin
info "[6/6] Running service/version detection on discovered open ports (${SERVICE_SCAN_CONCURRENCY} parallel, ${NMAP_HOST_TIMEOUT} cap per host)..."

SERVICE_OUT="${OUTDIR}/${SERVICE_SCAN_FILE}"
: > "$SERVICE_OUT"

if [ ! -s "$OPEN_PORTS_MAP" ]; then
    warn "No open ports discovered in step 5 -- nothing to version-scan."
else
    scan_one_host() {
        local line="$1" host ports outfile status
        local ipver_flag=()
        ports="${line##*:}"
        host="${line%:*}"
        [ -z "$ports" ] && return 0
        case "$host" in *:*) ipver_flag=(-6) ;; esac
        echo "    -> scanning ${host}  (ports: ${ports})" >&2
        outfile=$(mktemp "${OUTDIR}/.svc_XXXXXX")
        {
            echo "==== ${host} ===="
            nmap -sV -Pn "${ipver_flag[@]}" -p "$ports" --host-timeout "$NMAP_HOST_TIMEOUT" "$host"
            status=$?
            [ "$status" -ne 0 ] && echo "[!] nmap exited with status ${status} for ${host}"
            echo
        } > "$outfile" 2>&1
        echo "$outfile"
    }
    export -f scan_one_host
    export OUTDIR NMAP_HOST_TIMEOUT

    TOTAL_SCAN_HOSTS=$(wc -l < "$OPEN_PORTS_MAP" | tr -d ' ')
    info "Dispatching ${TOTAL_SCAN_HOSTS} hosts across ${SERVICE_SCAN_CONCURRENCY} parallel nmap workers..."
    OUTFILES=$(xargs -a "$OPEN_PORTS_MAP" -d '\n' -P "$SERVICE_SCAN_CONCURRENCY" -I{} bash -c 'scan_one_host "$@"' _ {})
    for f in $OUTFILES; do
        cat "$f" >> "$SERVICE_OUT"
        rm -f "$f"
    done
    good "Service scan complete -> ${SERVICE_OUT}"
fi
step_end "[6/6] Service/version detection"

# ==============================================================================
# Summary
# ==============================================================================
echo "=============================================================="
good "Recon complete for ${DOMAIN}"
TOTAL_RUNTIME=$(( $(date +%s) - SCRIPT_START ))
echo "    Total runtime:           $(fmt_duration "$TOTAL_RUNTIME")"
echo "    Raw subdomains:          ${RAW_COUNT}"
echo "    Unique subdomains:       ${DEDUP_COUNT}"
echo "    Alive subdomains:        ${ALIVE_COUNT}"
if [ "${USED_HOSTNAME_FALLBACK:-0}" -eq 1 ]; then
    echo "    Resolved IPs:            ${RESOLVED_COUNT:-0}  (DNS resolution failed — scanned by hostname)"
else
    echo "    Resolved IPs:            ${RESOLVED_COUNT:-0}"
fi
echo "    Wildcard-filtered hosts: ${WILDCARD_FILTERED_COUNT:-0}"
echo "    Hosts w/ open ports:     ${OPEN_HOST_COUNT}"
echo
echo "    Output directory:       ${OUTDIR}/"
echo "      |-- subs_raw.txt                (all subfinder + optional gobuster results, deduped)"
echo "      |-- alive_subs.txt              (alive subdomains)"
echo "      |-- clean_hosts.txt             (bare hostnames — ALL discovered subdomains)"
echo "      |-- resolved_ips.txt            (IPv4/IPv6 used for scanning; wildcard ghosts excluded)"
echo "      |-- host_ip_map.txt             (informational: every host → every IP, unfiltered)"
echo "      |-- wildcard_filtered_hosts.txt (hosts excluded as wildcard ghosts)"
echo "      |-- screenshots/                (gowitness screenshots of alive subs)"
echo "      |-- ${PORT_SCAN_FILE}"
echo "      \`-- ${SERVICE_SCAN_FILE}"
echo "=============================================================="