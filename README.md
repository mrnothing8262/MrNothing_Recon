# MrNothing_Recon.sh — Bug Bounty Subdomain Recon Pipeline

**Version:** MrNothing_Recon_v2.sh 
**Author:** Mr.Nothing

A comprehensive, modular subdomain reconnaissance script designed for bug bounty hunters and penetration testers. It automates the entire workflow: subdomain discovery, alive‑check, wildcard‑DNS filtering, IP resolution, screenshots, port scanning, and service/version detection — all with a focus on speed and reliability.

---

## ✨ Features

- **Passive Enumeration:** Uses `subfinder` with all sources to collect subdomains.
- **Active Brute‑Force (optional):** Feed a wordlist via `-w` to discover additional subdomains using `gobuster dns`.
- **Wildcard DNS Filtering:** Automatically detects wildcard DNS entries and excludes hosts that resolve **only** to wildcard IPs — preventing false positives in scans.
- **Intelligent IP Resolution:** Resolves every discovered subdomain to IPv4 and IPv6 using parallel `dig` workers. Falls back to hostnames if resolution fails.
- **Alive‑Check:** Fast HTTP/HTTPS probing with `httpx` (or a parallel `curl` fallback).
- **Screenshots:** Background `gowitness` capture of all alive subdomains.
- **Port Scanning:** Fast port discovery with `naabu` (supports custom port lists from `nmap-services`) or `nmap` as fallback.
- **Service Version Detection:** Multi‑threaded `nmap -sV` with per‑host timeouts to avoid hanging.
- **Configurable & Extensible:** Tweak threads, timeouts, port ranges, and rates directly in the script.
- **Clean Output:** All results are organised in a timestamped directory with clear file names.

---

## 🛠️ Requirements

The following tools must be installed and available in your `$PATH`:

| Tool | Purpose | Installation |
|------|---------|--------------|
| **subfinder** | Passive subdomain enumeration | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| **nmap** | Port scanning & service detection | Package manager (e.g., `apt install nmap`) |
| **dig** (bind‑utils) | DNS resolution | Package manager (e.g., `apt install dnsutils`) |
| **httpx** (optional but recommended) | Alive‑check | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| **naabu** (optional) | Fast port scanning | `go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| **gowitness** (optional) | Screenshots | `go install -v github.com/sensepost/gowitness@latest` |
| **gobuster** (optional, for brute‑force) | Active subdomain enumeration | `go install -v github.com/OJ/gobuster/v3@latest` |
| **timeout** (GNU coreutils) | Command timeouts | Usually pre‑installed; if missing, install `coreutils` |

> **Note:** `naabu` may require elevated capabilities (`CAP_NET_RAW`). Run with `sudo` if you encounter permission errors, or set the capability manually (`sudo setcap cap_net_raw+ep /path/to/naabu`).

---

## 📦 Installation

Clone the repository and make the script executable:

```bash
git clone https://github.com/yourusername/MrNothing_Recon.git
cd MrNothing_Recon
chmod +x MrNothing_Recon.sh
