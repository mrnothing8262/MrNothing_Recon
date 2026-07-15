# MrNothing_Recon

A fast, modular bug bounty subdomain reconnaissance and target profiling pipeline written in Bash. 

MrNothing_Recon automates the tedious early phases of security engagements by chaining together industry-standard tools. It handles everything from initial discovery to active service fingerprinting, featuring built-in fallbacks if certain tools are missing from your environment.  


🚀 Features & Pipeline StepsThe script executes a sequential 6-step reconnaissance pipeline:  
1. Subdomain Enumeration: Passively discovers subdomains using subfinder.
2. Deduplication & Live Probing: Cleans the results in-place and filters for active HTTP/HTTPS targets using httpx (with a lightweight curl fallback).
3. IP Resolution: Resolves active hostnames to their respective IPv4 and IPv6 addresses via dnsx (with a getent/dig fallback) to prevent scanning fronted CDNs where possible.
4. Visual Reconnaissance: Captures website screenshots automatically using gowitness.
5. Fast Port Scanning: Discovers open ports across the top 5,000 ports using naabu for raw speed, automatically falling back to an optimized nmap configuration if needed.
6. Service & Version Fingerprinting: Isolates only the specific open ports found in Step 5 and runs an aggressive nmap -sV scan against them, drastically saving time over blind full-range scans.



 🛠️ Prerequisites & InstallationThe pipeline relies on a few core tools.
 
Make sure they are installed and available in your system's $PATH.

Required CoreBashsudo apt update && sudo apt install nmap -y
  
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  

Highly Recommended (For Maximum Speed & Features)If these are missing, the script will gracefully switch to slower, native Linux fallbacks: 

Bashgo install 

github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/sensepost/gowitness@latest






💻 UsageClone this repository and navigate into it:Bashgit clone https://github.com/mrnothing8262/MrNothing_Recon.git

cd MrNothing_Recon

Make the script executable:Bashchmod +x MrNothing_Recon.sh

Run it against an authorized target domain:  Bash./MrNothing_Recon.sh example.com







Output StructureThe script dynamically creates a structured output folder named recon_<domain>_<timestamp>/ containing organized artifacts:  

Plaintext📂 recon_example.com_20260715_164500/

├── 📄 subs_raw.txt             # Raw, deduplicated subdomains
├── 📄 alive_subs.txt           # Verified live HTTP/HTTPS applications
├── 📄 clean_hosts.txt          # Stripped, bare hostnames
├── 📄 resolved_ips.txt         # Unique target IPv4/IPv6 addresses
├── 📄 Port_scan_alive_subs     # Raw fast-scan port results
├── 📄 Service_Scan_alive_subs  # In-depth nmap service fingerprints
└── 📂 screenshots/             # Visual gowitness captures







⚠️ Legal DisclaimerImportant: This tool is designed strictly for authorized security auditing, authorized pentesting, and legitimate Bug Bounty/VDP program participation.  The author ("Mr.Nothing") accepts no liability and is not responsible for any misuse, damage, or legal consequences caused by this program. Running active scans against networks without explicit, written permission from the asset owner is illegal in most jurisdictions. Use responsibly.  📄 LicenseThis project is licensed under the MIT License - see the LICENSE file for details.🔒 Bonus: Create a .gitignore fileBefore you run git add ., create a file named .gitignore in the exact same directory and paste this inside it. This stops Git from tracking your actual assessment data so you don't accidentally push a target's infrastructure logs to the public internet:Plaintext# Ignore local recon outputs
recon_*/


