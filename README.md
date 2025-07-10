# 🕵️ Bug Bounty Recon Scanner

**Bug Bounty Recon Scanner** is an automated reconnaissance and vulnerability scanning pipeline tailored for **bug bounty hunters**, **penetration testers**, and **red team operators**. It combines multiple reconnaissance techniques and security tools into a streamlined process — allowing you to discover attack surfaces quickly and effectively.

---

## ⚙️ Features

- 🔍 **Subdomain Enumeration** (passive & active)
- 🌐 **HTTP Probing** – Identify live web services
- 📚 **Wayback URL Collection** – Archive-based URL gathering
- 🕷️ **Web Crawling** using Katana
- 📁 **Directory Bruteforcing** via Gobuster
- 🎯 **GF Pattern Matching** – Search for vulnerability indicators
- 💥 **Nuclei Scanning** – Fast and template-driven vulnerability scanning
- 🧪 **Burp Suite Proxy Integration** – Optional traffic routing
- 🔁 **Force Rescan** – Ignore cached results and re-run all stages
- 📄 **Supports both single domain and domain lists**

---

## 🚀 Usage

```bash
Usage: assetminer.sh [options] (-d <domain> | -l <domain_list>) <proxy>

 ▄▄▄        ██████   ██████ ▓█████▄▄▄█████▓ ███▄ ▄███▓ ██▓ ███▄    █ ▓█████  ██▀███  
▒████▄    ▒██    ▒ ▒██    ▒ ▓█   ▀▓  ██▒ ▓▒▓██▒▀█▀ ██▒▓██▒ ██ ▀█   █ ▓█   ▀ ▓██ ▒ ██▒
▒██  ▀█▄  ░ ▓██▄   ░ ▓██▄   ▒███  ▒ ▓██░ ▒░▓██    ▓██░▒██▒▓██  ▀█ ██▒▒███   ▓██ ░▄█ ▒
░██▄▄▄▄██   ▒   ██▒  ▒   ██▒▒▓█  ▄░ ▓██▓ ░ ▒██    ▒██ ░██░▓██▒  ▐▌██▒▒▓█  ▄ ▒██▀▀█▄  
 ▓█   ▓██▒▒██████▒▒▒██████▒▒░▒████▒ ▒██▒ ░ ▒██▒   ░██▒░██░▒██░   ▓██░░▒████▒░██▓ ▒██▒
 ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░░░ ▒░ ░ ▒ ░░   ░ ▒░   ░  ░░▓  ░ ▒░   ▒ ▒ ░░ ▒░ ░░ ▒▓ ░▒▓░
  ▒   ▒▒ ░░ ░▒  ░ ░░ ░▒  ░ ░ ░ ░  ░   ░    ░  ░      ░ ▒ ░░ ░░   ░ ▒░ ░ ░  ░  ░▒ ░ ▒░
  ░   ▒   ░  ░  ░  ░  ░  ░     ░    ░      ░      ░    ▒ ░   ░   ░ ░    ░     ░░   ░ 
      ░  ░      ░        ░     ░  ░               ░    ░           ░    ░  ░   ░     
                                                                                     

Required arguments:
  -d <domain>           Single domain to scan
  -l <domain_list>      File containing list of domains (one per line)
  <proxy>               Burp Suite proxy URL (http://host:port)

Options:
  -h, --help            Show this help message
  --skip-subdomain      Skip subdomain enumeration phase
  --skip-http           Skip HTTP probe phase
  --skip-wayback        Skip Wayback URL collection
  --skip-crawl          Skip crawling with katana
  --skip-dirb           Skip directory bruteforcing with Gobuster
  --skip-gf             Skip GF pattern matching
  --skip-nuclei         Skip Nuclei scanning
  --with-burp           Send traffic to Burp Suite proxy
  --force-rescan        Force a full rescan ignoring previous results

Examples:
  Single domain:     ./recon.py -d example.com
  Domain list:       ./recon.py -l domains.txt
  With options:      ./recon.py -l domains.txt http://127.0.0.1:8080 --with-burp --force-rescan
