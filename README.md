

# ⚠️ Legal Disclaimer
This project is for educational & authorized testing only.
I am not responsible for misuse. Always have permission before scanning.

---

# 🔎 DirtyRecci (All-in-One Recon Toolkit)

**DRi** is a powerful **standalone reconnaissance toolkit** written in Python.  
It combines DNS, WHOIS, subdomain enumeration, port scanning, technology fingerprinting, and more — into **one sleek CLI tool**.  

🚀 Built for security researchers, bug bounty hunters, and students who want a **ready-to-use recon companion**.

---

## ✨ Features
- 🌍 **WHOIS Lookup** — Owner & registrar information.
- 🔎 **DNS Records Scanner** — A, MX, NS, TXT, CNAME lookups.
- 🏗️ **Subdomain Finder** — Smart wordlist-based discovery.
- ⚡ **Port Scanner** — Fast concurrent open port detection.
- 🖥️ **Tech Fingerprinting** — Detects headers & web technologies.
- 📑 **JSON Report Export** — Save findings for later analysis.
- 🎛️ **Interactive Dashboard** — Command-based menu system.

---

## 🖥️ Usage

### Commands 
```bash
pip install -r requirements.txt    ~ # Install Dependencies..

python sch.py      ~ # Run in Interactive mode..

python sch.py --target example.com --full --json report.json      ~ # Run in Command Mode..
