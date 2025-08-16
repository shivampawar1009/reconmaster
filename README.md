# Reconnaissance Toolkit

A powerful Python tool for comprehensive target reconnaissance, combining subdomain enumeration, port scanning, and service fingerprinting capabilities.

# Requirements
Python 3.x
Kali Linux (or any Linux with required tools)

- Required Python packages:
python-nmap
dnspython
requests
termcolor
tqdm

```
sudo apt update
sudo apt install python3-pip nmap
pip3 install python-nmap dnspython requests termcolor tqdm
```

# Features

- **Subdomain Enumeration**: Discover hidden subdomains using DNS resolution
- **Port Scanning**: Identify open ports with multi-threading support
- **Service Fingerprinting**: Detect running services and versions using Nmap
- **Multi-threaded**: Fast execution with configurable thread count
- **User-friendly**: Color-coded output and progress bars

# Installation

# Prerequisites
- Python 3.6+
- Nmap (for service fingerprinting)
- Required Python packages

# Setup
```bash
git clone git clone https://github.com/shivampawar1009/reconmaster.git
cd recon-toolkit
pip install -r requirements.txt
```

# Usage


# Full reconnaissance (subdomains + port scan + fingerprinting)
```python3 recon.py --full -d example.com -w wordlist.txt```

# Just port scanning and service fingerprinting
```python3 recon.py -t target.example.com -p 1-1000```

# Custom thread count
```python3 recon.py --full -d example.com -w wordlist.txt --threads 100```


# Arguments
- Argument	Description	Default
```
-d, --domain	Target domain for subdomain enumeration	None
-w, --wordlist	Wordlist path for subdomain brute-forcing	/usr/share/wordlists/dirb/common.txt
-t, --target	Target IP/domain for port scanning	None
-p, --ports	Ports to scan (e.g., 80,443 or 1-1000)	1-1024
--threads	Number of threads to use	50
--full	Run full reconnaissance workflow	False
```
