#!/usr/bin/env python3

import argparse
import socket
import concurrent.futures
import requests
import dns.resolver
from termcolor import colored
from urllib.parse import urlparse
from tqdm import tqdm

# Banner
def print_banner():
    banner = """
    ____  _   _ ____  _____ ___  ____  _____ _   _ _____ 
   / ___|| | | | __ )|  ___/ _ \|  _ \| ____| \ | |_   _|
   \___ \| | | |  _ \| |_ | | | | |_) |  _| |  \| | | |  
    ___) | |_| | |_) |  _|| |_| |  _ <| |___| |\  | | |  
   |____/ \___/|____/|_|   \___/|_| \_\_____|_| \_| |_|  
                                                          
    Subdomain Enumeration | Port Scanning | Basic Service Detection
    """
    print(colored(banner, 'cyan'))

# Subdomain enumeration
def enumerate_subdomains(domain, wordlist, threads):
    print(colored(f"\n[+] Enumerating subdomains for {domain}", 'yellow'))
    
    try:
        with open(wordlist, 'r') as f:
            subdomains = [line.strip() for line in f]
    except FileNotFoundError:
        print(colored(f"[-] Wordlist file not found: {wordlist}", 'red'))
        return []
    
    found_subdomains = []
    
    def check_subdomain(subdomain):
        full_domain = f"{subdomain}.{domain}"
        try:
            answers = dns.resolver.resolve(full_domain, 'A')
            for answer in answers:
                found_subdomains.append(full_domain)
                print(colored(f"[+] Found subdomain: {full_domain} -> {answer}", 'green'))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            pass
        except Exception as e:
            print(colored(f"[-] Error checking {full_domain}: {e}", 'red'))
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        list(tqdm(executor.map(check_subdomain, subdomains), total=len(subdomains), desc="Enumerating"))
    
    return found_subdomains

# Port scanning
def scan_ports(target, ports, threads):
    print(colored(f"\n[+] Scanning ports for {target}", 'yellow'))
    
    open_ports = []
    
    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                    print(colored(f"[+] Port {port} is open", 'green'))
        except Exception as e:
            print(colored(f"[-] Error scanning port {port}: {e}", 'red'))
    
    if '-' in ports:
        start_port, end_port = map(int, ports.split('-'))
        ports_to_scan = range(start_port, end_port + 1)
    else:
        ports_to_scan = [int(p) for p in ports.split(',')]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        list(tqdm(executor.map(scan_port, ports_to_scan), total=len(ports_to_scan), desc="Scanning"))
    
    return open_ports

# Basic service detection
def detect_services(target, open_ports):
    print(colored(f"\n[+] Detecting services on {target}", 'yellow'))
    
    # Common port to service mapping
    common_services = {
        20: 'FTP (Data)',
        21: 'FTP (Control)',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        3306: 'MySQL',
        3389: 'RDP',
        8080: 'HTTP-Alt',
    }
    
    for port in open_ports:
        service = common_services.get(port, 'Unknown')
        print(colored(f"[+] Port {port}: Likely {service} service", 'blue'))
        
        # Try to get HTTP service banner if it's a web port
        if port in [80, 443, 8080, 8443]:
            try:
                protocol = 'https' if port in [443, 8443] else 'http'
                url = f"{protocol}://{target}:{port}"
                response = requests.get(url, timeout=3, verify=False)
                server = response.headers.get('Server', 'Not specified')
                print(f"    Web Server: {server}")
                print(f"    Status Code: {response.status_code}")
                print(f"    Response Length: {len(response.content)} bytes")
            except requests.exceptions.RequestException as e:
                print("    Could not retrieve HTTP headers")

# Main function
def main():
    parser = argparse.ArgumentParser(description="Combined Subdomain Enumeration, Port Scanning, and Basic Service Detection Tool")
    parser.add_argument("-d", "--domain", help="Target domain for subdomain enumeration")
    parser.add_argument("-w", "--wordlist", default="/usr/share/wordlists/dirb/common.txt", help="Wordlist for subdomain enumeration")
    parser.add_argument("-t", "--target", help="Target IP or domain for port scanning")
    parser.add_argument("-p", "--ports", default="1-1024", help="Ports to scan (e.g., 80,443 or 1-1000)")
    parser.add_argument("--threads", type=int, default=50, help="Number of threads to use")
    parser.add_argument("--full", action="store_true", help="Run full reconnaissance (subdomain, port scan, service detection)")
    args = parser.parse_args()
    
    print_banner()
    
    if args.full:
        if not args.domain:
            print(colored("[-] Domain is required for full reconnaissance", 'red'))
            return
        
        # Step 1: Subdomain enumeration
        subdomains = enumerate_subdomains(args.domain, args.wordlist, args.threads)
        
        if not subdomains:
            print(colored("[-] No subdomains found", 'red'))
            return
        
        # Step 2: Port scanning for each found subdomain
        for subdomain in subdomains:
            try:
                target_ip = socket.gethostbyname(subdomain)
                print(colored(f"\n[+] Resolved {subdomain} to {target_ip}", 'blue'))
                
                open_ports = scan_ports(target_ip, args.ports, args.threads)
                
                if open_ports:
                    # Step 3: Basic service detection
                    detect_services(target_ip, open_ports)
                else:
                    print(colored(f"[-] No open ports found for {subdomain}", 'red'))
            except socket.gaierror:
                print(colored(f"[-] Could not resolve {subdomain}", 'red'))
    else:
        if args.target:
            try:
                target_ip = socket.gethostbyname(args.target)
                open_ports = scan_ports(target_ip, args.ports, args.threads)
                if open_ports:
                    detect_services(target_ip, open_ports)
            except socket.gaierror:
                print(colored(f"[-] Could not resolve {args.target}", 'red'))
        else:
            print(colored("[-] Please specify either --full or --target", 'red'))

if __name__ == "__main__":
    main()

