# VulnX Ultra

VulnX Ultra is an advanced web vulnerability scanner and exploitation tool. It supports detecting and exploiting multiple web vulnerabilities including:

- **XSS** (Cross-Site Scripting)
- **SSRF** (Server-Side Request Forgery)
- **LFI** (Local File Inclusion)
- **RFI** (Remote File Inclusion)
- **SQLi** (SQL Injection)
- **RCE** (Remote Code Execution)

---

## Requirements

- Python 3.x installed on your system
- Required Python libraries (see installation below)

---

## Installation

1. Clone or download the repository to your device (e.g., Termux).

2. Install required Python packages:

```bash
git clone https://github.com/HN1A/VulnX_Ultra.git
cd VulnX_Ultra
pip install -r requirements.txt
```


(If you don't have a requirements.txt, you can install common packages used for web requests and parsing, such as:)

pip install requests beautifulsoup4 colorama

3. Make sure Python is properly installed and available as python or python3.




---

Usage

Run the tool with:

python VulnX_Ultra.py -u <target_url> [options]


---

Available Options

Option	Description

-h, --help	Show help message
-u URL, --url URL	Target URL to test (e.g., http://example.com/page.php)
-p PARAM, --param	Parameter to test (default: file)
--lfi	Test for Local File Inclusion
--rfi	Test for Remote File Inclusion
--ssrf	Test for Server-Side Request Forgery
--xss	Test for Cross-Site Scripting
--sqli	Test for SQL Injection
--rce	Test for Remote Code Execution
--api	Test API endpoints
--headers	Test HTTP headers
--method METHOD	HTTP method to use (GET, POST, PUT, DELETE)
--encode	Use URL/Base64 encoding
--os {linux,windows}	Target operating system
--custom-payload	Use a custom payload file
--output	Output results to a file (txt/json/csv)
--proxy	Use a single proxy URL (e.g., http://127.0.0.1:8080)
--proxy-list	Use a list of proxies from a file
--tor	Use Tor network (127.0.0.1:9050)
--config	Use a configuration file (YAML format)
--keywords	Custom keywords for response analysis (comma-separated)
--delay	Delay between requests in seconds
--detect-waf	Detect Web Application Firewalls
--detect-ips	Detect IPS/IDS systems
--fingerprint	Perform OS fingerprinting
--subdomains	Enumerate subdomains
--port-scan	Perform port scanning
--stealth	Enable stealth mode (slower, less detectable)
--threads	Number of threads to use (default: 10)
--show-guide	Show usage guide and exit
--exploit-lfi	Exploit LFI vulnerabilities (requires --lfi)
--exploit-rfi	Exploit RFI vulnerabilities (requires --rfi)
--exploit-ssrf	Exploit SSRF vulnerabilities (requires --ssrf)
--exploit-xss	Exploit XSS vulnerabilities (requires --xss)
--exploit-sqli	Exploit SQL Injection (requires --sqli)
--exploit-rce	Exploit Remote Code Execution (requires --rce)
--server	External server URL for RFI or RCE exploitation
--upload	Upload a file (format: local_path:remote_path)



---

Running the Exploitation Server

To receive data or exploitation results, run the server using:

python Server.py


---

Example Usage

Scan a URL for XSS and SQL Injection vulnerabilities:


python VulnX_Ultra.py -u http://example.com/page.php --xss --sqli

Scan with exploitation enabled for LFI:


python VulnX_Ultra.py -u http://example.com/vuln.php --lfi --exploit-lfi

Use a proxy and save output to a JSON file:


python VulnX_Ultra.py -u http://target.com --xss --proxy http://127.0.0.1:8080 --output results.json


---

![Screenshot Termux](https://i.postimg.cc/zBYF1DNx/Screenshot-Termux.jpg) 



---

Notes

Always ensure you have permission to test the target.

Use responsibly and ethically.

Recommended to run in an isolated environment or container if possible.



---

License

Open source. Feel free to modify and extend.

