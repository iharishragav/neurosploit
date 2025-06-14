import requests
import socket
import threading
import time
import dns.resolver
import subprocess
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import ssl
import whois
from datetime import datetime
import urllib3
import sys

# Disable SSL warnings for reconnaissance purposes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class NeuroRecon:
    def __init__(self, domain, threads=50, timeout=5):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.found_subdomains = set()
        self.live_subdomains = []
        self.tech_stack = {}
        self.vulnerabilities = []
        
        # Configure requests session for better SSL handling
        self.session = requests.Session()
        self.session.verify = False  # For recon purposes
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def load_subdomain_wordlist(self):
        """Load common subdomain wordlist"""
        common_subdomains = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
            "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
            "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
            "ns3", "mail2", "new", "mysql", "old", "www1", "email", "img", "www3",
            "help", "shop", "secure", "download", "demo", "api", "app", "stage",
            "staging", "beta", "dev", "development", "prod", "production", "test",
            "testing", "lab", "sandbox", "portal", "dashboard", "panel", "login"
        ]
        
        # Try to load from file if exists
        try:
            with open('data/subdomains.txt', 'r') as f:
                file_subdomains = [line.strip() for line in f.readlines()]
            return list(set(common_subdomains + file_subdomains))
        except FileNotFoundError:
            return common_subdomains

    def dns_bruteforce(self, subdomain):
        """Bruteforce subdomain using DNS resolution"""
        try:
            full_domain = f"{subdomain}.{self.domain}"
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            
            answers = resolver.resolve(full_domain, 'A')
            ip = str(answers[0])
            self.found_subdomains.add((full_domain, ip))
            return full_domain, ip
        except:
            return None, None

    def crt_sh_enum(self):
        """Certificate Transparency logs enumeration"""
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                certificates = response.json()
                for cert in certificates:
                    name = cert.get('name_value', '')
                    if name and not name.startswith('*'):
                        subdomains = name.split('\n')
                        for sub in subdomains:
                            if sub.endswith(f".{self.domain}"):
                                self.found_subdomains.add((sub.strip(), "Unknown"))
        except Exception as e:
            print(f"[!] Error in crt.sh enumeration: {e}")

    def check_subdomain_alive(self, subdomain_info):
        """Check if subdomain is alive and get additional info"""
        subdomain, ip = subdomain_info
        try:
            # HTTP Check
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{subdomain}"
                    response = self.session.get(
                        url, 
                        timeout=self.timeout, 
                        allow_redirects=True
                    )
                    
                    tech_info = self.detect_technology(response)
                    
                    subdomain_data = {
                        'subdomain': subdomain,
                        'ip': ip,
                        'status_code': response.status_code,
                        'protocol': protocol,
                        'title': self.extract_title(response.text),
                        'server': response.headers.get('Server', 'Unknown'),
                        'technology': tech_info,
                        'response_time': response.elapsed.total_seconds(),
                        'content_length': len(response.content)
                    }
                    
                    self.live_subdomains.append(subdomain_data)
                    return subdomain_data
                except:
                    continue
        except Exception as e:
            pass
        return None

    def detect_technology(self, response):
        """Detect technologies used by the subdomain"""
        tech = []
        headers = response.headers
        content = response.text.lower()
        
        # Server detection
        server = headers.get('Server', '').lower()
        if 'nginx' in server:
            tech.append('Nginx')
        elif 'apache' in server:
            tech.append('Apache')
        elif 'iis' in server:
            tech.append('IIS')
        
        # Framework detection
        if 'x-powered-by' in headers:
            tech.append(f"Powered by: {headers['x-powered-by']}")
        
        # Content-based detection
        if 'react' in content or 'react-dom' in content:
            tech.append('React')
        if 'angular' in content:
            tech.append('Angular')
        if 'vue' in content:
            tech.append('Vue.js')
        if 'wordpress' in content or 'wp-content' in content:
            tech.append('WordPress')
        if 'drupal' in content:
            tech.append('Drupal')
        if 'joomla' in content:
            tech.append('Joomla')
        
        # Security headers check
        security_headers = ['x-frame-options', 'x-xss-protection', 'x-content-type-options']
        missing_headers = [h for h in security_headers if h not in headers]
        if missing_headers:
            tech.append(f"Missing security headers: {', '.join(missing_headers)}")
        
        return tech

    def extract_title(self, html):
        """Extract title from HTML content"""
        try:
            import re
            title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
            return title_match.group(1).strip() if title_match else "No Title"
        except:
            return "No Title"

    def port_scan(self, ip, ports=[80, 443, 21, 22, 25, 53, 110, 993, 995]):
        """Basic port scan on discovered IPs - Fixed to prevent terminal issues"""
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                # Silently handle errors to prevent terminal issues
                pass
        return open_ports

    def check_ssl_cert(self, domain):
        """Check SSL certificate information - Fixed to prevent terminal issues"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'subject': cert.get('subject'),
                        'issuer': cert.get('issuer'), 
                        'version': cert.get('version'),
                        'serialNumber': cert.get('serialNumber'),
                        'notBefore': cert.get('notBefore'),
                        'notAfter': cert.get('notAfter')
                    }
        except Exception:
            # Silently handle SSL errors to prevent terminal issues
            return None

    def safe_print(self, message):
        """Safe print function to prevent terminal control character issues"""
        try:
            # Clean the message of any control characters
            clean_message = ''.join(char for char in message if ord(char) >= 32 or char in '\n\t')
            print(clean_message)
            sys.stdout.flush()
        except Exception:
            print("[!] Output error occurred")

    def run_full_recon(self):
        """Execute complete reconnaissance with improved terminal handling"""
        self.safe_print(f"🎯 Starting reconnaissance on: {self.domain}")
        self.safe_print("=" * 60)
        
        # Step 1: Certificate Transparency
        self.safe_print("📋 [1/4] Enumerating subdomains via Certificate Transparency...")
        self.crt_sh_enum()
        
        # Step 2: DNS Bruteforce
        self.safe_print("🔍 [2/4] DNS Bruteforce enumeration...")
        wordlist = self.load_subdomain_wordlist()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.dns_bruteforce, sub) for sub in wordlist]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result[0]:  # If subdomain found
                        pass  # Already added in dns_bruteforce method
                except Exception:
                    continue
        
        self.safe_print(f"✅ Found {len(self.found_subdomains)} subdomains")
        
        # Step 3: Check alive subdomains
        self.safe_print("🌐 [3/4] Checking live subdomains...")
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(self.check_subdomain_alive, sub_info) 
                      for sub_info in self.found_subdomains]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.safe_print(f"   ✓ {result['subdomain']} [{result['status_code']}] - {result['server']}")
                except Exception:
                    continue
        
        # Step 4: Additional analysis - Fixed to prevent terminal issues
        self.safe_print("🔬 [4/4] Performing additional analysis...")
        
        # Process each subdomain safely
        for i, subdomain_data in enumerate(self.live_subdomains):
            try:
                ip = subdomain_data.get('ip', 'Unknown')
                if ip != "Unknown":
                    # Port scan with error handling
                    try:
                        open_ports = self.port_scan(ip)
                        subdomain_data['open_ports'] = open_ports
                    except Exception:
                        subdomain_data['open_ports'] = []
                    
                    # SSL certificate check with error handling
                    if subdomain_data.get('protocol') == 'https':
                        try:
                            ssl_info = self.check_ssl_cert(subdomain_data['subdomain'])
                            subdomain_data['ssl_cert'] = ssl_info
                        except Exception:
                            subdomain_data['ssl_cert'] = None
                
                # Progress indicator without control characters
                if (i + 1) % 5 == 0:
                    self.safe_print(f"   Analyzed {i + 1}/{len(self.live_subdomains)} subdomains...")
                    
            except Exception as e:
                # Skip problematic subdomains
                continue
        
        self.safe_print("✅ Additional analysis completed")
        return self.generate_report()

    def generate_report(self):
        """Generate comprehensive reconnaissance report"""
        report = {
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'total_subdomains_found': len(self.found_subdomains),
            'live_subdomains_count': len(self.live_subdomains),
            'subdomains': list(self.found_subdomains),
            'live_subdomains': self.live_subdomains,
            'summary': {
                'technologies': self.get_technology_summary(),
                'security_issues': self.identify_security_issues(),
                'recommendations': self.generate_recommendations()
            }
        }
        return report

    def get_technology_summary(self):
        """Summarize technologies found across all subdomains"""
        tech_count = {}
        for subdomain in self.live_subdomains:
            for tech in subdomain.get('technology', []):
                tech_count[tech] = tech_count.get(tech, 0) + 1
        return tech_count

    def identify_security_issues(self):
        """Identify potential security issues"""
        issues = []
        
        for subdomain in self.live_subdomains:
            sub_issues = []
            
            # Check for missing security headers
            tech = subdomain.get('technology', [])
            for t in tech:
                if 'Missing security headers' in t:
                    sub_issues.append("Missing security headers")
            
            # Check for HTTP instead of HTTPS
            if subdomain.get('protocol') == 'http':
                sub_issues.append("Using HTTP instead of HTTPS")
            
            # Check for common admin panels
            title = subdomain.get('title', '').lower()
            if any(word in title for word in ['admin', 'login', 'dashboard', 'panel']):
                sub_issues.append("Potential admin interface exposed")
            
            # Check for development/staging environments
            subdomain_name = subdomain.get('subdomain', '').lower()
            if any(word in subdomain_name for word in ['dev', 'test', 'staging', 'beta']):
                sub_issues.append("Development/staging environment exposed")
            
            if sub_issues:
                issues.append({
                    'subdomain': subdomain.get('subdomain'),
                    'issues': sub_issues
                })
        
        return issues

    def generate_recommendations(self):
        """Generate security recommendations"""
        recommendations = [
            "Implement proper security headers (X-Frame-Options, X-XSS-Protection, etc.)",
            "Ensure all subdomains use HTTPS with valid certificates",
            "Remove or restrict access to development/staging environments",
            "Implement proper access controls for admin interfaces",
            "Regular security scanning and penetration testing",
            "Monitor certificate transparency logs for unauthorized certificates"
        ]
        return recommendations

def build_ai_prompt(domain, recon_data):
    """Build enhanced AI prompt with real reconnaissance data"""
    
    live_subs = recon_data.get('live_subdomains', [])
    security_issues = recon_data.get('summary', {}).get('security_issues', [])
    tech_summary = recon_data.get('summary', {}).get('technologies', {})
    
    subdomains_info = []
    for sub in live_subs[:10]:  # Limit to first 10 for prompt
        info = f"  - {sub['subdomain']} [{sub['status_code']}] - {sub['server']}"
        if sub.get('open_ports'):
            info += f" (Ports: {', '.join(map(str, sub['open_ports']))})"
        subdomains_info.append(info)
    
    issues_text = []
    for issue in security_issues[:5]:  # Limit to first 5
        issues_text.append(f"  - {issue['subdomain']}: {', '.join(issue['issues'])}")
    
    tech_text = []
    for tech, count in tech_summary.items():
        tech_text.append(f"  - {tech}: {count} instances")
    
    prompt = f"""
🎯 **NEUROSPLOIT RECONNAISSANCE REPORT**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📌 **Target Domain:** {domain}
📊 **Total Subdomains Found:** {recon_data.get('total_subdomains_found', 0)}
🌐 **Live Subdomains:** {recon_data.get('live_subdomains_count', 0)}

🔍 **LIVE SUBDOMAINS:**
{chr(10).join(subdomains_info) if subdomains_info else "  No live subdomains found"}

🧱 **TECHNOLOGY STACK:**
{chr(10).join(tech_text) if tech_text else "  No technologies detected"}

⚠️  **SECURITY ISSUES IDENTIFIED:**
{chr(10).join(issues_text) if issues_text else "  No obvious security issues detected"}

🎯 **AI ANALYSIS REQUEST:**
Based on the above reconnaissance data, please provide:

1. **Vulnerability Assessment:** Identify potential vulnerabilities in the discovered infrastructure
2. **Attack Vectors:** Suggest possible attack paths and entry points
3. **Prioritized Targets:** Rank subdomains by their potential value as attack targets
4. **Exploitation Strategies:** Recommend specific tools and techniques for further testing
5. **Risk Assessment:** Evaluate the overall security posture and risk level

Please focus on actionable intelligence that could be used for authorized penetration testing.
"""
    
    return prompt

# Example usage function
def run_enhanced_recon(domain):
    """Main function to run enhanced reconnaissance"""
    recon = NeuroRecon(domain, threads=50)
    return recon.run_full_recon()

# Quick test function for development
def run_mock_recon(domain):
    """Mock function for testing - replace with run_enhanced_recon for real results"""
    return {
        "domain": domain,
        "total_subdomains_found": 15,
        "live_subdomains_count": 8,
        "subdomains": [
            (f"www.{domain}", "192.168.1.1"),
            (f"api.{domain}", "192.168.1.2"),
            (f"admin.{domain}", "192.168.1.3")
        ],
        "live_subdomains": [
            {
                "subdomain": f"www.{domain}",
                "ip": "192.168.1.1",
                "status_code": 200,
                "protocol": "https",
                "server": "nginx/1.18.0",
                "technology": ["Nginx", "React"],
                "open_ports": [80, 443]
            }
        ],
        "summary": {
            "technologies": {"Nginx": 3, "React": 2, "Missing security headers": 2},
            "security_issues": [
                {
                    "subdomain": f"admin.{domain}",
                    "issues": ["Potential admin interface exposed", "Missing security headers"]
                }
            ]
        }
    }