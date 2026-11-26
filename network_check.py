#!/usr/bin/env python3
"""
Network diagnostic script to check outbound connection issues.
Tests DNS resolution, HTTPS connectivity using Google as primary baseline,
with additional Slack API endpoint tests for Slack-specific tools.

Usage: python3 network_check.py
"""

import socket
import sys
import time
import ssl
import urllib.request
import urllib.error
from datetime import datetime
import json
import re
import os

# Color codes for terminal output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

# Global log file handle
log_file = None


class TeeOutput:
    """Class to write output to both stdout and log file"""
    def __init__(self, log_file_handle):
        self.log_file = log_file_handle
        self.stdout = sys.stdout
        
    def write(self, text):
        # Write to stdout (with colors)
        self.stdout.write(text)
        self.stdout.flush()
        
        # Write to log file (strip ANSI colors)
        if self.log_file:
            # Remove ANSI color codes for log file
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            clean_text = ansi_escape.sub('', text)
            self.log_file.write(clean_text)
            self.log_file.flush()
    
    def flush(self):
        self.stdout.flush()
        if self.log_file:
            self.log_file.flush()


def init_logging():
    """Initialize log file with timestamp"""
    global log_file
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_filename = f"network_check_{timestamp}.txt"
    
    try:
        log_file = open(log_filename, 'w', encoding='utf-8')
        # Redirect stdout to our TeeOutput class
        original_stdout = sys.stdout
        sys.stdout = TeeOutput(log_file)
        # Note: This print goes to both console and log
        original_stdout.write(f"Log file: {log_filename}\n\n")
        original_stdout.flush()
        return log_filename
    except Exception as e:
        sys.stderr.write(f"Warning: Could not create log file: {e}\n")
        return None


def close_logging():
    """Close log file and restore stdout"""
    global log_file
    if log_file:
        sys.stdout = sys.__stdout__  # Restore original stdout
        log_file.close()
        log_file = None


def print_header(text):
    """Print a formatted header"""
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{BLUE}{text}{RESET}")
    print(f"{BLUE}{'='*60}{RESET}\n")


def print_success(text):
    """Print success message"""
    print(f"{GREEN}✓{RESET} {text}")


def print_error(text):
    """Print error message"""
    print(f"{RED}✗{RESET} {text}")


def print_warning(text):
    """Print warning message"""
    print(f"{YELLOW}⚠{RESET} {text}")


def print_info(text):
    """Print info message"""
    print(f"  {text}")


def test_dns_resolution(hostname):
    """Test DNS resolution for a hostname"""
    print_info(f"Testing DNS resolution for {hostname}...")
    try:
        ip_addresses = socket.getaddrinfo(hostname, None, socket.AF_INET)
        ips = [ip[4][0] for ip in ip_addresses]
        print_success(f"DNS resolved {hostname} to: {', '.join(ips)}")
        return True, ips
    except socket.gaierror as e:
        print_error(f"DNS resolution failed for {hostname}: {e}")
        return False, None
    except Exception as e:
        print_error(f"Unexpected error during DNS resolution: {e}")
        return False, None


def test_tcp_connection(hostname, port, timeout=5):
    """Test TCP connection to a hostname:port"""
    print_info(f"Testing TCP connection to {hostname}:{port}...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((hostname, port))
        sock.close()
        
        if result == 0:
            print_success(f"TCP connection to {hostname}:{port} successful")
            return True
        else:
            print_error(f"TCP connection to {hostname}:{port} failed (error code: {result})")
            return False
    except socket.timeout:
        print_error(f"TCP connection to {hostname}:{port} timed out after {timeout}s")
        return False
    except Exception as e:
        print_error(f"TCP connection error: {e}")
        return False


def test_https_connection(url, timeout=10):
    """Test HTTPS connection to a URL"""
    print_info(f"Testing HTTPS connection to {url}...")
    try:
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'Mozilla/5.0 (compatible; ConnectionTest/1.0)')
        
        with urllib.request.urlopen(req, timeout=timeout) as response:
            status_code = response.getcode()
            if status_code == 200:
                print_success(f"HTTPS connection successful (Status: {status_code})")
                return True, status_code
            else:
                print_warning(f"HTTPS connection returned status {status_code}")
                return True, status_code
    except urllib.error.HTTPError as e:
        # HTTP errors mean the connection worked, but got an error response
        print_warning(f"HTTPS connection successful but got HTTP error: {e.code} {e.reason}")
        return True, e.code
    except urllib.error.URLError as e:
        print_error(f"HTTPS connection failed: {e.reason}")
        return False, None
    except socket.timeout:
        print_error(f"HTTPS connection timed out after {timeout}s")
        return False, None
    except Exception as e:
        print_error(f"HTTPS connection error: {e}")
        return False, None


def test_ssl_certificate(hostname, port=443):
    """Test SSL certificate validation"""
    print_info(f"Testing SSL certificate for {hostname}:{port}...")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print_success(f"SSL certificate valid for {hostname}")
                print_info(f"  Certificate subject: {cert.get('subject', 'N/A')}")
                return True
    except ssl.SSLError as e:
        print_error(f"SSL certificate error: {e}")
        return False
    except socket.timeout:
        print_error(f"SSL connection timed out")
        return False
    except Exception as e:
        print_error(f"SSL test error: {e}")
        return False


def test_slack_api():
    """Test Slack API connectivity"""
    print_info("Testing Slack API endpoint...")
    try:
        # Test auth.test endpoint (doesn't require valid token, just checks connectivity)
        url = "https://slack.com/api/auth.test"
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'Mozilla/5.0 (compatible; ConnectionTest/1.0)')
        req.add_header('Content-Type', 'application/json')
        
        # Send a minimal request (will fail auth but proves connectivity)
        data = json.dumps({"token": "test"}).encode('utf-8')
        
        with urllib.request.urlopen(req, data=data, timeout=10) as response:
            result = json.loads(response.read().decode('utf-8'))
            if result.get('ok') == False and 'invalid_auth' in result.get('error', ''):
                print_success("Slack API endpoint is reachable (authentication failed as expected)")
                return True
            else:
                print_warning(f"Slack API responded with unexpected result: {result}")
                return True
    except urllib.error.HTTPError as e:
        # If we get an HTTP error, the connection worked
        print_success(f"Slack API endpoint is reachable (HTTP {e.code})")
        return True
    except urllib.error.URLError as e:
        print_error(f"Slack API connection failed: {e.reason}")
        return False
    except socket.timeout:
        print_error("Slack API connection timed out")
        return False
    except Exception as e:
        print_error(f"Slack API test error: {e}")
        return False


def check_proxy_settings():
    """Check if proxy settings are configured"""
    print_info("Checking proxy configuration...")
    import os
    
    proxy_vars = ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy', 
                  'ALL_PROXY', 'all_proxy', 'NO_PROXY', 'no_proxy']
    
    found_proxies = []
    for var in proxy_vars:
        value = os.environ.get(var)
        if value:
            found_proxies.append(f"{var}={value}")
    
    if found_proxies:
        print_warning("Proxy environment variables detected:")
        for proxy in found_proxies:
            print_info(f"  {proxy}")
    else:
        print_success("No proxy environment variables detected")


def get_system_info():
    """Get basic system information"""
    import platform
    print_info(f"System: {platform.system()} {platform.release()}")
    print_info(f"Python: {sys.version.split()[0]}")
    print_info(f"Hostname: {socket.gethostname()}")
    try:
        host_ip = socket.gethostbyname(socket.gethostname())
        print_info(f"Local IP: {host_ip}")
    except:
        pass


def analyze_failures(dns_results, tcp_results, ssl_results, https_results, slack_api_result):
    """Analyze test failures and provide diagnostic information"""
    issues = []
    root_causes = []
    
    # Count failures
    dns_failures = [host for host, success in dns_results.items() if not success]
    tcp_failures = [host_port for host_port, success in tcp_results.items() if not success]
    ssl_failures = [host for host, success in ssl_results.items() if not success]
    https_failures = [url for url, success in https_results.items() if not success]
    
    # Analyze DNS failures
    google_dns_failed = any("google.com" in str(f) for f in dns_failures)
    all_dns_failed = len(dns_failures) == len(dns_results)
    some_dns_failed = len(dns_failures) > 0 and len(dns_failures) < len(dns_results)
    
    if all_dns_failed:
        root_causes.append({
            "severity": "CRITICAL",
            "issue": "DNS Resolution Failure",
            "description": "All DNS lookups are failing. This indicates a fundamental DNS problem.",
            "possible_causes": [
                "DNS server is unreachable or misconfigured",
                "Network interface is down or not properly configured",
                "DNS server IP addresses are incorrect in /etc/resolv.conf",
                "Firewall is blocking DNS queries (UDP port 53)",
                "Corporate DNS server is down or unreachable"
            ],
            "solutions": [
                "Check /etc/resolv.conf for correct DNS server addresses",
                "Try: nslookup google.com 8.8.8.8 (test with Google DNS directly)",
                "Check network interface: ip addr show or ifconfig",
                "Verify DNS server is reachable: ping your DNS server IP",
                "Check firewall rules blocking port 53 UDP"
            ]
        })
    elif google_dns_failed:
        root_causes.append({
            "severity": "HIGH",
            "issue": "DNS Resolution Failure for Google",
            "description": "Cannot resolve Google.com, which is a critical baseline test.",
            "possible_causes": [
                "DNS server is blocking or unable to resolve common domains",
                "Network connectivity issues to DNS server",
                "DNS cache corruption"
            ],
            "solutions": [
                "Try flushing DNS cache: sudo systemd-resolve --flush-caches (Linux) or sudo dscacheutil -flushcache (macOS)",
                "Test with different DNS server: nslookup google.com 8.8.8.8",
                "Check DNS server logs for errors"
            ]
        })
    elif some_dns_failed:
        root_causes.append({
            "severity": "MEDIUM",
            "issue": "Selective DNS Resolution Failure",
            "description": f"Some DNS lookups failed: {', '.join(dns_failures)}",
            "possible_causes": [
                "Specific domains are blocked by firewall/proxy",
                "DNS server has issues resolving certain domains",
                "Network policy blocking specific services"
            ],
            "solutions": [
                "Check if specific domains are blocked by corporate policy",
                "Try resolving from a different network to confirm",
                "Check firewall rules for domain-specific blocking"
            ]
        })
    
    # Analyze TCP failures
    google_tcp_failed = any("google.com" in str(f) for f in tcp_failures)
    all_tcp_failed = len(tcp_failures) == len(tcp_results)
    some_tcp_failed = len(tcp_failures) > 0 and len(tcp_failures) < len(tcp_results)
    
    if all_tcp_failed and not all_dns_failed:
        root_causes.append({
            "severity": "CRITICAL",
            "issue": "TCP Connection Failure",
            "description": "DNS works but cannot establish TCP connections. This indicates a firewall or routing issue.",
            "possible_causes": [
                "Firewall is blocking all outbound connections",
                "Network gateway/router is misconfigured",
                "No default route configured",
                "Corporate firewall blocking all outbound traffic",
                "VPN tunnel is down or misconfigured"
            ],
            "solutions": [
                "Check firewall rules: sudo iptables -L (Linux) or check firewall settings",
                "Verify default route: ip route show or route -n",
                "Check if VPN is connected and working",
                "Test with: telnet google.com 443 (if telnet is available)",
                "Check network gateway: ping your gateway IP"
            ]
        })
    elif google_tcp_failed and not google_dns_failed:
        root_causes.append({
            "severity": "HIGH",
            "issue": "TCP Connection Failure to Google",
            "description": "Can resolve DNS but cannot connect to Google on port 443.",
            "possible_causes": [
                "Firewall blocking HTTPS traffic (port 443)",
                "Proxy required but not configured",
                "Outbound HTTPS is blocked by policy"
            ],
            "solutions": [
                "Check if HTTPS (port 443) is blocked by firewall",
                "Verify proxy settings if behind corporate proxy",
                "Test with: curl -v https://www.google.com"
            ]
        })
    elif some_tcp_failed:
        root_causes.append({
            "severity": "MEDIUM",
            "issue": "Selective TCP Connection Failure",
            "description": f"Some TCP connections failed: {', '.join(tcp_failures)}",
            "possible_causes": [
                "Specific ports or services are blocked",
                "Selective firewall rules",
                "Service-specific blocking (e.g., Slack blocked but Google allowed)"
            ],
            "solutions": [
                "Check which specific services are blocked",
                "Verify if this is intentional (corporate policy)",
                "Test from different network to confirm"
            ]
        })
    
    # Analyze SSL failures
    if len(ssl_failures) > 0:
        if len(ssl_failures) == len(ssl_results):
            root_causes.append({
                "severity": "HIGH",
                "issue": "SSL/TLS Certificate Validation Failure",
                "description": "Cannot validate SSL certificates for any host.",
                "possible_causes": [
                    "System time is incorrect (SSL certificates are time-sensitive)",
                    "Corporate proxy intercepting SSL with self-signed certificates",
                    "SSL certificate store is corrupted or outdated",
                    "Man-in-the-middle proxy/firewall"
                ],
                "solutions": [
                    "Check system time: date (should be accurate)",
                    "If behind corporate proxy, may need to install corporate CA certificate",
                    "Update CA certificate bundle: sudo update-ca-certificates (Linux)",
                    "Check if proxy is doing SSL interception"
                ]
            })
        else:
            root_causes.append({
                "severity": "MEDIUM",
                "issue": "Selective SSL Certificate Failure",
                "description": f"SSL certificate validation failed for: {', '.join(ssl_failures)}",
                "possible_causes": [
                    "Specific domains have certificate issues",
                    "Selective SSL interception by proxy"
                ],
                "solutions": [
                    "Check certificate validity for specific domains",
                    "Verify if proxy is intercepting specific services"
                ]
            })
    
    # Analyze HTTPS failures
    google_https_failed = any("google.com" in str(f) for f in https_failures)
    all_https_failed = len(https_failures) == len(https_results)
    
    if all_https_failed and not all_tcp_failed:
        root_causes.append({
            "severity": "HIGH",
            "issue": "HTTPS Connection Failure",
            "description": "TCP connections work but HTTPS fails. This suggests SSL/TLS or proxy issues.",
            "possible_causes": [
                "SSL/TLS handshake is being blocked or intercepted",
                "Proxy required for HTTPS but not configured correctly",
                "Corporate proxy requires authentication",
                "SSL version mismatch or cipher suite issues"
            ],
            "solutions": [
                "Verify proxy configuration for HTTPS",
                "Check if proxy requires authentication",
                "Test with: curl -v https://www.google.com (shows detailed SSL handshake)",
                "Check SSL/TLS settings and supported protocols"
            ]
        })
    elif google_https_failed and not google_tcp_failed:
        root_causes.append({
            "severity": "MEDIUM",
            "issue": "HTTPS Failure to Google",
            "description": "Can connect via TCP but HTTPS to Google fails.",
            "possible_causes": [
                "Google-specific blocking or routing issue",
                "SSL handshake failing specifically for Google"
            ],
            "solutions": [
                "Test with: curl -v https://www.google.com",
                "Check if Google services are blocked by policy"
            ]
        })
    
    # Analyze Slack-specific failures
    slack_dns_failed = any("slack.com" in str(f) for f in dns_failures)
    slack_tcp_failed = any("slack.com" in str(f) for f in tcp_failures)
    slack_https_failed = any("slack.com" in str(f) for f in https_failures)
    
    if (slack_dns_failed or slack_tcp_failed or slack_https_failed) and not google_dns_failed and not google_tcp_failed:
        root_causes.append({
            "severity": "MEDIUM",
            "issue": "Slack-Specific Blocking",
            "description": "Google services work but Slack connectivity fails. This suggests Slack is specifically blocked.",
            "possible_causes": [
                "Corporate policy blocking Slack/workplace communication tools",
                "Firewall rules blocking Slack domains",
                "Proxy blocking Slack API endpoints",
                "Slack IP ranges blocked by network policy"
            ],
            "solutions": [
                "Check with network administrator about Slack access policies",
                "Verify if Slack is allowed on your network",
                "Test from different network to confirm",
                "Check firewall logs for blocked connections to slack.com"
            ]
        })
    
    # Timeout analysis
    timeout_indicators = ["timed out", "timeout", "Connection timed out"]
    if any("timeout" in str(f).lower() for f in tcp_failures + https_failures):
        root_causes.append({
            "severity": "MEDIUM",
            "issue": "Connection Timeouts",
            "description": "Some connections are timing out before completing.",
            "possible_causes": [
                "Network latency is very high",
                "Firewall is silently dropping packets",
                "Destination servers are overloaded",
                "Network congestion",
                "MTU size issues causing packet fragmentation"
            ],
            "solutions": [
                "Check network latency: ping google.com",
                "Verify firewall isn't silently dropping connections",
                "Test from different network to rule out local issues",
                "Check MTU settings: ping -M do -s 1472 google.com"
            ]
        })
    
    # General network issues if multiple failures
    total_failures = len(dns_failures) + len(tcp_failures) + len(ssl_failures) + len(https_failures)
    if total_failures > 5 and len(root_causes) == 0:
        root_causes.append({
            "severity": "HIGH",
            "issue": "Multiple Network Issues Detected",
            "description": f"Multiple test failures detected ({total_failures} total failures).",
            "possible_causes": [
                "General network connectivity problem",
                "Multiple services blocked",
                "Network misconfiguration"
            ],
            "solutions": [
                "Check overall network connectivity",
                "Verify network interface is up and configured correctly",
                "Check routing table: ip route show or route -n",
                "Contact network administrator"
            ]
        })
    
    return root_causes


def main():
    """Main diagnostic function"""
    # Initialize logging
    log_filename = init_logging()
    
    try:
        print_header("Outbound Connection Diagnostic Tool")
        
        if log_filename:
            print_info(f"Logging results to: {log_filename}")
        
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # System info
        print_header("System Information")
        get_system_info()
        
        # Proxy check
        print_header("Proxy Configuration")
        check_proxy_settings()
        
        # DNS tests
        print_header("DNS Resolution Tests")
        test_hosts = [
            "google.com",
            "8.8.8.8",  # Google DNS (should always resolve)
            "slack.com",
            "api.slack.com",
        ]
        
        dns_results = {}
        for host in test_hosts:
            if host.replace('.', '').isdigit():
                # IP address, skip DNS test
                print_info(f"Skipping DNS test for IP address {host}")
                dns_results[host] = True
            else:
                success, ips = test_dns_resolution(host)
                dns_results[host] = success
                if ips:
                    time.sleep(0.5)  # Small delay between tests
        
        # TCP connectivity tests
        print_header("TCP Connectivity Tests")
        tcp_tests = [
            ("google.com", 443),
            ("8.8.8.8", 53),  # Google DNS
            ("slack.com", 443),
            ("api.slack.com", 443),
        ]
        
        tcp_results = {}
        for host, port in tcp_tests:
            success = test_tcp_connection(host, port)
            tcp_results[f"{host}:{port}"] = success
            time.sleep(0.5)
        
        # SSL certificate tests
        print_header("SSL Certificate Tests")
        ssl_tests = ["google.com", "slack.com", "api.slack.com"]
        ssl_results = {}
        for host in ssl_tests:
            success = test_ssl_certificate(host)
            ssl_results[host] = success
            time.sleep(0.5)
        
        # HTTPS connectivity tests
        print_header("HTTPS Connectivity Tests")
        https_tests = [
            "https://www.google.com",
            "https://slack.com",
            "https://api.slack.com",
        ]
        
        https_results = {}
        for url in https_tests:
            success, status = test_https_connection(url)
            https_results[url] = success
            time.sleep(0.5)
        
        # Slack API specific test (additional check for Slack tools)
        print_header("Slack API Connectivity Test (Additional)")
        slack_api_result = test_slack_api()
        
        # Summary
        print_header("Diagnostic Summary")
        
        total_tests = len(dns_results) + len(tcp_results) + len(ssl_results) + len(https_results) + 1
        passed_tests = (
            sum(1 for v in dns_results.values() if v) +
            sum(1 for v in tcp_results.values() if v) +
            sum(1 for v in ssl_results.values() if v) +
            sum(1 for v in https_results.values() if v) +
            (1 if slack_api_result else 0)
        )
        
        print(f"\nTests Passed: {passed_tests}/{total_tests}")
        
        if passed_tests == total_tests:
            print_success("All connectivity tests passed!")
            print_info("Your outbound connections appear to be working correctly.")
        else:
            print_warning("Some connectivity tests failed.")
            
            # Run diagnostic analysis
            root_causes = analyze_failures(dns_results, tcp_results, ssl_results, https_results, slack_api_result)
            
            if root_causes:
                print_header("Root Cause Analysis")
                
                # Sort by severity
                severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
                root_causes.sort(key=lambda x: severity_order.get(x.get("severity", "MEDIUM"), 2))
                
                for i, cause in enumerate(root_causes, 1):
                    severity = cause.get("severity", "UNKNOWN")
                    issue = cause.get("issue", "Unknown Issue")
                    description = cause.get("description", "")
                    possible_causes = cause.get("possible_causes", [])
                    solutions = cause.get("solutions", [])
                    
                    # Color code severity
                    if severity == "CRITICAL":
                        severity_color = RED
                    elif severity == "HIGH":
                        severity_color = YELLOW
                    else:
                        severity_color = YELLOW
                    
                    print(f"\n{i}. {severity_color}[{severity}]{RESET} {issue}")
                    print_info(f"   {description}")
                    
                    if possible_causes:
                        print_info("   Possible causes:")
                        for pc in possible_causes:
                            print_info(f"     • {pc}")
                    
                    if solutions:
                        print_info("   Recommended solutions:")
                        for sol in solutions:
                            print_info(f"     • {sol}")
            else:
                print_info("\nGeneral troubleshooting suggestions:")
                print_info("1. Check your firewall settings")
                print_info("2. Verify proxy configuration (if using a proxy)")
                print_info("3. Check network connectivity: ping google.com")
                print_info("4. Verify DNS resolution: nslookup google.com")
                print_info("5. Check if you're behind a corporate firewall/VPN")
                print_info("6. Try disabling VPN/firewall temporarily to test")
        
        print(f"\nCompleted at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        if log_filename:
            print_info(f"Results saved to: {log_filename}\n")
        
        return 0 if passed_tests == total_tests else 1
    finally:
        close_logging()


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        close_logging()
        sys.exit(130)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        close_logging()
        sys.exit(1)


