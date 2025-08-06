# Network and Connectivity Issues

This guide addresses network-related problems that can affect Nginx Security Monitor's operation,
including connectivity issues, firewall problems, and integration failures.

## Network Diagnostic Tools

### Comprehensive Network Diagnostics

```python
#!/usr/bin/env python3
# scripts/network_diagnostics.py

import socket
import subprocess
import requests
import time
import json
import urllib.parse
from typing import Dict, List, Optional, Tuple

class NetworkDiagnostics:
    def __init__(self):
        self.nsm_host = "localhost"
        self.nsm_port = 8080
        self.results = {}
    
    def run_full_diagnostics(self) -> Dict:
        """Run comprehensive network diagnostics"""
        print("🌐 Running network diagnostics for Nginx Security Monitor...")
        
        diagnostics = [
            ("Local Service Connectivity", self.test_local_connectivity),
            ("Port Availability", self.test_port_availability),
            ("Firewall Rules", self.test_firewall_rules),
            ("DNS Resolution", self.test_dns_resolution),
            ("External Connectivity", self.test_external_connectivity),
            ("Integration Endpoints", self.test_integration_endpoints),
            ("Network Performance", self.test_network_performance),
            ("SSL/TLS Configuration", self.test_ssl_configuration)
        ]
        
        for test_name, test_func in diagnostics:
            print(f"\n🔍 Testing {test_name}...")
            try:
                result = test_func()
                self.results[test_name] = result
                
                if result.get('status') == 'success':
                    print(f"   ✅ {result.get('message', 'OK')}")
                elif result.get('status') == 'warning':
                    print(f"   ⚠️  {result.get('message', 'Warning')}")
                else:
                    print(f"   ❌ {result.get('message', 'Failed')}")
                    
            except Exception as e:
                error_result = {
                    'status': 'error',
                    'message': f"Test failed with exception: {str(e)}",
                    'exception': str(e)
                }
                self.results[test_name] = error_result
                print(f"   ❌ Error: {e}")
        
        return self.results
    
    def test_local_connectivity(self) -> Dict:
        """Test local service connectivity"""
        try:
            # Test basic socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.nsm_host, self.nsm_port))
            sock.close()
            
            if result != 0:
                return {
                    'status': 'error',
                    'message': f"Cannot connect to {self.nsm_host}:{self.nsm_port}",
                    'error_code': result
                }
            
            # Test HTTP connectivity
            response = requests.get(f"http://{self.nsm_host}:{self.nsm_port}/health", timeout=5)
            
            return {
                'status': 'success',
                'message': f"Service responding on {self.nsm_host}:{self.nsm_port}",
                'response_time': response.elapsed.total_seconds(),
                'status_code': response.status_code
            }
            
        except requests.exceptions.RequestException as e:
            return {
                'status': 'error',
                'message': f"HTTP request failed: {str(e)}",
                'error': str(e)
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': f"Connection test failed: {str(e)}",
                'error': str(e)
            }
    
    def test_port_availability(self) -> Dict:
        """Test port availability and conflicts"""
        try:
            # Check if port is in use
            result = subprocess.run(['netstat', '-tlnp'], capture_output=True, text=True)
            
            port_line = None
            for line in result.stdout.split('\n'):
                if f':{self.nsm_port}' in line and 'LISTEN' in line:
                    port_line = line
                    break
            
            if not port_line:
                return {
                    'status': 'error',
                    'message': f"Port {self.nsm_port} is not listening",
                    'suggestion': 'Check if NSM service is running'
                }
            
            # Extract process information
            parts = port_line.split()
            if len(parts) >= 7:
                process_info = parts[6]
                if 'nginx-security-monitor' in process_info or 'python' in process_info:
                    return {
                        'status': 'success',
                        'message': f"Port {self.nsm_port} is correctly bound to NSM",
                        'process': process_info
                    }
                else:
                    return {
                        'status': 'warning',
                        'message': f"Port {self.nsm_port} is bound to different process: {process_info}",
                        'process': process_info
                    }
            
            return {
                'status': 'success',
                'message': f"Port {self.nsm_port} is listening",
                'details': port_line.strip()
            }
            
        except subprocess.SubprocessError as e:
            return {
                'status': 'error',
                'message': f"Cannot check port status: {str(e)}",
                'error': str(e)
            }
    
    def test_firewall_rules(self) -> Dict:
        """Test firewall configuration"""
        firewall_tests = []
        
        # Test UFW (Ubuntu/Debian)
        try:
            result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
            if result.returncode == 0:
                ufw_output = result.stdout
                if 'Status: active' in ufw_output:
                    if f'{self.nsm_port}' in ufw_output:
                        firewall_tests.append(f"UFW: Port {self.nsm_port} is allowed")
                    else:
                        firewall_tests.append(f"UFW: Port {self.nsm_port} may be blocked")
                else:
                    firewall_tests.append("UFW: Firewall is inactive")
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        
        # Test iptables
        try:
            result = subprocess.run(['iptables', '-L', 'INPUT'], capture_output=True, text=True)
            if result.returncode == 0:
                if 'ACCEPT' in result.stdout or 'policy ACCEPT' in result.stdout:
                    firewall_tests.append("iptables: Basic rules detected")
                else:
                    firewall_tests.append("iptables: Restrictive rules may be blocking traffic")
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        
        # Test firewalld (CentOS/RHEL)
        try:
            result = subprocess.run(['firewall-cmd', '--state'], capture_output=True, text=True)
            if result.returncode == 0 and 'running' in result.stdout:
                # Check if port is open
                port_result = subprocess.run([
                    'firewall-cmd', '--query-port', f'{self.nsm_port}/tcp'
                ], capture_output=True, text=True)
                
                if port_result.returncode == 0:
                    firewall_tests.append(f"firewalld: Port {self.nsm_port} is open")
                else:
                    firewall_tests.append(f"firewalld: Port {self.nsm_port} may be blocked")
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        
        if not firewall_tests:
            return {
                'status': 'warning',
                'message': 'No firewall configuration detected',
                'suggestion': 'Consider enabling a firewall for security'
            }
        
        return {
            'status': 'success',
            'message': 'Firewall configuration checked',
            'details': firewall_tests
        }
    
    def test_dns_resolution(self) -> Dict:
        """Test DNS resolution for external services"""
        test_domains = [
            'github.com',
            'api.github.com',
            'security-feeds.example.com'  # Replace with actual threat feed domains
        ]
        
        resolution_results = []
        failed_domains = []
        
        for domain in test_domains:
            try:
                ip_address = socket.gethostbyname(domain)
                resolution_results.append(f"{domain} -> {ip_address}")
            except socket.gaierror as e:
                failed_domains.append(f"{domain}: {str(e)}")
        
        if failed_domains:
            return {
                'status': 'warning',
                'message': f"DNS resolution failed for {len(failed_domains)} domains",
                'failed_domains': failed_domains,
                'successful': resolution_results
            }
        
        return {
            'status': 'success',
            'message': f"DNS resolution successful for {len(test_domains)} domains",
            'resolutions': resolution_results
        }
    
    def test_external_connectivity(self) -> Dict:
        """Test external HTTP/HTTPS connectivity"""
        test_urls = [
            'https://httpbin.org/get',
            'https://api.github.com',
            'https://www.google.com'
        ]
        
        connectivity_results = []
        failed_urls = []
        
        for url in test_urls:
            try:
                start_time = time.time()
                response = requests.get(url, timeout=10)
                response_time = time.time() - start_time
                
                if response.status_code == 200:
                    connectivity_results.append({
                        'url': url,
                        'status': 'success',
                        'response_time': round(response_time, 3),
                        'status_code': response.status_code
                    })
                else:
                    failed_urls.append({
                        'url': url,
                        'error': f"HTTP {response.status_code}",
                        'response_time': round(response_time, 3)
                    })
                    
            except requests.exceptions.RequestException as e:
                failed_urls.append({
                    'url': url,
                    'error': str(e)
                })
        
        if failed_urls:
            return {
                'status': 'warning',
                'message': f"External connectivity issues detected",
                'failed': failed_urls,
                'successful': connectivity_results
            }
        
        return {
            'status': 'success',
            'message': f"External connectivity working for {len(test_urls)} URLs",
            'results': connectivity_results
        }
    
    def test_integration_endpoints(self) -> Dict:
        """Test integration endpoint connectivity"""
        try:
            # Get integration configuration from NSM
            response = requests.get(
                f"http://{self.nsm_host}:{self.nsm_port}/integrations/config", 
                timeout=5
            )
            
            if response.status_code != 200:
                return {
                    'status': 'error',
                    'message': 'Cannot retrieve integration configuration'
                }
            
            config = response.json()
            integration_tests = []
            
            # Test webhook endpoints
            if config.get('webhook', {}).get('enabled'):
                webhook_url = config['webhook'].get('url')
                if webhook_url:
                    try:
                        # Test with HEAD request to avoid triggering alerts
                        test_response = requests.head(webhook_url, timeout=10)
                        integration_tests.append({
                            'type': 'webhook',
                            'url': webhook_url,
                            'status': 'reachable' if test_response.status_code < 500 else 'error',
                            'status_code': test_response.status_code
                        })
                    except requests.exceptions.RequestException as e:
                        integration_tests.append({
                            'type': 'webhook',
                            'url': webhook_url,
                            'status': 'unreachable',
                            'error': str(e)
                        })
            
            # Test email server connectivity
            if config.get('email', {}).get('enabled'):
                smtp_server = config['email'].get('smtp_server')
                smtp_port = config['email'].get('port', 587)
                
                if smtp_server:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(10)
                        result = sock.connect_ex((smtp_server, smtp_port))
                        sock.close()
                        
                        integration_tests.append({
                            'type': 'email',
                            'server': f"{smtp_server}:{smtp_port}",
                            'status': 'reachable' if result == 0 else 'unreachable',
                            'error_code': result if result != 0 else None
                        })
                    except Exception as e:
                        integration_tests.append({
                            'type': 'email',
                            'server': f"{smtp_server}:{smtp_port}",
                            'status': 'error',
                            'error': str(e)
                        })
            
            if not integration_tests:
                return {
                    'status': 'success',
                    'message': 'No external integrations configured'
                }
            
            failed_integrations = [t for t in integration_tests if t['status'] in ['unreachable', 'error']]
            
            if failed_integrations:
                return {
                    'status': 'warning',
                    'message': f"{len(failed_integrations)} integration(s) unreachable",
                    'failed': failed_integrations,
                    'all_tests': integration_tests
                }
            
            return {
                'status': 'success',
                'message': f"All {len(integration_tests)} integrations reachable",
                'tests': integration_tests
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'message': f"Integration endpoint test failed: {str(e)}",
                'error': str(e)
            }
    
    def test_network_performance(self) -> Dict:
        """Test network performance metrics"""
        try:
            # Test latency to NSM service
            latencies = []
            for _ in range(5):
                start_time = time.time()
                response = requests.get(f"http://{self.nsm_host}:{self.nsm_port}/health", timeout=5)
                latency = (time.time() - start_time) * 1000  # Convert to milliseconds
                latencies.append(latency)
                time.sleep(0.1)
            
            avg_latency = sum(latencies) / len(latencies)
            max_latency = max(latencies)
            min_latency = min(latencies)
            
            # Determine performance status
            if avg_latency > 1000:  # > 1 second
                status = 'error'
                message = f"High latency detected: {avg_latency:.1f}ms average"
            elif avg_latency > 500:  # > 500ms
                status = 'warning'
                message = f"Moderate latency: {avg_latency:.1f}ms average"
            else:
                status = 'success'
                message = f"Good performance: {avg_latency:.1f}ms average"
            
            return {
                'status': status,
                'message': message,
                'metrics': {
                    'average_latency_ms': round(avg_latency, 1),
                    'min_latency_ms': round(min_latency, 1),
                    'max_latency_ms': round(max_latency, 1),
                    'measurements': len(latencies)
                }
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'message': f"Performance test failed: {str(e)}",
                'error': str(e)
            }
    
    def test_ssl_configuration(self) -> Dict:
        """Test SSL/TLS configuration if HTTPS is enabled"""
        try:
            # Check if HTTPS is configured
            response = requests.get(
                f"http://{self.nsm_host}:{self.nsm_port}/config/security",
                timeout=5
            )
            
            if response.status_code != 200:
                return {
                    'status': 'warning',
                    'message': 'Cannot check SSL configuration'
                }
            
            config = response.json()
            
            if not config.get('https_enabled', False):
                return {
                    'status': 'success',
                    'message': 'HTTPS not enabled (HTTP only)'
                }
            
            # Test HTTPS endpoint
            https_port = config.get('https_port', 8443)
            try:
                https_response = requests.get(
                    f"https://{self.nsm_host}:{https_port}/health",
                    timeout=5,
                    verify=True  # Verify SSL certificate
                )
                
                return {
                    'status': 'success',
                    'message': f"HTTPS working on port {https_port}",
                    'ssl_verified': True
                }
                
            except requests.exceptions.SSLError as e:
                return {
                    'status': 'warning',
                    'message': f"SSL certificate issue: {str(e)}",
                    'https_port': https_port,
                    'ssl_error': str(e)
                }
            except requests.exceptions.RequestException as e:
                return {
                    'status': 'error',
                    'message': f"HTTPS connection failed: {str(e)}",
                    'https_port': https_port,
                    'error': str(e)
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'message': f"SSL test failed: {str(e)}",
                'error': str(e)
            }
    
    def generate_report(self) -> str:
        """Generate a comprehensive network diagnostic report"""
        report = []
        report.append("="*60)
        report.append("NGINX SECURITY MONITOR - NETWORK DIAGNOSTIC REPORT")
        report.append("="*60)
        report.append(f"Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # Summary
        total_tests = len(self.results)
        successful_tests = len([r for r in self.results.values() if r.get('status') == 'success'])
        warning_tests = len([r for r in self.results.values() if r.get('status') == 'warning'])
        failed_tests = len([r for r in self.results.values() if r.get('status') in ['error', 'failed']])
        
        report.append("SUMMARY:")
        report.append(f"  Total Tests: {total_tests}")
        report.append(f"  Successful: {successful_tests}")
        report.append(f"  Warnings: {warning_tests}")
        report.append(f"  Failed: {failed_tests}")
        report.append("")
        
        # Detailed results
        for test_name, result in self.results.items():
            status_emoji = {
                'success': '✅',
                'warning': '⚠️',
                'error': '❌',
                'failed': '❌'
            }.get(result.get('status', 'unknown'), '❓')
            
            report.append(f"{status_emoji} {test_name.upper()}:")
            report.append(f"   Status: {result.get('status', 'unknown')}")
            report.append(f"   Message: {result.get('message', 'No message')}")
            
            # Add additional details if available
            for key, value in result.items():
                if key not in ['status', 'message']:
                    if isinstance(value, (list, dict)):
                        report.append(f"   {key.title()}: {json.dumps(value, indent=6)}")
                    else:
                        report.append(f"   {key.title()}: {value}")
            
            report.append("")
        
        # Recommendations
        report.append("RECOMMENDATIONS:")
        recommendations = self.generate_recommendations()
        for rec in recommendations:
            report.append(f"  • {rec}")
        
        return "\n".join(report)
    
    def generate_recommendations(self) -> List[str]:
        """Generate recommendations based on test results"""
        recommendations = []
        
        if self.results.get('Local Service Connectivity', {}).get('status') != 'success':
            recommendations.append("Check if NSM service is running: sudo systemctl status nginx-security-monitor")
        
        if self.results.get('Firewall Rules', {}).get('status') == 'warning':
            recommendations.append(f"Consider opening port {self.nsm_port} in firewall: sudo ufw allow {self.nsm_port}")
        
        if self.results.get('External Connectivity', {}).get('status') != 'success':
            recommendations.append("Check internet connectivity and proxy settings")
        
        if self.results.get('Integration Endpoints', {}).get('status') == 'warning':
            recommendations.append("Review integration configurations and endpoint availability")
        
        if self.results.get('Network Performance', {}).get('status') in ['warning', 'error']:
            recommendations.append("Investigate network latency issues and system performance")
        
        if not recommendations:
            recommendations.append("Network configuration appears to be working correctly")
        
        return recommendations

def main():
    diagnostics = NetworkDiagnostics()
    results = diagnostics.run_full_diagnostics()
    
    print("\n" + "="*60)
    print("NETWORK DIAGNOSTIC COMPLETE")
    print("="*60)
    
    # Generate and save report
    report = diagnostics.generate_report()
    
    # Save to file
    with open('/tmp/nsm-network-diagnostics.txt', 'w') as f:
        f.write(report)
    
    print(f"📋 Detailed report saved to: /tmp/nsm-network-diagnostics.txt")
    
    # Show summary
    failed_tests = [name for name, result in results.items() 
                   if result.get('status') in ['error', 'failed']]
    
    if not failed_tests:
        print("🎉 All network tests passed!")
    else:
        print(f"⚠️  {len(failed_tests)} test(s) failed:")
        for test_name in failed_tests:
            print(f"   • {test_name}")

if __name__ == "__main__":
    main()
```

## Common Network Issues

### 1. Port Binding Issues

#### Port Already in Use

**Error Messages:**

```text
[Errno 98] Address already in use
OSError: [Errno 98] Address already in use: ('0.0.0.0', 8080)
bind: Address already in use
```

**Diagnosis and Solutions:**

```bash
# Find what's using the port
sudo lsof -i :8080
sudo netstat -tlnp | grep :8080

# Kill the conflicting process
sudo kill -9 <PID>

# Or change NSM port in configuration
sudo vim /opt/nginx-security-monitor/config/settings.yaml
# Change: port: 8081

# Restart NSM service
sudo systemctl restart nginx-security-monitor
```

#### Permission Denied on Port Binding

**Error Messages:**

```text
[Errno 13] Permission denied
bind: Permission denied
```

**Solutions:**

```bash
# Option 1: Use port > 1024 (recommended)
# Edit config to use port 8080 instead of 80

# Option 2: Grant CAP_NET_BIND_SERVICE capability
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/nginx-security-monitor

# Option 3: Run with sudo (not recommended for production)
sudo systemctl edit nginx-security-monitor
# Add:
# [Service]
# User=root
# Group=root
```

### 2. Firewall Configuration Issues

#### UFW (Ubuntu/Debian)

```bash
# Check current UFW status
sudo ufw status verbose

# Allow NSM port
sudo ufw allow 8080/tcp

# Allow from specific networks only
sudo ufw allow from 10.0.0.0/8 to any port 8080
sudo ufw allow from 192.168.0.0/16 to any port 8080

# Enable UFW if not active
sudo ufw enable

# Check NSM service after firewall changes
curl http://localhost:8080/health
```

#### iptables

```bash
# Check current iptables rules
sudo iptables -L -n

# Allow NSM port
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT

# Save rules (Ubuntu/Debian)
sudo iptables-save > /etc/iptables/rules.v4

# Save rules (CentOS/RHEL)
sudo service iptables save
```

#### firewalld (CentOS/RHEL/Fedora)

```bash
# Check firewalld status
sudo firewall-cmd --state

# Open NSM port permanently
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload

# Or add a service definition
sudo firewall-cmd --permanent --new-service=nginx-security-monitor
sudo firewall-cmd --permanent --service=nginx-security-monitor --set-description="Nginx Security Monitor"
sudo firewall-cmd --permanent --service=nginx-security-monitor --add-port=8080/tcp
sudo firewall-cmd --permanent --add-service=nginx-security-monitor
sudo firewall-cmd --reload
```

### 3. Integration Connectivity Issues

#### Webhook Integration Failures

**Common Issues:**

```python
# Test webhook connectivity
#!/usr/bin/env python3

import requests
import json
import ssl
from urllib.parse import urlparse

def test_webhook(webhook_url, test_payload=None):
    """Test webhook connectivity and response"""
    
    if test_payload is None:
        test_payload = {
            "test": True,
            "timestamp": "2025-01-20T10:00:00Z",
            "source": "nsm-connectivity-test"
        }
    
    print(f"🔗 Testing webhook: {webhook_url}")
    
    # Parse URL to check for common issues
    parsed = urlparse(webhook_url)
    
    if not parsed.scheme:
        print("❌ URL missing scheme (http:// or https://)")
        return False
    
    if not parsed.netloc:
        print("❌ URL missing host")
        return False
    
    try:
        # Test with timeout
        response = requests.post(
            webhook_url,
            json=test_payload,
            timeout=30,
            headers={
                'Content-Type': 'application/json',
                'User-Agent': 'nginx-security-monitor/1.0'
            }
        )
        
        print(f"✅ Response: {response.status_code}")
        
        if response.status_code == 200:
            print("✅ Webhook is working correctly")
            return True
        elif response.status_code == 404:
            print("❌ Webhook endpoint not found (404)")
        elif response.status_code == 401:
            print("❌ Authentication required (401)")
        elif response.status_code == 403:
            print("❌ Access forbidden (403)")
        elif response.status_code >= 500:
            print(f"❌ Server error ({response.status_code})")
        else:
            print(f"⚠️  Unexpected status code: {response.status_code}")
        
        return False
        
    except requests.exceptions.SSLError as e:
        print(f"❌ SSL/TLS error: {e}")
        print("💡 Try: Check certificate validity or disable SSL verification")
        return False
        
    except requests.exceptions.ConnectionError as e:
        print(f"❌ Connection error: {e}")
        print("💡 Try: Check URL, firewall, and network connectivity")
        return False
        
    except requests.exceptions.Timeout as e:
        print(f"❌ Timeout error: {e}")
        print("💡 Try: Increase timeout or check server response time")
        return False
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

# Example usage
webhook_urls = [
    "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
    "https://discord.com/api/webhooks/YOUR/WEBHOOK/URL",
    "https://your-server.com/nsm-alerts"
]

for url in webhook_urls:
    test_webhook(url)
    print("-" * 50)
```

#### Email Integration Issues

```python
#!/usr/bin/env python3
# Test email integration

import smtplib
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def test_email_integration(smtp_server, port, username, password, use_tls=True):
    """Test email server connectivity and authentication"""
    
    print(f"📧 Testing email integration: {smtp_server}:{port}")
    
    try:
        # Test basic connectivity
        print("🔍 Testing server connectivity...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        result = sock.connect_ex((smtp_server, port))
        sock.close()
        
        if result != 0:
            print(f"❌ Cannot connect to {smtp_server}:{port}")
            return False
        
        print("✅ Server is reachable")
        
        # Test SMTP connection
        print("🔍 Testing SMTP connection...")
        
        if port == 465:  # SSL
            server = smtplib.SMTP_SSL(smtp_server, port, timeout=10)
        else:
            server = smtplib.SMTP(smtp_server, port, timeout=10)
            if use_tls and port != 465:
                server.starttls()
        
        print("✅ SMTP connection established")
        
        # Test authentication
        if username and password:
            print("🔍 Testing authentication...")
            try:
                server.login(username, password)
                print("✅ Authentication successful")
            except smtplib.SMTPAuthenticationError as e:
                print(f"❌ Authentication failed: {e}")
                server.quit()
                return False
        
        # Test sending (dry run)
        print("🔍 Testing message composition...")
        
        msg = MIMEMultipart()
        msg['From'] = username or 'nsm@localhost'
        msg['To'] = username or 'admin@localhost'
        msg['Subject'] = 'NSM Connectivity Test'
        
        body = "This is a test message from Nginx Security Monitor connectivity test."
        msg.attach(MIMEText(body, 'plain'))
        
        print("✅ Message composition successful")
        print("ℹ️  Not sending test email to avoid spam")
        
        server.quit()
        print("✅ Email integration test completed successfully")
        return True
        
    except socket.gaierror as e:
        print(f"❌ DNS resolution failed: {e}")
        return False
        
    except socket.timeout:
        print(f"❌ Connection timeout to {smtp_server}:{port}")
        return False
        
    except smtplib.SMTPException as e:
        print(f"❌ SMTP error: {e}")
        return False
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

# Common email provider settings for testing
email_providers = {
    'gmail': {
        'smtp_server': 'smtp.gmail.com',
        'port': 587,
        'use_tls': True
    },
    'outlook': {
        'smtp_server': 'smtp-mail.outlook.com',
        'port': 587,
        'use_tls': True
    },
    'yahoo': {
        'smtp_server': 'smtp.mail.yahoo.com',
        'port': 587,
        'use_tls': True
    }
}

# Test with your configuration
# test_email_integration(
#     smtp_server="your-smtp-server.com",
#     port=587,
#     username="your-username",
#     password="your-password"
# )
```

### 4. Proxy and NAT Issues

#### Proxy Configuration

```bash
# Set proxy environment variables
export http_proxy=http://proxy.company.com:8080
export https_proxy=http://proxy.company.com:8080
export no_proxy=localhost,127.0.0.1,10.0.0.0/8,192.168.0.0/16

# Configure for NSM service
sudo systemctl edit nginx-security-monitor
# Add:
# [Service]
# Environment="http_proxy=http://proxy.company.com:8080"
# Environment="https_proxy=http://proxy.company.com:8080"
# Environment="no_proxy=localhost,127.0.0.1"

# Test proxy connectivity
curl -x http://proxy.company.com:8080 https://api.github.com

# Configure proxy in NSM config
cat >> /opt/nginx-security-monitor/config/settings.yaml << EOF
network:
  proxy:
    http: "http://proxy.company.com:8080"
    https: "http://proxy.company.com:8080"
    no_proxy: ["localhost", "127.0.0.1", "10.0.0.0/8"]
EOF
```

#### NAT and Load Balancer Issues

```yaml
# Load balancer health check configuration
# /etc/nginx/sites-available/nsm-lb

upstream nsm_backend {
    server 10.0.1.10:8080;
    server 10.0.1.11:8080;
    server 10.0.1.12:8080;
}

server {
    listen 80;
    server_name nsm.company.com;
    
    location /health {
        proxy_pass http://nsm_backend/health;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Health check specific settings
        proxy_connect_timeout 5s;
        proxy_send_timeout 5s;
        proxy_read_timeout 5s;
    }
    
    location / {
        proxy_pass http://nsm_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support for real-time features
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### 5. DNS and Service Discovery Issues

#### DNS Resolution Problems

```bash
# Test DNS resolution
nslookup api.github.com
dig api.github.com

# Check DNS servers
cat /etc/resolv.conf

# Test with different DNS servers
nslookup api.github.com 8.8.8.8
nslookup api.github.com 1.1.1.1

# Fix DNS issues
# Option 1: Use reliable DNS servers
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
echo "nameserver 1.1.1.1" | sudo tee -a /etc/resolv.conf

# Option 2: Configure systemd-resolved
sudo systemctl enable systemd-resolved
sudo systemctl start systemd-resolved
sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
```

#### Service Discovery Configuration

```yaml
# NSM configuration for service discovery
service_discovery:
  enabled: true
  method: "consul"  # consul, etcd, dns
  
  consul:
    endpoints: ["consul.service.consul:8500"]
    service_name: "nginx-security-monitor"
    health_check:
      http: "http://localhost:8080/health"
      interval: "10s"
      timeout: "3s"
  
  dns:
    domain: "nsm.service.consul"
    port: 8080
```

______________________________________________________________________

**Related Documentation:**

- [Common Issues](common-issues.md)
- [Installation Issues](installation-issues.md)
- [Configuration Guide](../CONFIGURATION.md)
- [Operations Guide](../OPERATIONS_GUIDE.md)
- [Security Features](../SECURITY_FEATURES.md)
