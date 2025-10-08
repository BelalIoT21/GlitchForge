"""
Scanner Module
Orchestrates all vulnerability scanners
"""

from .sql_injection import SQLInjectionScanner
from .xss import XSSScanner
from .csrf import CSRFScanner

__all__ = ['SQLInjectionScanner', 'XSSScanner', 'CSRFScanner', 'VulnerabilityScanner']


import requests
import re
from typing import Dict, List
from config import DVWA_CONFIG

class VulnerabilityScanner:
    """
    Main scanner orchestrator that runs all vulnerability tests
    """
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'GlitchForge/1.0'
        })
        
        # Initialize individual scanners
        self.sql_scanner = SQLInjectionScanner(self.session)
        self.xss_scanner = XSSScanner(self.session)
        self.csrf_scanner = CSRFScanner(self.session)
        
        self.scan_results = []
        
    def login_dvwa(self, username: str = None, password: str = None) -> bool:
        """Login to DVWA and maintain session"""
        username = username or DVWA_CONFIG['username']
        password = password or DVWA_CONFIG['password']
        
        login_url = f"{DVWA_CONFIG['base_url']}/login.php"
        
        try:
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
            
            if success:
                print(f"✓ Successfully logged in as {username}")
            
            return success
            
        except requests.RequestException as e:
            print(f"✗ Login failed: {e}")
            return False
    
    def set_security_level(self, level: str = 'low') -> bool:
        """Set DVWA security level"""
        security_url = f"{DVWA_CONFIG['base_url']}/security.php"
        
        try:
            # Get current page to extract token
            response = self.session.get(security_url)
            token_match = re.search(r'user_token.*?value=["\']([^"\']+)', response.text)
            
            data = {
                'security': level,
                'seclev_submit': 'Submit'
            }
            
            if token_match:
                data['user_token'] = token_match.group(1)
            
            response = self.session.post(security_url, data=data)
            
            success = level in response.text.lower()
            
            if success:
                print(f"✓ Security level set to: {level}")
            
            return success
            
        except requests.RequestException as e:
            print(f"✗ Failed to set security level: {e}")
            return False
    
    def scan_sql_injection(self, endpoint: str, parameter: str) -> Dict:
        """Run SQL injection scan"""
        print(f"\n[*] Testing SQL Injection on {endpoint}...")
        
        full_url = f"{DVWA_CONFIG['base_url']}/{endpoint}"
        result = self.sql_scanner.detect(full_url, parameter)
        
        result['endpoint'] = endpoint
        result['parameter'] = parameter
        result['scan_type'] = 'sql_injection'
        
        self.scan_results.append(result)
        
        return result
    
    def scan_xss(self, endpoint: str, parameter: str) -> Dict:
        """Run XSS scan"""
        print(f"\n[*] Testing XSS on {endpoint}...")
        
        full_url = f"{DVWA_CONFIG['base_url']}/{endpoint}"
        result = self.xss_scanner.detect(full_url, parameter)
        
        result['endpoint'] = endpoint
        result['parameter'] = parameter
        result['scan_type'] = 'xss'
        
        self.scan_results.append(result)
        
        return result
    
    def scan_csrf(self, endpoint: str) -> Dict:
        """Run CSRF scan"""
        print(f"\n[*] Testing CSRF on {endpoint}...")
        
        full_url = f"{DVWA_CONFIG['base_url']}/{endpoint}"
        result = self.csrf_scanner.detect(full_url)
        
        result['endpoint'] = endpoint
        result['scan_type'] = 'csrf'
        
        self.scan_results.append(result)
        
        return result
    
    def scan_all(self) -> List[Dict]:
        """Run all vulnerability scans on common DVWA endpoints"""
        print("\n" + "="*60)
        print("  GlitchForge - Comprehensive Vulnerability Scan")
        print("="*60)
        
        # SQL Injection tests
        self.scan_sql_injection('vulnerabilities/sqli/', 'id')
        self.scan_sql_injection('vulnerabilities/sqli_blind/', 'id')
        
        # XSS tests
        self.scan_xss('vulnerabilities/xss_r/', 'name')
        self.scan_xss('vulnerabilities/xss_s/', 'txtName')
        
        # CSRF tests
        self.scan_csrf('vulnerabilities/csrf/')
        
        return self.scan_results
    
    def get_summary(self) -> Dict:
        """Get summary of all scan results"""
        summary = {
            'total_scans': len(self.scan_results),
            'vulnerabilities_found': 0,
            'high_confidence': 0,
            'medium_confidence': 0,
            'low_confidence': 0,
            'by_type': {
                'sql_injection': 0,
                'xss': 0,
                'csrf': 0
            }
        }
        
        for result in self.scan_results:
            if result['vulnerable']:
                summary['vulnerabilities_found'] += 1
                
                if result['confidence'] == 'high':
                    summary['high_confidence'] += 1
                elif result['confidence'] == 'medium':
                    summary['medium_confidence'] += 1
                elif result['confidence'] == 'low':
                    summary['low_confidence'] += 1
                
                scan_type = result['scan_type']
                summary['by_type'][scan_type] += 1
        
        return summary