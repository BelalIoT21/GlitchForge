"""
Cross-Site Request Forgery (CSRF) Detection Module
"""

import requests
import re
from typing import Dict, List
from bs4 import BeautifulSoup
from config import SCANNER_CONFIG

class CSRFScanner:
    def __init__(self, session: requests.Session):
        self.session = session
        self.timeout = SCANNER_CONFIG['timeout']
        
    def detect(self, url: str) -> Dict:
        """
        Detect CSRF vulnerabilities by analyzing forms
        """
        results = {
            'vulnerable': False,
            'confidence': 'none',
            'vulnerability_type': 'Cross-Site Request Forgery (CSRF)',
            'cwe_id': 'CWE-352',
            'forms_analyzed': 0,
            'vulnerable_forms': [],
            'details': {}
        }
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all forms
            forms = soup.find_all('form')
            results['forms_analyzed'] = len(forms)
            
            for idx, form in enumerate(forms):
                form_analysis = self._analyze_form(form, url)
                
                if form_analysis['vulnerable']:
                    results['vulnerable_forms'].append(form_analysis)
            
            # Calculate overall confidence
            results = self._calculate_confidence(results)
            
        except requests.RequestException as e:
            print(f"Error detecting CSRF: {e}")
            
        return results
    
    def _analyze_form(self, form, base_url: str) -> Dict:
        """Analyze a single form for CSRF protection"""
        analysis = {
            'vulnerable': False,
            'confidence': 'none',
            'action': form.get('action', ''),
            'method': form.get('method', 'get').upper(),
            'has_csrf_token': False,
            'token_details': {},
            'issues': []
        }
        
        # Check if form is state-changing (POST method)
        if analysis['method'] == 'GET':
            analysis['issues'].append('Uses GET for potentially state-changing operation')
        
        # Look for CSRF tokens
        csrf_token_names = [
            'csrf_token', 'csrf', '_csrf', 'token', 
            'authenticity_token', '_token', 'user_token',
            'anti_csrf', 'xsrf_token', '__requestverificationtoken'
        ]
        
        inputs = form.find_all('input')
        for input_field in inputs:
            input_name = input_field.get('name', '').lower()
            input_value = input_field.get('value', '')
            input_type = input_field.get('type', '').lower()
            
            # Check if this is a CSRF token field
            if any(token_name in input_name for token_name in csrf_token_names):
                analysis['has_csrf_token'] = True
                analysis['token_details'] = {
                    'name': input_field.get('name'),
                    'value': input_value,
                    'type': input_type,
                    'length': len(input_value)
                }
                
                # Analyze token quality
                if len(input_value) < 16:
                    analysis['issues'].append('CSRF token too short (weak)')
                elif self._is_predictable_token(input_value):
                    analysis['issues'].append('CSRF token appears predictable')
        
        # Determine vulnerability
        if not analysis['has_csrf_token']:
            analysis['vulnerable'] = True
            analysis['confidence'] = 'high'
            analysis['issues'].append('No CSRF token found')
        elif analysis['issues']:
            analysis['vulnerable'] = True
            analysis['confidence'] = 'medium'
        
        return analysis
    
    def _is_predictable_token(self, token: str) -> bool:
        """Check if token appears to be predictable"""
        if not token:
            return True
            
        # Check for sequential or simple patterns
        if re.match(r'^[0-9]+$', token):  # Only numbers
            return True
        if re.match(r'^[a-f0-9]{8}$', token):  # Simple 8-char hex (weak)
            return True
        if token.lower() in ['test', 'admin', '12345', 'token']:
            return True
            
        return False
    
    def _calculate_confidence(self, results: Dict) -> Dict:
        """Calculate overall CSRF vulnerability confidence"""
        vulnerable_forms = results['vulnerable_forms']
        
        if not vulnerable_forms:
            results['confidence'] = 'none'
            results['vulnerable'] = False
        else:
            # If any form has high confidence, overall is high
            high_confidence_forms = [
                f for f in vulnerable_forms 
                if f['confidence'] == 'high'
            ]
            
            if high_confidence_forms:
                results['confidence'] = 'high'
                results['vulnerable'] = True
            else:
                results['confidence'] = 'medium'
                results['vulnerable'] = True
        
        results['details'] = {
            'total_forms': results['forms_analyzed'],
            'vulnerable_forms': len(vulnerable_forms),
            'high_confidence': len([f for f in vulnerable_forms if f['confidence'] == 'high']),
            'medium_confidence': len([f for f in vulnerable_forms if f['confidence'] == 'medium'])
        }
        
        return results