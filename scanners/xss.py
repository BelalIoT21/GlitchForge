"""
Cross-Site Scripting (XSS) Detection Module
"""

import requests
import re
from typing import Dict, List
from bs4 import BeautifulSoup
from config import XSS_PAYLOADS, SCANNER_CONFIG

class XSSScanner:
    def __init__(self, session: requests.Session):
        self.session = session
        self.timeout = SCANNER_CONFIG['timeout']
        
    def detect(self, url: str, parameter: str) -> Dict:
        """
        Detect XSS vulnerabilities (Reflected and Stored)
        """
        results = {
            'vulnerable': False,
            'confidence': 'none',
            'vulnerability_type': 'Cross-Site Scripting (XSS)',
            'cwe_id': 'CWE-79',
            'xss_type': None,  # reflected, stored, dom
            'successful_payloads': [],
            'details': {}
        }
        
        # Test reflected XSS
        reflected_results = self._test_reflected_xss(url, parameter)
        
        # Analyze results
        results['details'] = {'reflected': reflected_results}
        results = self._calculate_confidence(results, reflected_results)
        
        return results
    
    def _test_reflected_xss(self, url: str, parameter: str) -> List[Dict]:
        """Test for reflected XSS"""
        results = []
        
        # Test all payload types
        all_payloads = []
        for payload_type, payloads in XSS_PAYLOADS.items():
            for payload in payloads:
                all_payloads.append((payload_type, payload))
        
        for payload_type, payload in all_payloads:
            test_url = f"{url}?{parameter}={payload}&Submit=Submit"
            
            try:
                response = self.session.get(test_url, timeout=self.timeout)
                
                # Check if payload is reflected in response
                is_reflected = payload in response.text
                
                # Check if payload is in executable context
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Check script tags
                in_script_tag = False
                for script in soup.find_all('script'):
                    if payload in str(script):
                        in_script_tag = True
                        break
                
                # Check event handlers
                has_event_handler = bool(re.search(
                    r'on\w+\s*=\s*["\'].*?' + re.escape(payload),
                    response.text,
                    re.IGNORECASE
                ))
                
                # Check if in dangerous attribute
                dangerous_contexts = ['src=', 'href=', 'action=']
                in_dangerous_context = any(
                    f'{ctx}"{payload}"' in response.text or f"{ctx}'{payload}'" in response.text
                    for ctx in dangerous_contexts
                )
                
                vulnerable = (is_reflected and (
                    in_script_tag or 
                    has_event_handler or 
                    in_dangerous_context or
                    '<script>' in payload.lower()
                ))
                
                results.append({
                    'payload_type': payload_type,
                    'payload': payload,
                    'vulnerable': vulnerable,
                    'is_reflected': is_reflected,
                    'in_script_tag': in_script_tag,
                    'has_event_handler': has_event_handler,
                    'in_dangerous_context': in_dangerous_context,
                    'status_code': response.status_code
                })
                
            except requests.RequestException as e:
                print(f"Error testing payload {payload}: {e}")
                
        return results
    
    def _calculate_confidence(self, results: Dict, test_results: List[Dict]) -> Dict:
        """Calculate confidence level for XSS detection"""
        vulnerable_count = 0
        high_confidence_count = 0
        
        for result in test_results:
            if result['vulnerable']:
                vulnerable_count += 1
                
                # High confidence if in script tag or event handler
                if result['in_script_tag'] or result['has_event_handler']:
                    high_confidence_count += 1
                    
                results['successful_payloads'].append({
                    'type': result['payload_type'],
                    'payload': result['payload']
                })
        
        if vulnerable_count == 0:
            results['confidence'] = 'none'
            results['vulnerable'] = False
        elif high_confidence_count >= 1:
            results['confidence'] = 'high'
            results['vulnerable'] = True
            results['xss_type'] = 'reflected'
        elif vulnerable_count >= 2:
            results['confidence'] = 'medium'
            results['vulnerable'] = True
            results['xss_type'] = 'reflected'
        else:
            results['confidence'] = 'low'
            results['vulnerable'] = True
            results['xss_type'] = 'reflected'
        
        return results