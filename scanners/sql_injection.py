"""
SQL Injection Detection Module
Enhanced version with confidence scoring
"""

import requests
import re
import time
from typing import Dict, List, Tuple
from config import SQL_PAYLOADS, SCANNER_CONFIG

class SQLInjectionScanner:
    def __init__(self, session: requests.Session):
        self.session = session
        self.timeout = SCANNER_CONFIG['timeout']
        
    def detect(self, url: str, parameter: str) -> Dict:
        """
        Detect SQL injection vulnerabilities
        Returns detailed results with confidence scoring
        """
        results = {
            'vulnerable': False,
            'confidence': 'none',  # none, low, medium, high
            'vulnerability_type': 'SQL Injection',
            'cwe_id': 'CWE-89',
            'successful_payloads': [],
            'details': {}
        }
        
        # Test different payload types
        error_based_results = self._test_error_based(url, parameter)
        union_based_results = self._test_union_based(url, parameter)
        boolean_blind_results = self._test_boolean_blind(url, parameter)
        time_based_results = self._test_time_based(url, parameter)
        
        # Analyze results and determine confidence
        all_results = {
            'error_based': error_based_results,
            'union_based': union_based_results,
            'boolean_blind': boolean_blind_results,
            'time_based': time_based_results
        }
        
        results['details'] = all_results
        results = self._calculate_confidence(results, all_results)
        
        return results
    
    def _test_error_based(self, url: str, parameter: str) -> List[Dict]:
        """Test error-based SQL injection"""
        results = []
        
        for payload in SQL_PAYLOADS['error_based']:
            test_url = f"{url}?{parameter}={payload}&Submit=Submit"
            
            try:
                response = self.session.get(test_url, timeout=self.timeout)
                
                # Check for SQL error messages
                error_patterns = [
                    r'mysql_fetch',
                    r'SQL syntax',
                    r'mysqli',
                    r'ORA-\d+',
                    r'PostgreSQL.*ERROR',
                    r'Warning.*mysql',
                ]
                
                has_error = any(
                    re.search(pattern, response.text, re.IGNORECASE) 
                    for pattern in error_patterns
                )
                
                # Check for successful data extraction
                success_indicators = ['surname', 'first name', 'admin', 'gordon']
                has_data = any(
                    indicator.lower() in response.text.lower() 
                    for indicator in success_indicators
                )
                
                results.append({
                    'payload': payload,
                    'vulnerable': has_error or has_data,
                    'has_error': has_error,
                    'has_data': has_data,
                    'status_code': response.status_code,
                    'response_length': len(response.text)
                })
                
            except requests.RequestException as e:
                print(f"Error testing payload {payload}: {e}")
                
        return results
    
    def _test_union_based(self, url: str, parameter: str) -> List[Dict]:
        """Test UNION-based SQL injection"""
        results = []
        
        for payload in SQL_PAYLOADS['union_based']:
            test_url = f"{url}?{parameter}={payload}&Submit=Submit"
            
            try:
                response = self.session.get(test_url, timeout=self.timeout)
                
                # Check for version info, database names, etc.
                union_indicators = [
                    r'\d+\.\d+\.\d+',  # Version numbers
                    r'database',
                    r'information_schema',
                    r'root@',
                    r'version\(\)'
                ]
                
                has_union_data = any(
                    re.search(pattern, response.text, re.IGNORECASE)
                    for pattern in union_indicators
                )
                
                results.append({
                    'payload': payload,
                    'vulnerable': has_union_data,
                    'status_code': response.status_code,
                    'response_length': len(response.text)
                })
                
            except requests.RequestException as e:
                print(f"Error testing payload {payload}: {e}")
                
        return results
    
    def _test_boolean_blind(self, url: str, parameter: str) -> List[Dict]:
        """Test boolean-based blind SQL injection"""
        results = []
        
        # Get baseline response
        baseline_url = f"{url}?{parameter}=1&Submit=Submit"
        try:
            baseline_response = self.session.get(baseline_url, timeout=self.timeout)
            baseline_length = len(baseline_response.text)
        except:
            return results
        
        for payload in SQL_PAYLOADS['boolean_blind']:
            test_url = f"{url}?{parameter}={payload}&Submit=Submit"
            
            try:
                response = self.session.get(test_url, timeout=self.timeout)
                response_length = len(response.text)
                
                # Check if response differs significantly from baseline
                length_diff = abs(response_length - baseline_length)
                is_different = length_diff > 100  # Threshold for significance
                
                results.append({
                    'payload': payload,
                    'vulnerable': is_different,
                    'baseline_length': baseline_length,
                    'response_length': response_length,
                    'difference': length_diff
                })
                
            except requests.RequestException as e:
                print(f"Error testing payload {payload}: {e}")
                
        return results
    
    def _test_time_based(self, url: str, parameter: str) -> List[Dict]:
        """Test time-based blind SQL injection"""
        results = []
        
        for payload in SQL_PAYLOADS['time_based']:
            test_url = f"{url}?{parameter}={payload}&Submit=Submit"
            
            try:
                start_time = time.time()
                response = self.session.get(test_url, timeout=self.timeout + 10)
                elapsed_time = time.time() - start_time
                
                # If response took significantly longer, likely vulnerable
                is_delayed = elapsed_time > 4.5  # Expecting 5 second delay
                
                results.append({
                    'payload': payload,
                    'vulnerable': is_delayed,
                    'elapsed_time': elapsed_time,
                    'expected_delay': 5.0
                })
                
            except requests.Timeout:
                # Timeout is actually a positive indicator for time-based injection
                results.append({
                    'payload': payload,
                    'vulnerable': True,
                    'elapsed_time': 'timeout',
                    'expected_delay': 5.0
                })
            except requests.RequestException as e:
                print(f"Error testing payload {payload}: {e}")
                
        return results
    
    def _calculate_confidence(self, results: Dict, all_results: Dict) -> Dict:
        """Calculate confidence level based on test results"""
        vulnerable_count = 0
        high_confidence_indicators = 0
        
        # Count vulnerabilities across all test types
        for test_type, test_results in all_results.items():
            for result in test_results:
                if result.get('vulnerable', False):
                    vulnerable_count += 1
                    
                    # High confidence indicators
                    if test_type == 'error_based' and result.get('has_error'):
                        high_confidence_indicators += 2
                    elif test_type == 'error_based' and result.get('has_data'):
                        high_confidence_indicators += 2
                    elif test_type == 'time_based':
                        high_confidence_indicators += 2
                    elif test_type == 'union_based':
                        high_confidence_indicators += 1
        
        # Determine confidence level
        if vulnerable_count == 0:
            results['confidence'] = 'none'
            results['vulnerable'] = False
        elif high_confidence_indicators >= 2:
            results['confidence'] = 'high'
            results['vulnerable'] = True
        elif vulnerable_count >= 3:
            results['confidence'] = 'medium'
            results['vulnerable'] = True
        else:
            results['confidence'] = 'low'
            results['vulnerable'] = True
        
        # Store successful payloads
        for test_type, test_results in all_results.items():
            for result in test_results:
                if result.get('vulnerable', False):
                    results['successful_payloads'].append({
                        'type': test_type,
                        'payload': result['payload']
                    })
        
        return results