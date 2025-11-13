"""
GlitchForge CSRF Scanner - Stage 1
Detects Cross-Site Request Forgery (CSRF) vulnerabilities
"""
import re
from typing import Dict, List, Optional, Set
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

from .base_scanner import (
    BaseScanner, VulnerabilityResult, VulnerabilityType,
    SeverityLevel
)


class CSRFScanner(BaseScanner):
    """
    Cross-Site Request Forgery (CSRF) vulnerability scanner
    
    Detects:
    - Missing CSRF tokens in forms
    - Weak CSRF token implementation
    - Token validation issues
    - SameSite cookie attribute issues
    """
    
    def __init__(self, config: Dict):
        """
        Initialize CSRF scanner
        
        Args:
            config: Scanner configuration from config.py
        """
        super().__init__(config)
        
        # Common CSRF token field names
        self.csrf_token_names = [
            'csrf_token',
            'csrftoken',
            'csrf',
            '_csrf',
            '_token',
            'authenticity_token',
            'token',
            '__requestverificationtoken',
            'anti_csrf_token',
            'xsrf_token',
        ]
        
        # Sensitive actions that should have CSRF protection
        self.sensitive_actions = [
            'delete',
            'remove',
            'update',
            'edit',
            'change',
            'transfer',
            'withdraw',
            'purchase',
            'buy',
            'sell',
            'reset',
            'password',
        ]
    
    def get_payloads(self) -> Dict[str, List[str]]:
        """
        CSRF scanner doesn't use payloads in the traditional sense
        
        Returns:
            Empty dictionary
        """
        return {'csrf_test': ['']}
    
    def detect_vulnerability(
        self,
        url: str,
        parameter: str,
        payload: str,
        response: requests.Response
    ) -> Optional[VulnerabilityResult]:
        """
        Detect CSRF vulnerability
        
        Args:
            url: Target URL
            parameter: Parameter being tested
            payload: Payload (not used for CSRF)
            response: HTTP response
            
        Returns:
            VulnerabilityResult if vulnerability found, None otherwise
        """
        # CSRF detection is handled differently, not through payloads
        return None
    
    def scan(
        self,
        url: str,
        parameters: Optional[List[str]] = None,
        methods: Optional[List[str]] = None
    ) -> List[VulnerabilityResult]:
        """
        Scan URL for CSRF vulnerabilities (overrides base scan method)
        
        Args:
            url: Target URL
            parameters: Not used for CSRF scanning
            methods: Not used for CSRF scanning
            
        Returns:
            List of discovered vulnerabilities
        """
        from datetime import datetime
        
        self.scan_metadata['start_time'] = datetime.now()
        self.vulnerabilities = []
        
        self.logger.info(f"Starting CSRF scan on {url}")
        
        # Get the page
        response = self.make_request(url)
        
        if not response:
            self.logger.error(f"Failed to retrieve {url}")
            return []
        
        # Parse HTML
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Find all forms
        forms = soup.find_all('form')
        
        if not forms:
            self.logger.info("No forms found on page")
            self.scan_metadata['end_time'] = datetime.now()
            return []
        
        self.logger.info(f"Found {len(forms)} forms to analyze")
        
        # Analyze each form
        for form_index, form in enumerate(forms, 1):
            self.logger.debug(f"Analyzing form {form_index}/{len(forms)}")
            
            # Check if form has CSRF token
            has_token = self._has_csrf_token(form)
            
            # Get form action and method
            form_action = form.get('action', url)
            form_method = form.get('method', 'GET').upper()
            
            # Full URL for form action
            form_url = urljoin(url, form_action)
            
            # Check if form performs sensitive actions
            is_sensitive = self._is_sensitive_form(form, form_action)
            
            # Determine if vulnerable
            if form_method == 'POST' and not has_token:
                severity = SeverityLevel.HIGH if is_sensitive else SeverityLevel.MEDIUM
                confidence = 0.90 if is_sensitive else 0.75
                
                result = self._create_result(
                    url=form_url,
                    form=form,
                    issue="Missing CSRF token",
                    severity=severity,
                    confidence=confidence,
                    is_sensitive=is_sensitive
                )
                
                self.vulnerabilities.append(result)
                self.scan_metadata['total_vulnerabilities'] += 1
                
                self.logger.warning(
                    f"CSRF vulnerability found in form {form_index}: "
                    f"POST form without CSRF token"
                )
            
            elif has_token:
                # Token exists, check if it's properly implemented
                token_issues = self._check_token_implementation(url, form)
                
                if token_issues:
                    result = self._create_result(
                        url=form_url,
                        form=form,
                        issue=f"Weak CSRF token implementation: {', '.join(token_issues)}",
                        severity=SeverityLevel.MEDIUM,
                        confidence=0.70,
                        is_sensitive=is_sensitive
                    )
                    
                    self.vulnerabilities.append(result)
                    self.scan_metadata['total_vulnerabilities'] += 1
                    
                    self.logger.warning(
                        f"Weak CSRF protection in form {form_index}: {', '.join(token_issues)}"
                    )
        
        # Check for SameSite cookie attribute
        samesite_issue = self._check_samesite_cookies(response)
        if samesite_issue:
            result = self._create_cookie_result(
                url=url,
                issue=samesite_issue,
                severity=SeverityLevel.LOW,
                confidence=0.85
            )
            self.vulnerabilities.append(result)
            self.scan_metadata['total_vulnerabilities'] += 1
        
        self.scan_metadata['end_time'] = datetime.now()
        duration = (self.scan_metadata['end_time'] - self.scan_metadata['start_time']).total_seconds()
        
        self.logger.info(
            f"CSRF scan completed in {duration:.2f} seconds. "
            f"Found {len(self.vulnerabilities)} vulnerabilities."
        )
        
        return self.vulnerabilities
    
    def _has_csrf_token(self, form) -> bool:
        """
        Check if form contains a CSRF token
        
        Args:
            form: BeautifulSoup form element
            
        Returns:
            True if CSRF token found, False otherwise
        """
        # Check all input fields
        inputs = form.find_all('input')
        
        for input_field in inputs:
            name = input_field.get('name', '').lower()
            
            # Check if input name matches common CSRF token names
            if any(token_name in name for token_name in self.csrf_token_names):
                self.logger.debug(f"CSRF token found: {name}")
                return True
            
            # Check for hidden fields with 'token' in name
            if input_field.get('type') == 'hidden' and 'token' in name:
                self.logger.debug(f"Possible CSRF token found: {name}")
                return True
        
        return False
    
    def _is_sensitive_form(self, form, form_action: str) -> bool:
        """
        Determine if form performs sensitive actions
        
        Args:
            form: BeautifulSoup form element
            form_action: Form action URL
            
        Returns:
            True if form is sensitive, False otherwise
        """
        # Check form action URL for sensitive keywords
        form_action_lower = form_action.lower()
        
        if any(action in form_action_lower for action in self.sensitive_actions):
            return True
        
        # Check button/submit text
        buttons = form.find_all(['button', 'input'])
        
        for button in buttons:
            button_type = button.get('type', '').lower()
            button_value = button.get('value', '').lower()
            button_text = button.get_text().lower()
            
            if button_type == 'submit' or button.name == 'button':
                if any(action in button_value or action in button_text 
                       for action in self.sensitive_actions):
                    return True
        
        # Check for password fields
        password_fields = form.find_all('input', {'type': 'password'})
        if password_fields:
            return True
        
        return False
    
    def _check_token_implementation(
        self,
        url: str,
        form
    ) -> List[str]:
        """
        Check if CSRF token is properly implemented
        
        Args:
            url: Target URL
            form: BeautifulSoup form element
            
        Returns:
            List of issues found
        """
        issues = []
        
        # Find the CSRF token field
        csrf_field = None
        csrf_value = None
        
        for input_field in form.find_all('input'):
            name = input_field.get('name', '').lower()
            if any(token_name in name for token_name in self.csrf_token_names):
                csrf_field = input_field
                csrf_value = input_field.get('value', '')
                break
        
        if not csrf_field or not csrf_value:
            return []
        
        # Check if token is too short (weak randomness)
        if len(csrf_value) < 16:
            issues.append("Token too short (less than 16 characters)")
        
        # Check if token looks predictable (sequential or simple pattern)
        if csrf_value.isdigit():
            issues.append("Token appears to be sequential number")
        
        # Check if token is same across requests (not session-specific)
        try:
            # Make another request and check if token changes
            response2 = self.make_request(url)
            if response2:
                soup2 = BeautifulSoup(response2.content, 'html.parser')
                forms2 = soup2.find_all('form')
                
                for form2 in forms2:
                    for input_field2 in form2.find_all('input'):
                        name2 = input_field2.get('name', '').lower()
                        if name2 == csrf_field.get('name', '').lower():
                            value2 = input_field2.get('value', '')
                            
                            if value2 == csrf_value:
                                issues.append("Token does not change between requests")
                            break
        except Exception as e:
            self.logger.debug(f"Error checking token uniqueness: {str(e)}")
        
        return issues
    
    def _check_samesite_cookies(self, response: requests.Response) -> Optional[str]:
        """
        Check if session cookies have SameSite attribute
        
        Args:
            response: HTTP response
            
        Returns:
            Issue description if problem found, None otherwise
        """
        # Check Set-Cookie headers
        set_cookie_headers = response.headers.get('Set-Cookie', '')
        
        if not set_cookie_headers:
            return None
        
        # Look for session cookies
        session_cookie_names = ['session', 'sessionid', 'phpsessid', 'jsessionid', 'asp.net_sessionid']
        
        cookies = set_cookie_headers.lower()
        
        # Check if any session cookie exists
        has_session_cookie = any(name in cookies for name in session_cookie_names)
        
        if has_session_cookie:
            # Check for SameSite attribute
            if 'samesite' not in cookies:
                return "Session cookies missing SameSite attribute"
            elif 'samesite=none' in cookies:
                return "Session cookies use SameSite=None (less secure)"
        
        return None
    
    def _create_result(
        self,
        url: str,
        form,
        issue: str,
        severity: SeverityLevel,
        confidence: float,
        is_sensitive: bool
    ) -> VulnerabilityResult:
        """
        Create VulnerabilityResult for CSRF issue
        
        Args:
            url: Target URL
            form: Form element
            issue: Description of the issue
            severity: Severity level
            confidence: Confidence score
            is_sensitive: Whether form performs sensitive actions
            
        Returns:
            VulnerabilityResult object
        """
        form_action = form.get('action', 'N/A')
        form_method = form.get('method', 'GET')
        
        description = (
            f"CSRF vulnerability detected: {issue}. "
            f"The form (action: {form_action}, method: {form_method}) "
            f"does not have adequate CSRF protection. "
        )
        
        if is_sensitive:
            description += (
                "This form appears to perform sensitive actions, making this vulnerability "
                "particularly dangerous. Attackers can trick users into performing unintended "
                "actions such as changing passwords, transferring funds, or modifying account settings."
            )
        else:
            description += (
                "While this form may not perform highly sensitive actions, "
                "CSRF protection should still be implemented to prevent unauthorized requests."
            )
        
        # Get form inputs as evidence
        inputs = form.find_all('input')
        input_names = [inp.get('name', 'unnamed') for inp in inputs]
        evidence = f"Form inputs: {', '.join(input_names[:10])}"  # Limit to first 10
        
        remediation = (
            "1. Implement CSRF tokens (also called anti-CSRF tokens or synchronizer tokens).\n"
            "2. Use the Synchronizer Token Pattern: generate a unique token for each session/request.\n"
            "3. Validate the token on the server side for all state-changing operations.\n"
            "4. Set the SameSite cookie attribute to 'Strict' or 'Lax' for session cookies.\n"
            "5. For sensitive operations, require re-authentication or additional verification.\n"
            "6. Implement proper CORS policies to restrict cross-origin requests.\n"
            "7. Use security frameworks that provide built-in CSRF protection (e.g., Django, Spring Security)."
        )
        
        return VulnerabilityResult(
            vuln_type=VulnerabilityType.CSRF,
            url=url,
            parameter=f"Form: {form_action}",
            payload="N/A",
            severity=severity,
            confidence=confidence,
            description=description,
            evidence=evidence,
            remediation=remediation,
            cvss_score=6.5 if is_sensitive else 4.3,
            cwe_id="CWE-352"
        )
    
    def _create_cookie_result(
        self,
        url: str,
        issue: str,
        severity: SeverityLevel,
        confidence: float
    ) -> VulnerabilityResult:
        """
        Create VulnerabilityResult for cookie-related CSRF issue
        
        Args:
            url: Target URL
            issue: Description of cookie issue
            severity: Severity level
            confidence: Confidence score
            
        Returns:
            VulnerabilityResult object
        """
        description = (
            f"CSRF-related cookie security issue: {issue}. "
            f"The SameSite cookie attribute helps prevent CSRF attacks by controlling "
            f"when cookies are sent with cross-site requests."
        )
        
        remediation = (
            "1. Add 'SameSite=Strict' or 'SameSite=Lax' to all session cookies.\n"
            "2. SameSite=Strict: Cookie only sent for same-site requests (most secure).\n"
            "3. SameSite=Lax: Cookie sent for top-level navigation (balance of security and usability).\n"
            "4. Avoid SameSite=None unless absolutely necessary for cross-site scenarios.\n"
            "5. Combine with other CSRF protections (tokens, CORS policies)."
        )
        
        return VulnerabilityResult(
            vuln_type=VulnerabilityType.CSRF,
            url=url,
            parameter="Cookie Security",
            payload="N/A",
            severity=severity,
            confidence=confidence,
            description=description,
            evidence=issue,
            remediation=remediation,
            cvss_score=4.3,
            cwe_id="CWE-352"
        )


if __name__ == "__main__":
    # Test the CSRF scanner
    from config import SCANNER_CONFIG
    
    scanner = CSRFScanner(SCANNER_CONFIG)
    
    # Test against DVWA (if available)
    test_url = "http://192.168.1.127/DVWA/vulnerabilities/csrf/"
    
    print(f"\nTesting CSRF Scanner against: {test_url}")
    print("="*60)
    
    results = scanner.scan(test_url)
    
    print(f"\nFound {len(results)} vulnerabilities")
    
    for i, vuln in enumerate(results, 1):
        print(f"\n[{i}] {vuln.vuln_type.value}")
        print(f"    Location: {vuln.parameter}")
        print(f"    Issue: {vuln.description[:100]}...")
        print(f"    Severity: {vuln.severity.value}")
        print(f"    Confidence: {vuln.confidence:.2%}")
        print(f"    CVSS: {vuln.cvss_score}")
    
    # Export results
    summary = scanner.get_results_summary()
    print("\n" + "="*60)
    print("SCAN SUMMARY")
    print("="*60)
    print(f"Scanner: {summary['scanner_type']}")
    print(f"Duration: {summary['scan_duration']:.2f} seconds")
    print(f"Total Requests: {summary['total_requests']}")
    print(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
    print(f"Severity Breakdown: {summary['severity_breakdown']}")