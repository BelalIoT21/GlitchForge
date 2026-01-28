"""
GlitchForge XSS Scanner - Stage 1
Detects Cross-Site Scripting (XSS) vulnerabilities
"""
import re
from typing import Dict, List, Optional
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup

from .base_scanner import (
    BaseScanner, VulnerabilityResult, VulnerabilityType,
    SeverityLevel
)


class XSSScanner(BaseScanner):
    """
    Cross-Site Scripting (XSS) vulnerability scanner
    
    Supports detection of:
    - Reflected XSS
    - Stored XSS
    - DOM-based XSS
    """
    
    def __init__(self, config: Dict):
        """
        Initialize XSS scanner
        
        Args:
            config: Scanner configuration from config.py
        """
        super().__init__(config)
        
        # XSS detection patterns
        self.xss_patterns = [
            # Script tags
            r'<script[^>]*>.*?</script>',
            r'<script[^>]*>',
            
            # Event handlers
            r'on\w+\s*=',
            r'onerror\s*=',
            r'onload\s*=',
            r'onmouseover\s*=',
            r'onfocus\s*=',
            r'onclick\s*=',
            
            # JavaScript protocols
            r'javascript:',
            r'vbscript:',
            
            # SVG/XML tags
            r'<svg[^>]*>',
            r'<embed[^>]*>',
            r'<object[^>]*>',
            r'<iframe[^>]*>',
            
            # IMG tags with event handlers
            r'<img[^>]*\son\w+',
            
            # Special characters that indicate potential XSS
            r'<.*?>',  # Any HTML tag
        ]
        
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.xss_patterns]
        
        # Unique marker for XSS detection
        self.xss_marker = "GLITCHFORGE_XSS_TEST_"
    
    def get_payloads(self) -> Dict[str, List[str]]:
        """
        Get XSS payloads from config
        
        Returns:
            Dictionary of payload categories
        """
        from app.config import XSS_PAYLOADS
        return XSS_PAYLOADS
    
    def detect_vulnerability(
        self,
        url: str,
        parameter: str,
        payload: str,
        response: requests.Response
    ) -> Optional[VulnerabilityResult]:
        """
        Detect XSS vulnerability based on response
        
        Args:
            url: Target URL
            parameter: Parameter being tested
            payload: Payload used
            response: HTTP response
            
        Returns:
            VulnerabilityResult if vulnerability found, None otherwise
        """
        # Check for reflected XSS
        if self._is_reflected_xss(payload, response):
            return self._create_result(
                url, parameter, payload, response,
                xss_type="Reflected",
                severity=SeverityLevel.HIGH,
                confidence=0.90
            )
        
        # Check for DOM-based XSS indicators
        if self._is_dom_based_xss(response):
            return self._create_result(
                url, parameter, payload, response,
                xss_type="DOM-based",
                severity=SeverityLevel.MEDIUM,
                confidence=0.75
            )
        
        return None
    
    def _is_reflected_xss(
        self,
        payload: str,
        response: requests.Response
    ) -> bool:
        """
        Check if payload is reflected in response without proper encoding
        
        Args:
            payload: XSS payload
            response: HTTP response
            
        Returns:
            True if reflected XSS detected, False otherwise
        """
        response_text = response.text
        
        # Check if the exact payload appears in response
        if payload in response_text:
            self.logger.debug(f"Exact payload reflected: {payload[:50]}...")
            return True
        
        # Check if payload appears unencoded in HTML attributes or JavaScript
        soup = BeautifulSoup(response_text, 'html.parser')
        
        # Check all attributes
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if isinstance(value, str) and payload.lower() in value.lower():
                    self.logger.debug(f"Payload found in {tag.name} tag, {attr} attribute")
                    return True
                elif isinstance(value, list):
                    for v in value:
                        if isinstance(v, str) and payload.lower() in v.lower():
                            self.logger.debug(f"Payload found in {tag.name} tag, {attr} attribute")
                            return True
        
        # Check script tags for reflected content
        for script in soup.find_all('script'):
            if script.string and payload.lower() in script.string.lower():
                self.logger.debug("Payload found in script tag")
                return True
        
        # Check for common XSS patterns in response
        for pattern in self.compiled_patterns:
            if pattern.search(response_text):
                # Verify the matched pattern contains part of our payload
                matches = pattern.finditer(response_text)
                for match in matches:
                    matched_text = match.group(0)
                    # Check if our payload or parts of it are in the matched text
                    payload_keywords = ['script', 'onerror', 'onload', 'alert', 'img', 'svg']
                    if any(keyword in payload.lower() and keyword in matched_text.lower() 
                           for keyword in payload_keywords):
                        self.logger.debug(f"XSS pattern matched with payload content: {matched_text[:50]}...")
                        return True
        
        return False
    
    def _is_dom_based_xss(self, response: requests.Response) -> bool:
        """
        Check for DOM-based XSS indicators
        
        Args:
            response: HTTP response
            
        Returns:
            True if DOM-based XSS indicators found, False otherwise
        """
        response_text = response.text.lower()
        
        # DOM XSS sinks (dangerous JavaScript functions)
        dom_sinks = [
            r'document\.write\s*\(',
            r'document\.writeln\s*\(',
            r'\.innerhtml\s*=',
            r'\.outerhtml\s*=',
            r'eval\s*\(',
            r'settimeout\s*\(',
            r'setinterval\s*\(',
            r'execscript\s*\(',
            r'location\s*=',
            r'location\.href\s*=',
            r'location\.replace\s*\(',
        ]
        
        # DOM XSS sources (user-controlled data)
        dom_sources = [
            r'location\.hash',
            r'location\.search',
            r'document\.url',
            r'document\.documenturi',
            r'document\.referrer',
            r'window\.name',
        ]
        
        # Check if both sources and sinks are present
        has_source = any(re.search(source, response_text) for source in dom_sources)
        has_sink = any(re.search(sink, response_text) for sink in dom_sinks)
        
        if has_source and has_sink:
            self.logger.debug("DOM-based XSS indicators found (source + sink)")
            return True
        
        return False
    
    def check_stored_xss(
        self,
        url: str,
        parameter: str,
        payload: str
    ) -> Optional[VulnerabilityResult]:
        """
        Check for stored XSS vulnerability
        
        Args:
            url: Target URL
            parameter: Parameter name
            payload: XSS payload
            
        Returns:
            VulnerabilityResult if stored XSS found, None otherwise
        """
        try:
            # Add unique marker to payload
            marked_payload = f"{self.xss_marker}{payload}"
            
            # Submit payload via POST
            self.logger.info(f"Testing stored XSS with marked payload")
            post_response = self.make_request(url, method='POST', data={parameter: marked_payload})
            
            if not post_response:
                return None
            
            # Wait briefly for storage
            import time
            time.sleep(1)
            
            # Retrieve the page to see if payload is stored
            get_response = self.make_request(url, method='GET')
            
            if not get_response:
                return None
            
            # Check if marked payload appears in response
            if self.xss_marker in get_response.text:
                self.logger.warning("Stored XSS detected - marker found in response")
                
                return self._create_result(
                    url, parameter, marked_payload, get_response,
                    xss_type="Stored",
                    severity=SeverityLevel.CRITICAL,
                    confidence=0.95
                )
        
        except Exception as e:
            self.logger.debug(f"Error in stored XSS test: {str(e)}")
        
        return None
    
    def _create_result(
        self,
        url: str,
        parameter: str,
        payload: str,
        response: requests.Response,
        xss_type: str,
        severity: SeverityLevel,
        confidence: float
    ) -> VulnerabilityResult:
        """
        Create a VulnerabilityResult object for XSS
        
        Args:
            url: Target URL
            parameter: Vulnerable parameter
            payload: Successful payload
            response: HTTP response
            xss_type: Type of XSS (Reflected, Stored, DOM-based)
            severity: Severity level
            confidence: Confidence score (0-1)
            
        Returns:
            VulnerabilityResult object
        """
        # Extract evidence
        evidence = response.text[:500] if len(response.text) > 500 else response.text
        
        description = (
            f"{xss_type} XSS vulnerability detected in parameter '{parameter}'. "
            f"The application does not properly sanitize user input before including it in the HTML response. "
            f"Attackers can inject malicious JavaScript code to steal session cookies, "
            f"perform actions on behalf of users, or deface the website."
        )
        
        remediation = (
            "1. Implement proper output encoding/escaping for all user-controlled data.\n"
            "2. Use Content Security Policy (CSP) headers to restrict script execution.\n"
            "3. Validate and sanitize all user input on the server side.\n"
            "4. Use HTTPOnly flags on cookies to prevent JavaScript access.\n"
            "5. Consider using security libraries or frameworks with built-in XSS protection.\n"
            "6. Implement input validation with allowlists rather than denylists."
        )
        
        # Set CVSS score based on type
        cvss_score = 7.1 if xss_type == "Reflected" else 8.8 if xss_type == "Stored" else 6.5
        
        return VulnerabilityResult(
            vuln_type=VulnerabilityType.XSS,
            url=url,
            parameter=parameter,
            payload=payload,
            severity=severity,
            confidence=confidence,
            description=description,
            evidence=evidence,
            remediation=remediation,
            cvss_score=cvss_score,
            cwe_id="CWE-79"
        )
    
    def scan(
        self,
        url: str,
        parameters: Optional[List[str]] = None,
        methods: Optional[List[str]] = None,
        check_stored: bool = True
    ) -> List[VulnerabilityResult]:
        """
        Scan URL for XSS vulnerabilities (overrides base scan to add stored XSS check)
        
        Args:
            url: Target URL
            parameters: List of parameters to test
            methods: HTTP methods to test
            check_stored: Whether to check for stored XSS
            
        Returns:
            List of discovered vulnerabilities
        """
        # Run base scan for reflected and DOM-based XSS
        results = super().scan(url, parameters, methods)
        
        # Additionally check for stored XSS if requested
        if check_stored:
            self.logger.info("Performing stored XSS checks...")
            
            if parameters is None:
                parameters = self.discover_parameters(url)
            
            payloads = self.get_payloads()
            
            for param in parameters:
                for category, payload_list in payloads.items():
                    # Test one payload per category for stored XSS
                    payload = payload_list[0]
                    stored_result = self.check_stored_xss(url, param, payload)
                    
                    if stored_result:
                        results.append(stored_result)
                        self.vulnerabilities.append(stored_result)
                        self.scan_metadata['total_vulnerabilities'] += 1
        
        return results


if __name__ == "__main__":
    # Test the XSS scanner
    from app.config import SCANNER_CONFIG
    
    scanner = XSSScanner(SCANNER_CONFIG)
    
    # Test against DVWA (if available)
    test_url = "http://192.168.1.127/DVWA/vulnerabilities/xss_r/"
    
    print(f"\nTesting XSS Scanner against: {test_url}")
    print("="*60)
    
    results = scanner.scan(test_url, parameters=['name'], methods=['GET'])
    
    print(f"\nFound {len(results)} vulnerabilities")
    
    for i, vuln in enumerate(results, 1):
        print(f"\n[{i}] {vuln.vuln_type.value}")
        print(f"    Parameter: {vuln.parameter}")
        print(f"    Payload: {vuln.payload}")
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