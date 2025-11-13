"""
GlitchForge SQL Injection Scanner - Stage 1
Detects SQL Injection vulnerabilities using multiple techniques
"""
import re
import time
from typing import Dict, List, Optional
import requests

from .base_scanner import (
    BaseScanner, VulnerabilityResult, VulnerabilityType,
    SeverityLevel
)


class SQLInjectionScanner(BaseScanner):
    """
    SQL Injection vulnerability scanner
    
    Supports detection of:
    - Error-based SQL injection
    - Union-based SQL injection
    - Boolean-based blind SQL injection
    - Time-based blind SQL injection
    """
    
    def __init__(self, config: Dict):
        """
        Initialize SQL Injection scanner
        
        Args:
            config: Scanner configuration from config.py
        """
        super().__init__(config)
        
        # SQL error patterns from different database systems
        self.error_patterns = [
            # MySQL
            r"SQL syntax.*?MySQL",
            r"Warning.*?mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your MySQL",
            
            # PostgreSQL
            r"PostgreSQL.*?ERROR",
            r"Warning.*?pg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            
            # MSSQL
            r"Driver.*? SQL[\-\_\ ]*Server",
            r"OLE DB.*? SQL Server",
            r"SQLServer JDBC Driver",
            r"Microsoft SQL Native Client error",
            
            # Oracle
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*?Driver",
            r"Warning.*?oci_.*",
            
            # Generic
            r"SQL syntax error",
            r"syntax error near",
            r"unclosed quotation mark",
            r"quoted string not properly terminated",
        ]
        
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.error_patterns]
    
    def get_payloads(self) -> Dict[str, List[str]]:
        """
        Get SQL injection payloads from config
        
        Returns:
            Dictionary of payload categories
        """
        from config import SQL_PAYLOADS
        return SQL_PAYLOADS
    
    def detect_vulnerability(
        self,
        url: str,
        parameter: str,
        payload: str,
        response: requests.Response
    ) -> Optional[VulnerabilityResult]:
        """
        Detect SQL injection vulnerability based on response
        
        Args:
            url: Target URL
            parameter: Parameter being tested
            payload: Payload used
            response: HTTP response
            
        Returns:
            VulnerabilityResult if vulnerability found, None otherwise
        """
        # Check for error-based SQL injection
        if self._is_error_based(response):
            return self._create_result(
                url, parameter, payload, response,
                detection_type="Error-based",
                severity=SeverityLevel.HIGH,
                confidence=0.95
            )
        
        # Check for union-based SQL injection
        if "UNION" in payload.upper() and self._is_union_based(response):
            return self._create_result(
                url, parameter, payload, response,
                detection_type="Union-based",
                severity=SeverityLevel.HIGH,
                confidence=0.90
            )
        
        # Check for boolean-based blind SQL injection
        if self._is_boolean_blind(url, parameter, payload):
            return self._create_result(
                url, parameter, payload, response,
                detection_type="Boolean-based blind",
                severity=SeverityLevel.MEDIUM,
                confidence=0.80
            )
        
        # Check for time-based blind SQL injection
        if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper():
            if self._is_time_based(url, parameter, payload):
                return self._create_result(
                    url, parameter, payload, response,
                    detection_type="Time-based blind",
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.85
                )
        
        return None
    
    def _is_error_based(self, response: requests.Response) -> bool:
        """
        Check if response contains SQL error messages
        
        Args:
            response: HTTP response object
            
        Returns:
            True if SQL errors detected, False otherwise
        """
        response_text = response.text.lower()
        
        for pattern in self.compiled_patterns:
            if pattern.search(response.text):
                self.logger.debug(f"SQL error pattern matched: {pattern.pattern}")
                return True
        
        return False
    
    def _is_union_based(self, response: requests.Response) -> bool:
        """
        Check if union-based SQL injection is successful
        
        Args:
            response: HTTP response object
            
        Returns:
            True if union injection detected, False otherwise
        """
        response_text = response.text.lower()
        
        # Look for typical database version strings or system information
        indicators = [
            r'\d+\.\d+\.\d+',  # Version numbers (e.g., 5.7.31)
            r'@@version',
            r'version\(\)',
            r'user\(\)',
            r'database\(\)',
            r'current_user',
        ]
        
        for indicator in indicators:
            if re.search(indicator, response_text):
                return True
        
        return False
    
    def _is_boolean_blind(
        self,
        url: str,
        parameter: str,
        payload: str
    ) -> bool:
        """
        Check for boolean-based blind SQL injection
        
        Args:
            url: Target URL
            parameter: Parameter name
            payload: Payload being tested
            
        Returns:
            True if boolean blind injection detected, False otherwise
        """
        try:
            # Test with true condition
            true_payload = f"1' AND '1'='1"
            response_true = self.make_request(url, params={parameter: true_payload})
            
            if not response_true:
                return False
            
            # Test with false condition
            false_payload = f"1' AND '1'='2"
            response_false = self.make_request(url, params={parameter: false_payload})
            
            if not response_false:
                return False
            
            # Compare response lengths
            len_true = len(response_true.content)
            len_false = len(response_false.content)
            
            # If responses are significantly different, likely vulnerable
            if abs(len_true - len_false) > 100:
                self.logger.debug(
                    f"Boolean blind detected: true={len_true} bytes, false={len_false} bytes"
                )
                return True
        
        except Exception as e:
            self.logger.debug(f"Error in boolean blind test: {str(e)}")
        
        return False
    
    def _is_time_based(
        self,
        url: str,
        parameter: str,
        payload: str
    ) -> bool:
        """
        Check for time-based blind SQL injection
        
        Args:
            url: Target URL
            parameter: Parameter name
            payload: Payload with time delay
            
        Returns:
            True if time-based injection detected, False otherwise
        """
        try:
            # Measure baseline response time
            baseline_start = time.time()
            baseline_response = self.make_request(url, params={parameter: "1"})
            baseline_time = time.time() - baseline_start
            
            if not baseline_response:
                return False
            
            # Test with time delay payload
            delay_start = time.time()
            delay_response = self.make_request(url, params={parameter: payload})
            delay_time = time.time() - delay_start
            
            if not delay_response:
                return False
            
            # If delay response is significantly slower (>4 seconds difference), likely vulnerable
            time_diff = delay_time - baseline_time
            
            if time_diff > 4.0:
                self.logger.debug(
                    f"Time-based blind detected: baseline={baseline_time:.2f}s, "
                    f"delay={delay_time:.2f}s, diff={time_diff:.2f}s"
                )
                return True
        
        except Exception as e:
            self.logger.debug(f"Error in time-based test: {str(e)}")
        
        return False
    
    def _create_result(
        self,
        url: str,
        parameter: str,
        payload: str,
        response: requests.Response,
        detection_type: str,
        severity: SeverityLevel,
        confidence: float
    ) -> VulnerabilityResult:
        """
        Create a VulnerabilityResult object
        
        Args:
            url: Target URL
            parameter: Vulnerable parameter
            payload: Successful payload
            response: HTTP response
            detection_type: Type of SQL injection detected
            severity: Severity level
            confidence: Confidence score (0-1)
            
        Returns:
            VulnerabilityResult object
        """
        # Extract relevant evidence from response
        evidence = response.text[:500] if len(response.text) > 500 else response.text
        
        description = (
            f"{detection_type} SQL Injection vulnerability detected in parameter '{parameter}'. "
            f"The application is vulnerable to SQL injection attacks, allowing attackers to "
            f"manipulate database queries and potentially extract, modify, or delete data."
        )
        
        remediation = (
            "1. Use parameterized queries (prepared statements) instead of concatenating user input into SQL queries.\n"
            "2. Implement input validation and sanitization.\n"
            "3. Apply the principle of least privilege to database accounts.\n"
            "4. Use Web Application Firewalls (WAF) to detect and block SQL injection attempts.\n"
            "5. Keep database software up to date with security patches."
        )
        
        return VulnerabilityResult(
            vuln_type=VulnerabilityType.SQL_INJECTION,
            url=url,
            parameter=parameter,
            payload=payload,
            severity=severity,
            confidence=confidence,
            description=description,
            evidence=evidence,
            remediation=remediation,
            cwe_id="CWE-89"
        )


if __name__ == "__main__":
    # Test the SQL Injection scanner
    from config import SCANNER_CONFIG, SQL_PAYLOADS
    
    scanner = SQLInjectionScanner(SCANNER_CONFIG)
    
    # Test against DVWA (if available)
    test_url = "http://192.168.1.127/DVWA/vulnerabilities/sqli/"
    
    print(f"\nTesting SQL Injection Scanner against: {test_url}")
    print("="*60)
    
    results = scanner.scan(test_url, parameters=['id'], methods=['GET'])
    
    print(f"\nFound {len(results)} vulnerabilities")
    
    for i, vuln in enumerate(results, 1):
        print(f"\n[{i}] {vuln.vuln_type.value}")
        print(f"    Parameter: {vuln.parameter}")
        print(f"    Payload: {vuln.payload}")
        print(f"    Severity: {vuln.severity.value}")
        print(f"    Confidence: {vuln.confidence:.2%}")
    
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