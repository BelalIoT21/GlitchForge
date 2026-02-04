"""
SQL Injection Scanner - Fast and Accurate
Error-based and behavior-based detection
"""
import re
from typing import List, Optional
from datetime import datetime
import requests

from .base_scanner import (
    BaseScanner,
    VulnerabilityResult,
    VulnerabilityType,
    SeverityLevel
)


class SQLScanner(BaseScanner):
    """
    SQL Injection Scanner

    Strategy:
    - Error-based detection (looks for SQL error messages)
    - Behavior-based detection (compares response differences)
    - 4 simple payloads that trigger database errors or behavior changes
    """

    def __init__(self, config):
        super().__init__(config)
        self.baseline_responses = {}  # Cache baseline responses for comparison

        # Database error patterns (compiled for speed)
        self.error_patterns = [
            # MySQL
            re.compile(r"SQL syntax.*MySQL", re.IGNORECASE),
            re.compile(r"Warning.*mysql_", re.IGNORECASE),
            re.compile(r"MySQLSyntaxErrorException", re.IGNORECASE),
            re.compile(r"valid MySQL result", re.IGNORECASE),
            re.compile(r"check the manual that corresponds to your MySQL", re.IGNORECASE),

            # PostgreSQL
            re.compile(r"PostgreSQL.*ERROR", re.IGNORECASE),
            re.compile(r"Warning.*\Wpg_", re.IGNORECASE),
            re.compile(r"valid PostgreSQL result", re.IGNORECASE),
            re.compile(r"Npgsql\.", re.IGNORECASE),

            # MSSQL
            re.compile(r"Driver.*SQL[\-\_\ ]*Server", re.IGNORECASE),
            re.compile(r"OLE DB.*SQL Server", re.IGNORECASE),
            re.compile(r"\[SQL Server\]", re.IGNORECASE),
            re.compile(r"SQLServer JDBC Driver", re.IGNORECASE),
            re.compile(r"Microsoft SQL Native Client", re.IGNORECASE),

            # Oracle
            re.compile(r"ORA-\d{4,5}", re.IGNORECASE),
            re.compile(r"Oracle error", re.IGNORECASE),
            re.compile(r"Oracle.*Driver", re.IGNORECASE),
            re.compile(r"Warning.*\Woci_", re.IGNORECASE),

            # SQLite
            re.compile(r"SQLite.*error", re.IGNORECASE),
            re.compile(r"sqlite3\.", re.IGNORECASE),

            # Generic SQL errors
            re.compile(r"syntax error.*SQL", re.IGNORECASE),
            re.compile(r"unclosed quotation mark", re.IGNORECASE),
            re.compile(r"quoted string not properly terminated", re.IGNORECASE),
            re.compile(r"SQL command not properly ended", re.IGNORECASE),
        ]

    def get_payloads(self) -> List[str]:
        """
        Minimal payloads that reliably trigger SQL errors

        We only need 4 payloads:
        1. Single quote - breaks string context
        2. Double quote - breaks some DBs
        3. Quote with OR - breaks and adds logic
        4. Quote with comment - breaks with comment
        """
        return [
            "'",                    # Simple quote - triggers most errors
            "1'",                   # Quote after number
            "1' OR '1'='1",        # Classic injection
            "1' --",               # Comment-based
        ]

    def get_baseline(self, url: str, param: str) -> Optional[str]:
        """Get baseline response for comparison, preserving existing URL params"""
        cache_key = f"{url}:{param}"
        if cache_key not in self.baseline_responses:
            # Build params preserving existing ones (like Submit=Submit for DVWA)
            # Use existing_params set by base scanner's scan() method
            test_params = getattr(self, 'existing_params', {}).copy()
            test_params[param] = "1"

            # Use base_url set by base scanner's scan() method
            base_url = getattr(self, 'base_url', url)

            response = self.make_request(base_url, params=test_params)
            if response:
                self.baseline_responses[cache_key] = response.text
                self.logger.debug(f"Baseline captured for {param}: {len(response.text)} bytes")
        return self.baseline_responses.get(cache_key)

    def detect_vulnerability(
        self,
        url: str,
        param: str,
        payload: str,
        response: requests.Response
    ) -> Optional[VulnerabilityResult]:
        """
        Check for SQL injection using multiple methods:
        1. Error-based: Look for SQL error messages
        2. Behavior-based: Compare response to baseline (for tautology payloads)
        """
        response_text = response.text

        # Method 1: Error-based detection
        for pattern in self.error_patterns:
            match = pattern.search(response_text)
            if match:
                evidence = match.group(0)[:200]
                self.logger.debug(f"SQL error found: {evidence}")

                return VulnerabilityResult(
                    vuln_type=VulnerabilityType.SQL_INJECTION,
                    severity=SeverityLevel.HIGH,
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=evidence,
                    confidence=0.95,
                    timestamp=datetime.now()
                )

        # Method 2: Behavior-based detection for tautology payloads
        # Check if OR '1'='1 payload returns significantly more data
        if "OR" in payload and "'1'='1" in payload:
            baseline = self.get_baseline(url, param)
            if baseline:
                baseline_len = len(baseline)
                response_len = len(response_text)

                self.logger.info(f"Behavior comparison: baseline={baseline_len} bytes, injected={response_len} bytes")

                # If injected response is significantly larger, likely returning more rows
                if response_len > baseline_len * 1.5 and response_len - baseline_len > 500:
                    evidence = f"Response size increased from {baseline_len} to {response_len} bytes (data extraction detected)"
                    self.logger.warning(f"SQL INJECTION DETECTED: {evidence}")

                    return VulnerabilityResult(
                        vuln_type=VulnerabilityType.SQL_INJECTION,
                        severity=SeverityLevel.HIGH,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=evidence,
                        confidence=0.85,
                        timestamp=datetime.now()
                    )

                # Check for multiple user records (common in DVWA)
                # Count <pre> blocks which contain user records in DVWA
                baseline_records = baseline.count('<pre>') + baseline.lower().count('first name')
                response_records = response_text.count('<pre>') + response_text.lower().count('first name')

                self.logger.info(f"Record count: baseline={baseline_records}, injected={response_records}")

                if response_records > baseline_records and response_records >= 2:
                    evidence = f"Multiple records returned ({response_records} vs {baseline_records} baseline) - data extraction successful"
                    self.logger.warning(f"SQL INJECTION DETECTED: {evidence}")

                    return VulnerabilityResult(
                        vuln_type=VulnerabilityType.SQL_INJECTION,
                        severity=SeverityLevel.HIGH,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=evidence,
                        confidence=0.90,
                        timestamp=datetime.now()
                    )

        # Method 3: Check if quote causes content to disappear (broken query)
        if payload in ["'", "1'"]:
            baseline = self.get_baseline(url, param)
            if baseline:
                # Look for data that should be in response but isn't
                # This indicates the query broke
                baseline_has_data = 'first name' in baseline.lower() or 'surname' in baseline.lower() or 'user' in baseline.lower()
                response_has_data = 'first name' in response_text.lower() or 'surname' in response_text.lower() or 'user' in response_text.lower()

                if baseline_has_data and not response_has_data:
                    evidence = "Query appears broken - expected data missing after quote injection"
                    self.logger.debug(f"Quote injection detected: {evidence}")

                    return VulnerabilityResult(
                        vuln_type=VulnerabilityType.SQL_INJECTION,
                        severity=SeverityLevel.HIGH,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=evidence,
                        confidence=0.80,
                        timestamp=datetime.now()
                    )

        return None
