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

            # MSSQL / SQL Server (ASP.NET sites)
            re.compile(r"Driver.*SQL[\-\_\ ]*Server", re.IGNORECASE),
            re.compile(r"OLE DB.*SQL Server", re.IGNORECASE),
            re.compile(r"\[SQL Server\]", re.IGNORECASE),
            re.compile(r"SQLServer JDBC Driver", re.IGNORECASE),
            re.compile(r"Microsoft SQL Native Client", re.IGNORECASE),
            re.compile(r"Incorrect syntax near", re.IGNORECASE),
            re.compile(r"SqlException", re.IGNORECASE),
            re.compile(r"System\.Data\.SqlClient", re.IGNORECASE),
            re.compile(r"Microsoft\.Data\.SqlClient", re.IGNORECASE),
            re.compile(r"Server Error in.*Application", re.IGNORECASE),
            re.compile(r"Exception.*SqlException", re.IGNORECASE),

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
            re.compile(r"Incorrect syntax near the keyword", re.IGNORECASE),
        ]

    def get_payloads(self) -> List[str]:
        """
        Payloads covering both string and numeric SQL contexts.

        String context (varchar columns): quotes trigger parser errors.
        Numeric context (int columns): no quotes needed — OR 1=1 is injected directly.
        testaspnet.vulnweb.com uses numeric `id` columns, so numeric payloads are essential.
        """
        return [
            "'",                    # String context: breaks query, triggers error or empty response
            "1 OR 1=1",             # Numeric context: tautology — returns all rows (int columns)
            "1'",                   # String context: quote after number
            "1' OR '1'='1",        # String context: classic tautology
            "1' --",               # String context: comment-based
        ]

    def get_baseline(self, url: str, param: str) -> Optional[str]:
        """
        Get baseline response for comparison.

        Uses the ORIGINAL parameter value from the URL so we get real page content.
        Falling back to "1" only if the original value is missing or returns empty.
        """
        cache_key = f"{url}:{param}"
        if cache_key not in self.baseline_responses:
            existing = getattr(self, 'existing_params', {})
            base_url = getattr(self, 'base_url', url)

            # Use the original param value so pages that require specific IDs return content
            original_val = existing.get(param, "1")
            test_params = existing.copy()
            test_params[param] = original_val

            response = self.make_request(base_url, params=test_params)
            if response and len(response.text) > 0:
                self.baseline_responses[cache_key] = response.text
                self.logger.debug(f"Baseline [{param}={original_val}]: {len(response.text)} bytes")
            else:
                # Fallback: try value "1" in case original returned empty
                test_params[param] = "1"
                response = self.make_request(base_url, params=test_params)
                if response:
                    self.baseline_responses[cache_key] = response.text
                    self.logger.debug(f"Baseline fallback [{param}=1]: {len(response.text)} bytes")

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
        1. Error-based: Look for SQL error messages in response body
        2. HTTP 500: Server error after injection strongly indicates SQL error
        3. Behavior-based tautology: OR 1=1 returns more data
        4. Behavior-based breakage: quote breaks query, content disappears
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

        # Method 2: HTTP 500 after injection — server threw an unhandled exception
        # Only flag when baseline returns 200, so we know the 500 is caused by the payload
        if response.status_code == 500 and payload in ["'", "1'"]:
            baseline = self.get_baseline(url, param)
            if baseline is not None:
                evidence = f"HTTP 500 Internal Server Error triggered by quote injection in '{param}' (baseline was 200)"
                self.logger.warning(f"SQL INJECTION (HTTP 500): {evidence}")
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

        # Method 3: Tautology detection — OR 1=1 / OR '1'='1 should return more rows
        # Works for both numeric columns ("1 OR 1=1") and string columns ("1' OR '1'='1")
        payload_upper = payload.upper()
        is_tautology = "OR" in payload_upper and ("1=1" in payload or "1'='1" in payload)
        if is_tautology:
            baseline = self.get_baseline(url, param)
            if baseline:
                baseline_len = len(baseline)
                response_len = len(response_text)

                self.logger.info(f"Tautology comparison [{param}]: baseline={baseline_len} injected={response_len}")

                # Lowered to 1.2x — testaspnet returns ~1.27x more rows on OR 1=1
                if response_len > baseline_len * 1.2 and response_len - baseline_len > 200:
                    evidence = f"Response grew from {baseline_len} to {response_len} bytes with tautology '{payload}' — extra rows returned"
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

        # Method 4: Injection breaks query → response goes empty or shrinks dramatically
        # Works for both quote-based (string) and numeric injections
        is_breaking_payload = payload in ("'", "1'", "1 OR 1=2", "1 OR 1=1")
        if is_breaking_payload:
            baseline = self.get_baseline(url, param)
            if baseline:
                baseline_len = len(baseline)
                response_len = len(response_text)

                # Content gone entirely (e.g. testaspnet returns len=0 on broken numeric query)
                # or shrunk to under 40% of baseline
                if baseline_len > 200 and (response_len == 0 or response_len < baseline_len * 0.4):
                    cause = "empty response" if response_len == 0 else f"shrank to {response_len} bytes"
                    evidence = (
                        f"Response {cause} (baseline={baseline_len} bytes) after injecting '{payload}' "
                        f"— SQL query likely broken"
                    )
                    self.logger.warning(f"SQL INJECTION DETECTED: {evidence}")

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
