"""
SQL Injection Scanner - Fast and Accurate
Error-based detection only - the most reliable method
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
    - Error-based detection ONLY (fastest and most reliable)
    - 4 simple payloads that trigger database errors
    - Look for database error messages in response
    - No time delays, no boolean logic, no union queries
    """

    def __init__(self, config):
        super().__init__(config)

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

    def detect_vulnerability(
        self,
        url: str,
        param: str,
        payload: str,
        response: requests.Response
    ) -> Optional[VulnerabilityResult]:
        """
        Check if response contains SQL error messages

        Simple and reliable:
        - Search response for database error patterns
        - If found, it's definitely vulnerable
        - Extract error message as evidence
        """
        response_text = response.text

        # Check each pattern
        for pattern in self.error_patterns:
            match = pattern.search(response_text)
            if match:
                # Found SQL error - definite vulnerability!
                evidence = match.group(0)[:200]  # First 200 chars of error

                self.logger.debug(f"SQL error found: {evidence}")

                return VulnerabilityResult(
                    vuln_type=VulnerabilityType.SQL_INJECTION,
                    severity=SeverityLevel.HIGH,
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=evidence,
                    confidence=0.95,  # Error-based is very reliable
                    timestamp=datetime.now()
                )

        return None
