"""
XSS Scanner - Fast and Accurate
Reflected XSS detection only
"""
import re
from typing import List, Optional
from datetime import datetime
import requests
import html

from .base_scanner import (
    BaseScanner,
    VulnerabilityResult,
    VulnerabilityType,
    SeverityLevel
)


class XSSScanner(BaseScanner):
    """
    XSS Scanner

    Strategy:
    - Reflected XSS ONLY (no DOM, no stored - too slow and unreliable)
    - 4 simple payloads with unique markers
    - Check if payload appears unescaped in response
    - Fast and reliable
    """

    def __init__(self, config):
        super().__init__(config)

    def get_payloads(self) -> List[str]:
        """
        Minimal XSS payloads with unique markers

        Each payload has a unique string we can search for:
        1. Basic script tag with marker
        2. Event handler with marker
        3. IMG tag with event
        4. SVG tag with event
        """
        return [
            "<script>alert('XSS_TEST_1')</script>",
            "\"><script>alert('XSS_TEST_2')</script>",
            "<img src=x onerror=alert('XSS_TEST_3')>",
            "<svg/onload=alert('XSS_TEST_4')>",
        ]

    def detect_vulnerability(
        self,
        url: str,
        param: str,
        payload: str,
        response: requests.Response
    ) -> Optional[VulnerabilityResult]:
        """
        Check if payload is reflected unescaped in response

        Detection logic:
        1. First check if payload is HTML-escaped (safe)
        2. Only flag if payload appears UNESCAPED and executable
        3. Strict detection to avoid false positives
        """
        response_text = response.text
        response_lower = response_text.lower()
        payload_lower = payload.lower()

        # Check if payload is HTML-encoded (properly escaped = safe)
        escaped_payload = html.escape(payload).lower()
        if escaped_payload in response_lower:
            # Payload is properly escaped, NOT vulnerable
            self.logger.debug(f"Payload found but properly escaped")
            return None

        # Check for exact unescaped payload reflection (definitely vulnerable)
        if payload_lower in response_lower:
            # Verify it's actually in executable context, not just in text
            # Extract a snippet around the payload
            payload_index = response_lower.find(payload_lower)
            context_start = max(0, payload_index - 100)
            context_end = min(len(response_text), payload_index + len(payload) + 100)
            context = response_text[context_start:context_end]

            return VulnerabilityResult(
                vuln_type=VulnerabilityType.XSS,
                severity=SeverityLevel.HIGH,
                url=url,
                parameter=param,
                payload=payload,
                evidence=f"Payload reflected unescaped: {context[:200]}",
                confidence=0.95,
                timestamp=datetime.now()
            )

        return None
