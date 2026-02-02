"""
GlitchForge Base Scanner - Rebuilt for Speed and Accuracy
Simple, fast, and reliable vulnerability scanning
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from urllib.parse import urlparse, parse_qs, urljoin
import requests
import time

from app.utils.logger import get_logger


class VulnerabilityType(Enum):
    """Vulnerability types"""
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting (XSS)"
    CSRF = "Cross-Site Request Forgery (CSRF)"


class SeverityLevel(Enum):
    """Severity levels"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class VulnerabilityResult:
    """Vulnerability finding"""
    vuln_type: VulnerabilityType
    severity: SeverityLevel
    url: str
    parameter: str
    payload: str
    evidence: str
    confidence: float
    timestamp: datetime

    def to_dict(self):
        """Convert to dictionary for JSON export"""
        return {
            'type': self.vuln_type.value,
            'severity': self.severity.value,
            'url': self.url,
            'parameter': self.parameter,
            'payload': self.payload,
            'evidence': self.evidence,
            'confidence': self.confidence,
            'timestamp': self.timestamp.isoformat()
        }


class BaseScanner(ABC):
    """
    Base scanner class - keeps things simple and fast

    Design principles:
    - Test only what's likely to be vulnerable
    - Use only reliable detection methods
    - Stop testing as soon as we find something
    - No over-engineering
    """

    def __init__(self, config: Dict):
        self.config = config
        self.logger = get_logger(self.__class__.__name__)
        self.timeout = config.get('timeout', 15)
        self.user_agent = config.get('user_agent', 'GlitchForge/2.0')
        self.vulnerabilities = []
        self.request_count = 0

    def make_request(
        self,
        url: str,
        method: str = 'GET',
        params: Dict = None,
        data: Dict = None,
        allow_redirects: bool = True
    ) -> Optional[requests.Response]:
        """Make HTTP request with error handling"""
        try:
            headers = {'User-Agent': self.user_agent}
            self.request_count += 1

            if method == 'GET':
                response = requests.get(
                    url,
                    params=params,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=allow_redirects,
                    verify=False
                )
            else:
                response = requests.post(
                    url,
                    data=data,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=allow_redirects,
                    verify=False
                )

            return response

        except requests.Timeout:
            self.logger.debug(f"Request timeout: {url}")
            return None
        except requests.RequestException as e:
            self.logger.debug(f"Request failed: {str(e)}")
            return None

    def discover_parameters(self, url: str) -> List[str]:
        """
        Discover parameters - focus on injectable ones

        Smart filtering:
        - Skip tracking params (utm_*, fbclid, etc.)
        - Skip UI state params (tab, view, page, etc.)
        - Skip hash fragments (#inbox, #section1)
        - Prioritize query params over form params
        """
        params = []

        # Extract query parameters from URL
        parsed = urlparse(url)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            params.extend(query_params.keys())

        # Get form parameters from the page
        try:
            response = self.make_request(url)
            if response:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.content, 'html.parser')

                # Find input fields in forms
                for form in soup.find_all('form'):
                    for inp in form.find_all(['input', 'select', 'textarea']):
                        name = inp.get('name')
                        if name:
                            params.append(name)
        except Exception as e:
            self.logger.debug(f"Error discovering form params: {str(e)}")

        # Remove duplicates
        params = list(set(params))

        # Filter out non-injectable parameters
        SKIP_PARAMS = {
            # Tracking & analytics
            'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
            'fbclid', 'gclid', 'msclkid', '_ga', '_gid', 'mc_cid', 'mc_eid',
            # UI state (rarely injectable)
            'tab', 'view', 'page', 'section', 'panel', 'mode',
            # Navigation
            'sort', 'order', 'limit', 'offset', 'next', 'prev',
            # Google-specific
            'ogbl', 'emr', 'ifkv', 'osid', 'flowEntry', 'flowName',
            # Locale/language (safe in most cases)
            'lang', 'locale', 'hl',
            # Timestamps
            'timestamp', 'ts', 'time', '_', 'v', 'ver', 'version', 'cache',
            # Common safe params
            'ref', 'referrer', 'source', 'redirect_uri', 'return_url'
        }

        filtered = [p for p in params if p.lower() not in SKIP_PARAMS]

        # Limit to first 10 parameters (more than this is excessive)
        if len(filtered) > 10:
            self.logger.info(f"Limiting to 10 parameters (found {len(filtered)})")
            filtered = filtered[:10]

        self.logger.debug(f"Found {len(filtered)} testable parameters: {filtered}")
        return filtered

    @abstractmethod
    def get_payloads(self) -> List[str]:
        """Get payloads for this scanner - keep it minimal"""
        pass

    @abstractmethod
    def detect_vulnerability(
        self,
        url: str,
        param: str,
        payload: str,
        response: requests.Response
    ) -> Optional[VulnerabilityResult]:
        """Detect if response indicates vulnerability"""
        pass

    def scan(self, url: str, parameters: Optional[List[str]] = None) -> List[VulnerabilityResult]:
        """
        Scan URL for vulnerabilities

        Simple approach:
        1. Discover parameters (or use provided ones)
        2. Test each parameter with payloads
        3. Stop after finding vulnerability for each parameter
        4. Return results
        """
        start_time = datetime.now()
        self.vulnerabilities = []
        self.request_count = 0

        self.logger.info(f"Starting scan: {url}")

        # Discover or use provided parameters
        if parameters is None:
            parameters = self.discover_parameters(url)

        if not parameters:
            self.logger.info("No parameters found - nothing to test")
            return []

        # Get payloads
        payloads = self.get_payloads()

        # Test each parameter
        for param in parameters:
            # Try each payload until we find a vulnerability
            for payload in payloads:
                # Make request with payload
                response = self.make_request(url, method='GET', params={param: payload})

                if not response:
                    continue

                # Check if vulnerable
                result = self.detect_vulnerability(url, param, payload, response)

                if result:
                    self.vulnerabilities.append(result)
                    self.logger.warning(f"Found {result.vuln_type.value} in parameter '{param}'")
                    # Stop testing this parameter - we found a vulnerability
                    break

                # Small delay to be polite
                time.sleep(0.05)

        duration = (datetime.now() - start_time).total_seconds()
        self.logger.info(
            f"Scan complete: {len(self.vulnerabilities)} vulnerabilities "
            f"in {duration:.1f}s ({self.request_count} requests)"
        )

        return self.vulnerabilities
