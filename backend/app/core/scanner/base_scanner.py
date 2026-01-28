"""
GlitchForge Base Scanner - Stage 1
Abstract base class for all vulnerability scanners
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import requests
from urllib.parse import urljoin, urlparse
import time

from app.utils.logger import get_logger


class VulnerabilityType(Enum):
    """Enumeration of vulnerability types"""
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting (XSS)"
    CSRF = "Cross-Site Request Forgery (CSRF)"
    UNKNOWN = "Unknown"


class SeverityLevel(Enum):
    """Severity levels for vulnerabilities"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


@dataclass
class VulnerabilityResult:
    """Data class for vulnerability detection results"""
    vuln_type: VulnerabilityType
    url: str
    parameter: str
    payload: str
    severity: SeverityLevel
    confidence: float  # 0.0 to 1.0
    description: str
    evidence: str
    remediation: str
    timestamp: datetime = field(default_factory=datetime.now)
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'vulnerability_type': self.vuln_type.value,
            'url': self.url,
            'parameter': self.parameter,
            'payload': self.payload,
            'severity': self.severity.value,
            'confidence': self.confidence,
            'description': self.description,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'timestamp': self.timestamp.isoformat(),
            'cvss_score': self.cvss_score,
            'cwe_id': self.cwe_id
        }


class BaseScanner(ABC):
    """
    Abstract base class for all vulnerability scanners
    
    All specific scanners (SQL Injection, XSS, CSRF) inherit from this class
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize base scanner
        
        Args:
            config: Scanner configuration dictionary
        """
        self.config = config
        self.timeout = config.get('timeout', 10)
        self.max_retries = config.get('max_retries', 3)
        self.user_agent = config.get('user_agent', 'GlitchForge/1.0')
        self.logger = get_logger(self.__class__.__name__)
        
        # Session for maintaining cookies and headers
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.user_agent})
        
        # Results storage
        self.vulnerabilities: List[VulnerabilityResult] = []
        self.scan_metadata = {
            'start_time': None,
            'end_time': None,
            'total_requests': 0,
            'total_vulnerabilities': 0
        }
    
    @abstractmethod
    def get_payloads(self) -> Dict[str, List[str]]:
        """
        Get payloads specific to this vulnerability type
        
        Returns:
            Dictionary of payload categories and their payloads
        """
        pass
    
    @abstractmethod
    def detect_vulnerability(
        self,
        url: str,
        parameter: str,
        payload: str,
        response: requests.Response
    ) -> Optional[VulnerabilityResult]:
        """
        Detect if a vulnerability exists based on response
        
        Args:
            url: Target URL
            parameter: Parameter being tested
            payload: Payload used
            response: HTTP response object
            
        Returns:
            VulnerabilityResult if vulnerability found, None otherwise
        """
        pass
    
    def make_request(
        self,
        url: str,
        method: str = 'GET',
        params: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Optional[requests.Response]:
        """
        Make HTTP request with retry logic
        
        Args:
            url: Target URL
            method: HTTP method (GET, POST, etc.)
            params: Query parameters
            data: POST data
            headers: Additional headers
            
        Returns:
            Response object or None if all retries failed
        """
        for attempt in range(self.max_retries):
            try:
                self.scan_metadata['total_requests'] += 1
                
                if method.upper() == 'GET':
                    response = self.session.get(
                        url,
                        params=params,
                        timeout=self.timeout,
                        headers=headers,
                        allow_redirects=True
                    )
                elif method.upper() == 'POST':
                    response = self.session.post(
                        url,
                        data=data,
                        timeout=self.timeout,
                        headers=headers,
                        allow_redirects=True
                    )
                else:
                    self.logger.error(f"Unsupported HTTP method: {method}")
                    return None
                
                return response
            
            except requests.Timeout:
                self.logger.warning(f"Request timeout for {url} (attempt {attempt + 1}/{self.max_retries})")
                if attempt < self.max_retries - 1:
                    time.sleep(1)
            
            except requests.ConnectionError:
                self.logger.error(f"Connection error for {url}")
                return None
            
            except Exception as e:
                self.logger.error(f"Unexpected error during request to {url}: {str(e)}")
                return None
        
        self.logger.error(f"All retry attempts failed for {url}")
        return None
    
    def scan(
        self,
        url: str,
        parameters: Optional[List[str]] = None,
        methods: Optional[List[str]] = None
    ) -> List[VulnerabilityResult]:
        """
        Scan URL for vulnerabilities
        
        Args:
            url: Target URL
            parameters: List of parameters to test (if None, will discover)
            methods: HTTP methods to test (default: ['GET', 'POST'])
            
        Returns:
            List of discovered vulnerabilities
        """
        self.scan_metadata['start_time'] = datetime.now()
        self.vulnerabilities = []
        
        if methods is None:
            methods = ['GET', 'POST']
        
        self.logger.info(f"Starting {self.__class__.__name__} scan on {url}")
        
        # Get payloads for this scanner
        payload_categories = self.get_payloads()
        
        # If no parameters specified, try to discover them
        if parameters is None:
            parameters = self.discover_parameters(url)
        
        if not parameters:
            self.logger.warning(f"No parameters found for {url}")
            parameters = ['id', 'name', 'search', 'query']  # Common parameter names
        
        # Test each parameter with each payload
        for param in parameters:
            for category, payloads in payload_categories.items():
                self.logger.debug(f"Testing parameter '{param}' with {category} payloads")
                
                for payload in payloads:
                    for method in methods:
                        result = self.test_payload(url, param, payload, method)
                        if result:
                            self.vulnerabilities.append(result)
                            self.scan_metadata['total_vulnerabilities'] += 1
                            self.logger.warning(
                                f"Vulnerability found: {result.vuln_type.value} "
                                f"in parameter '{param}' with payload '{payload[:50]}...'"
                            )
                        
                        # Small delay to avoid overwhelming the target
                        time.sleep(0.1)
        
        self.scan_metadata['end_time'] = datetime.now()
        duration = (self.scan_metadata['end_time'] - self.scan_metadata['start_time']).total_seconds()
        
        self.logger.info(
            f"Scan completed in {duration:.2f} seconds. "
            f"Found {len(self.vulnerabilities)} vulnerabilities "
            f"after {self.scan_metadata['total_requests']} requests."
        )
        
        return self.vulnerabilities
    
    def test_payload(
        self,
        url: str,
        parameter: str,
        payload: str,
        method: str = 'GET'
    ) -> Optional[VulnerabilityResult]:
        """
        Test a single payload on a parameter
        
        Args:
            url: Target URL
            parameter: Parameter name
            payload: Payload to test
            method: HTTP method
            
        Returns:
            VulnerabilityResult if vulnerability found, None otherwise
        """
        try:
            if method.upper() == 'GET':
                response = self.make_request(url, method='GET', params={parameter: payload})
            else:
                response = self.make_request(url, method='POST', data={parameter: payload})
            
            if response is None:
                return None
            
            # Let the specific scanner detect the vulnerability
            result = self.detect_vulnerability(url, parameter, payload, response)
            
            return result
        
        except Exception as e:
            self.logger.error(f"Error testing payload: {str(e)}")
            return None
    
    def discover_parameters(self, url: str) -> List[str]:
        """
        Discover parameters from URL and forms
        
        Args:
            url: Target URL
            
        Returns:
            List of discovered parameter names
        """
        parameters = []
        
        # Parse URL parameters
        parsed = urlparse(url)
        if parsed.query:
            from urllib.parse import parse_qs
            params = parse_qs(parsed.query)
            parameters.extend(params.keys())
        
        # Try to discover form parameters
        try:
            response = self.make_request(url)
            if response:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Find all input fields in forms
                for input_tag in soup.find_all('input'):
                    name = input_tag.get('name')
                    if name:
                        parameters.append(name)
                
                # Find select fields
                for select_tag in soup.find_all('select'):
                    name = select_tag.get('name')
                    if name:
                        parameters.append(name)
        
        except Exception as e:
            self.logger.debug(f"Error discovering parameters: {str(e)}")
        
        return list(set(parameters))  # Remove duplicates
    
    def get_results_summary(self) -> Dict[str, Any]:
        """
        Get summary of scan results
        
        Returns:
            Dictionary containing scan summary
        """
        if not self.scan_metadata['start_time']:
            return {'error': 'No scan has been performed'}
        
        duration = 0
        if self.scan_metadata['end_time']:
            duration = (
                self.scan_metadata['end_time'] - self.scan_metadata['start_time']
            ).total_seconds()
        
        severity_count = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for vuln in self.vulnerabilities:
            severity_count[vuln.severity.value.lower()] += 1
        
        return {
            'scanner_type': self.__class__.__name__,
            'scan_duration': duration,
            'total_requests': self.scan_metadata['total_requests'],
            'total_vulnerabilities': len(self.vulnerabilities),
            'severity_breakdown': severity_count,
            'start_time': self.scan_metadata['start_time'].isoformat() if self.scan_metadata['start_time'] else None,
            'end_time': self.scan_metadata['end_time'].isoformat() if self.scan_metadata['end_time'] else None
        }
    
    def export_results(self, format: str = 'json') -> str:
        """
        Export scan results
        
        Args:
            format: Export format ('json', 'csv', 'html')
            
        Returns:
            Formatted results string
        """
        if format == 'json':
            import json
            results = {
                'summary': self.get_results_summary(),
                'vulnerabilities': [v.to_dict() for v in self.vulnerabilities]
            }
            return json.dumps(results, indent=2)
        
        elif format == 'csv':
            import csv
            from io import StringIO
            output = StringIO()
            
            if not self.vulnerabilities:
                return "No vulnerabilities found"
            
            fieldnames = list(self.vulnerabilities[0].to_dict().keys())
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            
            for vuln in self.vulnerabilities:
                writer.writerow(vuln.to_dict())
            
            return output.getvalue()
        
        else:
            return f"Unsupported format: {format}"