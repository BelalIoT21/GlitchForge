"""
URL Crawler for GlitchForge
Discovers sub-URLs from a base URL for comprehensive scanning
"""
from typing import List, Set, Dict, Optional
from urllib.parse import urlparse, urljoin, parse_qs
import requests
from bs4 import BeautifulSoup
import re

from app.utils.logger import get_logger


class URLCrawler:
    """
    Simple URL crawler that discovers scannable pages from a base URL

    Features:
    - Discovers links from anchor tags and form actions
    - Stays within the same domain
    - Limits crawl depth to avoid infinite loops
    - Identifies pages with parameters (likely vulnerable)
    - Special handling for known vulnerable apps (DVWA, etc.)
    """

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.logger = get_logger("URLCrawler")
        self.timeout = self.config.get('timeout', 10)
        self.user_agent = self.config.get('user_agent', 'GlitchForge/2.0')
        self.cookies = self.config.get('cookies', {})
        self.max_depth = self.config.get('max_depth', 3)
        self.max_urls = self.config.get('max_urls', 50)

        self.visited: Set[str] = set()
        self.discovered: Set[str] = set()
        self.request_count = 0

    def crawl(self, base_url: str) -> List[str]:
        """
        Crawl from base URL and return list of discovered URLs to scan

        Args:
            base_url: Starting URL to crawl from

        Returns:
            List of URLs to scan (prioritized by likely vulnerability)
        """
        self.visited.clear()
        self.discovered.clear()
        self.request_count = 0

        parsed = urlparse(base_url)
        self.base_domain = parsed.netloc
        self.base_scheme = parsed.scheme

        self.logger.info(f"Starting crawl from: {base_url}")

        # Check for known vulnerable apps and use predefined paths
        known_paths = self._get_known_paths(base_url)
        if known_paths:
            self.logger.info(f"Detected known app - using {len(known_paths)} predefined paths")
            return known_paths

        # General crawl
        self._crawl_recursive(base_url, depth=0)

        # Prioritize URLs with parameters
        urls = list(self.discovered)
        urls = self._prioritize_urls(urls)

        self.logger.info(f"Crawl complete: {len(urls)} URLs discovered ({self.request_count} requests)")

        return urls[:self.max_urls]

    def _get_known_paths(self, base_url: str) -> Optional[List[str]]:
        """Return predefined paths for known vulnerable applications"""

        url_lower = base_url.lower()

        # DVWA - Damn Vulnerable Web Application
        if 'dvwa' in url_lower:
            # Extract base DVWA path
            parsed = urlparse(base_url)
            path_parts = parsed.path.rstrip('/').split('/')

            # Find DVWA in path
            dvwa_base = base_url.rstrip('/')
            if 'dvwa' not in parsed.path.lower():
                dvwa_base = f"{parsed.scheme}://{parsed.netloc}/DVWA"
            else:
                # Find DVWA segment and build base
                for i, part in enumerate(path_parts):
                    if part.lower() == 'dvwa':
                        dvwa_base = f"{parsed.scheme}://{parsed.netloc}" + '/'.join(path_parts[:i+1])
                        break

            return [
                f"{dvwa_base}/vulnerabilities/sqli/",
                f"{dvwa_base}/vulnerabilities/sqli_blind/",
                f"{dvwa_base}/vulnerabilities/xss_r/",
                f"{dvwa_base}/vulnerabilities/xss_s/",
                f"{dvwa_base}/vulnerabilities/xss_d/",
                f"{dvwa_base}/vulnerabilities/csrf/",
                f"{dvwa_base}/vulnerabilities/exec/",
                f"{dvwa_base}/vulnerabilities/fi/.?page=include.php",
                f"{dvwa_base}/vulnerabilities/upload/",
                f"{dvwa_base}/vulnerabilities/captcha/",
                f"{dvwa_base}/vulnerabilities/brute/",
                f"{dvwa_base}/vulnerabilities/weak_id/",
                f"{dvwa_base}/vulnerabilities/csp/",
                f"{dvwa_base}/vulnerabilities/javascript/",
            ]

        # testphp.vulnweb.com - Acunetix test site
        if 'testphp.vulnweb.com' in url_lower or 'vulnweb.com' in url_lower:
            base = "http://testphp.vulnweb.com"
            return [
                f"{base}/listproducts.php?cat=1",
                f"{base}/artists.php?artist=1",
                f"{base}/showimage.php?file=./pictures/1.jpg",
                f"{base}/search.php?test=query",
                f"{base}/comment.php?aid=1",
                f"{base}/guestbook.php",
                f"{base}/cart.php",
                f"{base}/login.php",
                f"{base}/signup.php",
                f"{base}/userinfo.php",
                f"{base}/product.php?pic=1",
                f"{base}/hpp/?pp=12",
                f"{base}/Mod_Rewrite_Numeric/1",
                f"{base}/AJAX/index.php",
            ]

        # bWAPP - Buggy Web Application
        if 'bwapp' in url_lower:
            parsed = urlparse(base_url)
            bwapp_base = f"{parsed.scheme}://{parsed.netloc}/bWAPP"
            return [
                f"{bwapp_base}/sqli_1.php",
                f"{bwapp_base}/sqli_2.php",
                f"{bwapp_base}/sqli_6.php",
                f"{bwapp_base}/xss_get.php",
                f"{bwapp_base}/xss_post.php",
                f"{bwapp_base}/xss_stored_1.php",
                f"{bwapp_base}/csrf_1.php",
                f"{bwapp_base}/csrf_2.php",
            ]

        return None

    def _crawl_recursive(self, url: str, depth: int):
        """Recursively crawl URLs up to max depth"""

        if depth > self.max_depth:
            return

        if url in self.visited:
            return

        if len(self.discovered) >= self.max_urls:
            return

        # Normalize URL
        url = self._normalize_url(url)
        if not url:
            return

        # Check if same domain
        parsed = urlparse(url)
        if parsed.netloc != self.base_domain:
            return

        # Skip non-HTML resources
        skip_extensions = {'.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg',
                          '.ico', '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip'}
        if any(parsed.path.lower().endswith(ext) for ext in skip_extensions):
            return

        self.visited.add(url)

        # Fetch page
        try:
            response = self._make_request(url)
            if not response:
                return

            # Add to discovered if it has forms or parameters
            if self._is_scannable(url, response):
                self.discovered.add(url)

            # Parse and extract links
            soup = BeautifulSoup(response.content, 'html.parser')

            # Extract links from anchors
            for a in soup.find_all('a', href=True):
                href = a['href']
                full_url = urljoin(url, href)
                self._crawl_recursive(full_url, depth + 1)

            # Extract form actions
            for form in soup.find_all('form'):
                action = form.get('action', '')
                if action:
                    full_url = urljoin(url, action)
                    # Add form URL directly as scannable
                    normalized = self._normalize_url(full_url)
                    if normalized and urlparse(normalized).netloc == self.base_domain:
                        self.discovered.add(normalized)

        except Exception as e:
            self.logger.debug(f"Error crawling {url}: {e}")

    def _make_request(self, url: str) -> Optional[requests.Response]:
        """Make HTTP request with error handling"""
        try:
            self.request_count += 1
            response = requests.get(
                url,
                headers={'User-Agent': self.user_agent},
                cookies=self.cookies,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False
            )
            return response
        except Exception as e:
            self.logger.debug(f"Request failed for {url}: {e}")
            return None

    def _normalize_url(self, url: str) -> Optional[str]:
        """Normalize URL for deduplication"""
        try:
            parsed = urlparse(url)

            # Must have scheme and netloc
            if not parsed.scheme or not parsed.netloc:
                return None

            # Remove fragment
            normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                normalized += f"?{parsed.query}"

            return normalized
        except:
            return None

    def _is_scannable(self, url: str, response: requests.Response) -> bool:
        """Determine if URL is worth scanning"""

        # URLs with query parameters are interesting
        parsed = urlparse(url)
        if parsed.query:
            return True

        # Check for forms in response
        try:
            soup = BeautifulSoup(response.content, 'html.parser')
            forms = soup.find_all('form')
            if forms:
                return True

            # Check for input fields
            inputs = soup.find_all('input')
            if len(inputs) > 0:
                return True

        except:
            pass

        return False

    def _prioritize_urls(self, urls: List[str]) -> List[str]:
        """Sort URLs by likely vulnerability (parameterized first)"""

        def score(url: str) -> int:
            s = 0
            url_lower = url.lower()

            # URLs with parameters score highest
            if '?' in url:
                s += 100

            # Known vulnerable patterns
            vuln_patterns = ['sqli', 'xss', 'csrf', 'exec', 'upload', 'file',
                           'search', 'query', 'id=', 'user', 'login', 'admin']
            for pattern in vuln_patterns:
                if pattern in url_lower:
                    s += 50

            # PHP/ASP pages more likely vulnerable than static
            if '.php' in url_lower or '.asp' in url_lower:
                s += 20

            return s

        return sorted(urls, key=score, reverse=True)
