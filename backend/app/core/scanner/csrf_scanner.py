"""
CSRF Scanner - Simple and Accurate
Checks for CSRF protection mechanisms
"""
from typing import List, Optional
from datetime import datetime
import requests
import re

from .base_scanner import (
    BaseScanner,
    VulnerabilityResult,
    VulnerabilityType,
    SeverityLevel
)


class CSRFScanner(BaseScanner):
    """
    CSRF Scanner

    Strategy:
    - Check forms for CSRF tokens
    - Check for SameSite cookies
    - Check for CSRF headers (X-CSRF-Token, etc.)
    - Skip login/auth pages (use different protection)
    - Simple boolean detection
    """

    def __init__(self, config):
        super().__init__(config)

    def get_payloads(self) -> List[str]:
        """CSRF doesn't use payloads"""
        return []

    def detect_vulnerability(
        self,
        url: str,
        param: str,
        payload: str,
        response: requests.Response
    ) -> Optional[VulnerabilityResult]:
        """Not used for CSRF - we override scan() instead"""
        return None

    def scan(self, url: str, parameters: Optional[List[str]] = None) -> List[VulnerabilityResult]:
        """
        Check for CSRF vulnerabilities

        Different from other scanners - we check forms, not parameters
        """
        start_time = datetime.now()
        self.vulnerabilities = []
        self.request_count = 0

        self.logger.info(f"Starting CSRF scan: {url}")

        try:
            response = self.make_request(url)
            if not response:
                return []

            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.content, 'html.parser')

            # Check each form
            forms = soup.find_all('form')

            if not forms:
                self.logger.debug("No forms found")
                return []

            for form in forms:
                method = (form.get('method') or 'get').upper()

                # For GET forms, only flag if they do state-changing operations
                # (like password change - common DVWA test case)
                if method == 'GET':
                    if not self._is_state_changing_form(form):
                        self.logger.debug("Skipping non-state-changing GET form")
                        continue
                    self.logger.info("Found state-changing GET form (itself a vulnerability)")

                # Check if this is a login form (different protection)
                if self._is_login_form(form):
                    self.logger.debug("Skipping login form")
                    continue

                # Check for CSRF protection
                has_csrf_token = self._has_csrf_token(form)
                has_samesite = self._has_samesite_cookie(response)
                has_csrf_header = self._has_csrf_header(response)

                # If no protection found, it's vulnerable
                if not (has_csrf_token or has_samesite or has_csrf_header):
                    self.vulnerabilities.append(
                        VulnerabilityResult(
                            vuln_type=VulnerabilityType.CSRF,
                            severity=SeverityLevel.MEDIUM,
                            url=url,
                            parameter="form",
                            payload="N/A",
                            evidence="No CSRF protection found (no token, SameSite cookie, or CSRF header)",
                            confidence=0.80,
                            timestamp=datetime.now()
                        )
                    )
                    self.logger.warning("CSRF vulnerability found")
                    # Only report once per page
                    break

        except Exception as e:
            self.logger.error(f"CSRF scan error: {str(e)}")

        duration = (datetime.now() - start_time).total_seconds()
        self.logger.info(f"CSRF scan complete in {duration:.1f}s")

        return self.vulnerabilities

    def _has_csrf_token(self, form) -> bool:
        """Check if form has CSRF token field"""
        token_names = [
            'csrf', 'csrf_token', 'csrftoken', '_csrf', 'token',
            'authenticity_token', '_token', 'xsrf', 'xsrf_token'
        ]

        inputs = form.find_all('input', type='hidden')
        for inp in inputs:
            name = (inp.get('name') or '').lower()
            if any(token_name in name for token_name in token_names):
                return True

        return False

    def _has_samesite_cookie(self, response: requests.Response) -> bool:
        """Check for SameSite cookie attribute"""
        set_cookie = response.headers.get('Set-Cookie', '').lower()
        return 'samesite=strict' in set_cookie or 'samesite=lax' in set_cookie

    def _has_csrf_header(self, response: requests.Response) -> bool:
        """Check for CSRF protection headers"""
        csrf_headers = ['x-csrf-token', 'x-xsrf-token', 'csrf-token']

        for header in csrf_headers:
            if header in [h.lower() for h in response.headers.keys()]:
                return True

        # Check if Set-Cookie includes CSRF tokens
        set_cookie = response.headers.get('Set-Cookie', '').lower()
        if 'xsrf-token' in set_cookie or 'csrf-token' in set_cookie:
            return True

        return False

    def _is_login_form(self, form) -> bool:
        """
        Check if form is a login/auth form

        Login forms use different CSRF protection (session-based)
        so we shouldn't flag them
        """
        # Check form action
        action = (form.get('action') or '').lower()
        if any(keyword in action for keyword in ['login', 'signin', 'auth', 'sso']):
            return True

        # Check for password field (strong indicator)
        inputs = form.find_all('input')
        has_password = any(inp.get('type') == 'password' for inp in inputs)

        # Check for username/email field
        has_username = any(
            inp.get('type') in ['email', 'text'] and
            (inp.get('name') or '').lower() in ['email', 'username', 'user', 'login']
            for inp in inputs
        )

        return has_password and has_username

    def _is_state_changing_form(self, form) -> bool:
        """
        Check if a GET form performs state-changing operations

        GET forms shouldn't change state, but some vulnerable apps do this.
        Examples: password change, delete account, update settings
        """
        # Check form action for state-changing keywords
        action = (form.get('action') or '').lower()
        state_changing_actions = [
            'change', 'update', 'delete', 'remove', 'modify',
            'password', 'passwd', 'pwd', 'settings', 'profile',
            'csrf'  # DVWA's CSRF test page
        ]
        if any(keyword in action for keyword in state_changing_actions):
            return True

        # Check for password fields (new password for change)
        inputs = form.find_all('input')
        password_fields = [inp for inp in inputs if inp.get('type') == 'password']

        # If there's a password field but it's not a login form, it's likely a password change
        if password_fields:
            # Login forms have username + password
            # Password change forms often have just password fields (new_password, confirm_password)
            has_username = any(
                inp.get('type') in ['email', 'text'] and
                (inp.get('name') or '').lower() in ['email', 'username', 'user', 'login']
                for inp in inputs
            )
            if not has_username:
                return True

        # Check input names for state-changing operations
        state_changing_params = [
            'new_password', 'password_new', 'password_conf', 'confirm',
            'change', 'update', 'delete'
        ]
        for inp in inputs:
            name = (inp.get('name') or '').lower()
            if any(param in name for param in state_changing_params):
                return True

        return False
