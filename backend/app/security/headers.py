"""
Security Headers Module

Implements security headers and HTTPS enforcement:
- Content Security Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security (HSTS)
- X-XSS-Protection
- Referrer-Policy

OWASP Reference: Security headers prevent various attacks
(OWASP Secure Headers Project)
"""

import os
from typing import Optional
from flask import Flask, request, redirect


class SecurityHeaders:
    """
    Security headers configuration and middleware.

    Adds security headers to all responses and optionally
    enforces HTTPS in production.
    """

    def __init__(
        self,
        enforce_https: bool = False,
        csp_policy: Optional[str] = None,
        hsts_max_age: int = 31536000  # 1 year
    ):
        """
        Initialize security headers configuration.

        Args:
            enforce_https: Whether to redirect HTTP to HTTPS
            csp_policy: Custom Content-Security-Policy header
            hsts_max_age: HSTS max-age in seconds
        """
        self.enforce_https = enforce_https
        self.hsts_max_age = hsts_max_age

        # Default CSP policy - restrictive but functional
        self.csp_policy = csp_policy or (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "base-uri 'self'"
        )

    def init_app(self, app: Flask):
        """
        Initialize the security headers middleware on a Flask app.

        Args:
            app: Flask application instance
        """
        @app.before_request
        def before_request():
            # Enforce HTTPS in production
            if self.enforce_https:
                # Check if behind a proxy (X-Forwarded-Proto)
                proto = request.headers.get('X-Forwarded-Proto', 'http')
                if proto != 'https' and not request.is_secure:
                    # Don't redirect health checks
                    if request.path not in ['/health', '/api/status']:
                        url = request.url.replace('http://', 'https://', 1)
                        return redirect(url, code=301)

        @app.after_request
        def after_request(response):
            # Security headers
            headers = {
                # Prevent MIME type sniffing
                'X-Content-Type-Options': 'nosniff',

                # Prevent clickjacking
                'X-Frame-Options': 'DENY',

                # XSS protection (legacy, but still useful)
                'X-XSS-Protection': '1; mode=block',

                # Referrer policy
                'Referrer-Policy': 'strict-origin-when-cross-origin',

                # Permissions policy (restrict browser features)
                'Permissions-Policy': (
                    'accelerometer=(), '
                    'camera=(), '
                    'geolocation=(), '
                    'gyroscope=(), '
                    'magnetometer=(), '
                    'microphone=(), '
                    'payment=(), '
                    'usb=()'
                ),

                # Content Security Policy
                'Content-Security-Policy': self.csp_policy,

                # Prevent caching of sensitive data
                'Cache-Control': 'no-store, no-cache, must-revalidate, private',
                'Pragma': 'no-cache',
                'Expires': '0',
            }

            # Add HSTS header only for HTTPS
            if request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https':
                headers['Strict-Transport-Security'] = (
                    f'max-age={self.hsts_max_age}; includeSubDomains; preload'
                )

            # Apply headers
            for header, value in headers.items():
                response.headers[header] = value

            return response


def create_security_headers(
    enforce_https: Optional[bool] = None,
    csp_policy: Optional[str] = None
) -> SecurityHeaders:
    """
    Create a SecurityHeaders instance with environment-aware defaults.

    Args:
        enforce_https: Override HTTPS enforcement (defaults to env var)
        csp_policy: Custom CSP policy

    Returns:
        Configured SecurityHeaders instance
    """
    # Default: enforce HTTPS in production
    if enforce_https is None:
        env = os.getenv('FLASK_ENV', 'development')
        enforce_https = env == 'production'

    return SecurityHeaders(
        enforce_https=enforce_https,
        csp_policy=csp_policy
    )
