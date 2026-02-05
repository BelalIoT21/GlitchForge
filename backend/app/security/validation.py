"""
Input Validation and Sanitization Module

Implements strict input validation following OWASP guidelines:
- Schema-based validation with type checking
- Length limits to prevent buffer overflow attacks
- Input sanitization to prevent injection attacks
- Rejection of unexpected fields

OWASP Reference: Input validation is critical for preventing
injection attacks (OWASP Top 10 - A03:2021 Injection)
"""

import re
from typing import Dict, List, Optional, Any, Tuple
from functools import wraps
from urllib.parse import urlparse, parse_qs
from flask import request, jsonify


# Maximum lengths for various input fields
MAX_URL_LENGTH = 2048
MAX_COOKIE_NAME_LENGTH = 128
MAX_COOKIE_VALUE_LENGTH = 4096
MAX_COOKIES_COUNT = 20
MAX_SCAN_TYPES = 10
MAX_URLS = 50

# Allowed scan types (whitelist approach)
ALLOWED_SCAN_TYPES = {'sql', 'xss', 'csrf'}

# URL scheme whitelist
ALLOWED_SCHEMES = {'http', 'https'}

# Dangerous patterns that should be rejected
DANGEROUS_PATTERNS = [
    r'javascript:',
    r'data:',
    r'vbscript:',
    r'file:',
    r'<script',
    r'</script',
    r'onerror=',
    r'onload=',
]


class ValidationError(Exception):
    """Custom exception for validation errors."""
    def __init__(self, message: str, field: Optional[str] = None):
        self.message = message
        self.field = field
        super().__init__(self.message)


class ScanRequestSchema:
    """
    Schema definition for scan request validation.

    Defines required/optional fields, types, and constraints
    for the /api/scan endpoint.
    """

    REQUIRED_FIELDS = {'url'}
    OPTIONAL_FIELDS = {'scan_types', 'cookies', 'crawl', 'max_urls'}
    ALL_FIELDS = REQUIRED_FIELDS | OPTIONAL_FIELDS

    @staticmethod
    def validate(data: Dict) -> Tuple[bool, Optional[str]]:
        """
        Validate scan request data against schema.

        Args:
            data: Request JSON data

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not isinstance(data, dict):
            return False, "Request body must be a JSON object"

        # Check for unexpected fields (reject unknown fields)
        unexpected = set(data.keys()) - ScanRequestSchema.ALL_FIELDS
        if unexpected:
            return False, f"Unexpected fields: {', '.join(unexpected)}"

        # Check required fields
        missing = ScanRequestSchema.REQUIRED_FIELDS - set(data.keys())
        if missing:
            return False, f"Missing required fields: {', '.join(missing)}"

        # Validate URL
        url = data.get('url')
        is_valid, error = validate_url(url)
        if not is_valid:
            return False, f"Invalid URL: {error}"

        # Validate scan_types if provided
        scan_types = data.get('scan_types', [])
        if not isinstance(scan_types, list):
            return False, "scan_types must be an array"
        if len(scan_types) > MAX_SCAN_TYPES:
            return False, f"Too many scan types (max {MAX_SCAN_TYPES})"
        invalid_types = set(scan_types) - ALLOWED_SCAN_TYPES
        if invalid_types:
            return False, f"Invalid scan types: {', '.join(invalid_types)}"

        # Validate cookies if provided
        cookies = data.get('cookies')
        if cookies is not None:
            if not isinstance(cookies, dict):
                return False, "cookies must be an object"
            is_valid, error = validate_cookies(cookies)
            if not is_valid:
                return False, f"Invalid cookies: {error}"

        # Validate crawl flag
        crawl = data.get('crawl')
        if crawl is not None and not isinstance(crawl, bool):
            return False, "crawl must be a boolean"

        # Validate max_urls
        max_urls = data.get('max_urls')
        if max_urls is not None:
            if not isinstance(max_urls, int):
                return False, "max_urls must be an integer"
            if max_urls < 1 or max_urls > MAX_URLS:
                return False, f"max_urls must be between 1 and {MAX_URLS}"

        return True, None


def validate_url(url: str) -> Tuple[bool, Optional[str]]:
    """
    Validate and sanitize a URL.

    Checks:
    - Length limits
    - Valid URL format
    - Allowed scheme (http/https only)
    - No dangerous patterns

    Args:
        url: URL string to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(url, str):
        return False, "URL must be a string"

    if not url.strip():
        return False, "URL cannot be empty"

    if len(url) > MAX_URL_LENGTH:
        return False, f"URL too long (max {MAX_URL_LENGTH} characters)"

    # Check for dangerous patterns
    url_lower = url.lower()
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, url_lower, re.IGNORECASE):
            return False, f"URL contains dangerous pattern"

    # Parse URL
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL format"

    # Check scheme
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return False, f"Invalid scheme. Allowed: {', '.join(ALLOWED_SCHEMES)}"

    # Check netloc (hostname)
    if not parsed.netloc:
        return False, "URL must include a hostname"

    return True, None


def validate_cookies(cookies: Dict) -> Tuple[bool, Optional[str]]:
    """
    Validate cookie dictionary.

    Checks:
    - Maximum number of cookies
    - Cookie name/value lengths
    - No dangerous patterns in values

    Args:
        cookies: Dictionary of cookie name-value pairs

    Returns:
        Tuple of (is_valid, error_message)
    """
    if len(cookies) > MAX_COOKIES_COUNT:
        return False, f"Too many cookies (max {MAX_COOKIES_COUNT})"

    for name, value in cookies.items():
        if not isinstance(name, str) or not isinstance(value, str):
            return False, "Cookie names and values must be strings"

        if len(name) > MAX_COOKIE_NAME_LENGTH:
            return False, f"Cookie name too long (max {MAX_COOKIE_NAME_LENGTH})"

        if len(value) > MAX_COOKIE_VALUE_LENGTH:
            return False, f"Cookie value too long (max {MAX_COOKIE_VALUE_LENGTH})"

        # Check for dangerous patterns in cookie values
        for pattern in DANGEROUS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                return False, "Cookie value contains dangerous pattern"

    return True, None


def sanitize_url(url: str) -> str:
    """
    Sanitize a URL by removing potentially dangerous elements.

    Args:
        url: URL to sanitize

    Returns:
        Sanitized URL string
    """
    # Strip whitespace
    url = url.strip()

    # Parse and reconstruct to normalize
    parsed = urlparse(url)

    # Reconstruct URL without fragment
    sanitized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    if parsed.query:
        sanitized += f"?{parsed.query}"

    return sanitized


def sanitize_cookies(cookies: Dict[str, str]) -> Dict[str, str]:
    """
    Sanitize cookie values.

    Args:
        cookies: Dictionary of cookie name-value pairs

    Returns:
        Sanitized cookie dictionary
    """
    sanitized = {}
    for name, value in cookies.items():
        # Strip whitespace
        clean_name = name.strip()
        clean_value = value.strip()

        # Only include if both name and value are non-empty
        if clean_name and clean_value:
            sanitized[clean_name] = clean_value

    return sanitized


def validate_request(schema_class):
    """
    Decorator to validate request JSON against a schema.

    Usage:
        @app.route('/api/scan', methods=['POST'])
        @validate_request(ScanRequestSchema)
        def scan():
            ...

    Args:
        schema_class: Schema class with validate() method

    Returns:
        Decorated function with validation applied
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get JSON data
            try:
                data = request.get_json(force=True)
            except Exception:
                return jsonify({
                    'success': False,
                    'error': 'Invalid JSON in request body'
                }), 400

            if data is None:
                return jsonify({
                    'success': False,
                    'error': 'Request body is required'
                }), 400

            # Validate against schema
            is_valid, error = schema_class.validate(data)
            if not is_valid:
                return jsonify({
                    'success': False,
                    'error': 'Validation failed',
                    'message': error
                }), 400

            return f(*args, **kwargs)

        return decorated_function
    return decorator
