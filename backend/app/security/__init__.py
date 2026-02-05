"""
GlitchForge Security Module

This module provides security features including:
- Rate limiting (IP and user-based)
- Input validation and sanitization
- Authentication (OAuth 2.0)
- Role-Based Access Control (RBAC)
- Security headers and HTTPS enforcement
"""

from app.security.rate_limiter import RateLimiter, rate_limit
from app.security.validation import (
    ScanRequestSchema,
    validate_request,
    sanitize_url,
    sanitize_cookies
)
from app.security.auth import (
    AuthManager,
    require_auth,
    get_current_user
)
from app.security.rbac import (
    Permission,
    Role,
    require_permission
)
from app.security.headers import SecurityHeaders

__all__ = [
    'RateLimiter',
    'rate_limit',
    'ScanRequestSchema',
    'validate_request',
    'sanitize_url',
    'sanitize_cookies',
    'AuthManager',
    'require_auth',
    'get_current_user',
    'Permission',
    'Role',
    'require_permission',
    'SecurityHeaders'
]
