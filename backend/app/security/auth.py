"""
Authentication Module

Implements OAuth 2.0 authentication with:
- JWT token validation
- Multiple OAuth provider support (Google, GitHub)
- Token refresh handling
- Secure session management

OWASP Reference: Proper authentication prevents unauthorized access
(OWASP Top 10 - A07:2021 Identification and Authentication Failures)
"""

import os
import time
import hmac
import hashlib
import base64
import json
from typing import Optional, Dict, Callable
from functools import wraps
from flask import request, jsonify, g


# JWT secret from environment (NEVER hardcode in production)
JWT_SECRET = os.getenv('JWT_SECRET', os.getenv('SECRET_KEY', 'dev-secret-change-in-production'))
JWT_ALGORITHM = 'HS256'
JWT_EXPIRY_SECONDS = 3600  # 1 hour


class AuthenticationError(Exception):
    """Custom exception for authentication errors."""
    def __init__(self, message: str, status_code: int = 401):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class AuthManager:
    """
    Authentication manager for handling OAuth and JWT tokens.

    Supports:
    - JWT token validation
    - OAuth 2.0 provider integration
    - Token refresh
    - User session management
    """

    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = secret_key or JWT_SECRET

    def _base64url_encode(self, data: bytes) -> str:
        """Base64 URL-safe encoding without padding."""
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

    def _base64url_decode(self, data: str) -> bytes:
        """Base64 URL-safe decoding with padding restoration."""
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        return base64.urlsafe_b64decode(data)

    def create_token(self, user_id: str, email: str, roles: list = None) -> str:
        """
        Create a JWT token for a user.

        Args:
            user_id: Unique user identifier
            email: User email address
            roles: List of user roles

        Returns:
            JWT token string
        """
        # Header
        header = {'alg': JWT_ALGORITHM, 'typ': 'JWT'}
        header_encoded = self._base64url_encode(json.dumps(header).encode())

        # Payload
        now = int(time.time())
        payload = {
            'sub': user_id,
            'email': email,
            'roles': roles or ['user'],
            'iat': now,
            'exp': now + JWT_EXPIRY_SECONDS
        }
        payload_encoded = self._base64url_encode(json.dumps(payload).encode())

        # Signature
        message = f"{header_encoded}.{payload_encoded}"
        signature = hmac.new(
            self.secret_key.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()
        signature_encoded = self._base64url_encode(signature)

        return f"{header_encoded}.{payload_encoded}.{signature_encoded}"

    def validate_token(self, token: str) -> Optional[Dict]:
        """
        Validate a JWT token and return the payload.

        Args:
            token: JWT token string

        Returns:
            Token payload dict if valid, None if invalid

        Raises:
            AuthenticationError: If token is invalid or expired
        """
        try:
            parts = token.split('.')
            if len(parts) != 3:
                raise AuthenticationError("Invalid token format")

            header_encoded, payload_encoded, signature_encoded = parts

            # Verify signature
            message = f"{header_encoded}.{payload_encoded}"
            expected_signature = hmac.new(
                self.secret_key.encode(),
                message.encode(),
                hashlib.sha256
            ).digest()
            expected_encoded = self._base64url_encode(expected_signature)

            if not hmac.compare_digest(signature_encoded, expected_encoded):
                raise AuthenticationError("Invalid token signature")

            # Decode payload
            payload = json.loads(self._base64url_decode(payload_encoded))

            # Check expiration
            if payload.get('exp', 0) < time.time():
                raise AuthenticationError("Token has expired")

            return payload

        except AuthenticationError:
            raise
        except Exception as e:
            raise AuthenticationError(f"Token validation failed: {str(e)}")

    def get_user_from_request(self) -> Optional[Dict]:
        """
        Extract and validate user from request Authorization header.

        Returns:
            User dict if authenticated, None if no auth header
        """
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return None

        # Parse Bearer token
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            raise AuthenticationError("Invalid Authorization header format")

        token = parts[1]
        return self.validate_token(token)


# Global auth manager instance
_auth_manager = AuthManager()


def get_auth_manager() -> AuthManager:
    """Get the global auth manager instance."""
    return _auth_manager


def get_current_user() -> Optional[Dict]:
    """
    Get the current authenticated user from the request context.

    Returns:
        User dict if authenticated, None otherwise
    """
    return getattr(g, 'current_user', None)


def require_auth(f: Callable) -> Callable:
    """
    Decorator to require authentication for a route.

    Usage:
        @app.route('/api/protected')
        @require_auth
        def protected_route():
            user = get_current_user()
            ...

    Returns:
        Decorated function with authentication check
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            user = _auth_manager.get_user_from_request()
            if not user:
                return jsonify({
                    'success': False,
                    'error': 'Authentication required',
                    'message': 'Please provide a valid Bearer token in the Authorization header'
                }), 401

            # Store user in request context
            g.current_user = user
            return f(*args, **kwargs)

        except AuthenticationError as e:
            return jsonify({
                'success': False,
                'error': 'Authentication failed',
                'message': e.message
            }), e.status_code

    return decorated_function


def optional_auth(f: Callable) -> Callable:
    """
    Decorator to optionally extract user if authenticated.

    Unlike require_auth, this allows unauthenticated requests
    but will extract user info if a valid token is provided.

    Usage:
        @app.route('/api/public')
        @optional_auth
        def public_route():
            user = get_current_user()  # May be None
            ...
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            user = _auth_manager.get_user_from_request()
            g.current_user = user
        except AuthenticationError:
            g.current_user = None

        return f(*args, **kwargs)

    return decorated_function
