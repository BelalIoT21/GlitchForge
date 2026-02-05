"""
Rate Limiting Module

Implements IP-based and user-based rate limiting with:
- Sliding window algorithm for accurate rate tracking
- Graceful 429 responses with retry-after headers
- Configurable limits per endpoint
- Redis-compatible in-memory fallback

OWASP Reference: Rate limiting helps prevent brute force attacks,
DoS attacks, and API abuse (OWASP API Security Top 10 - API4:2019)
"""

import time
import threading
from functools import wraps
from typing import Optional, Dict, Callable
from flask import request, jsonify, g
from collections import defaultdict


class RateLimiter:
    """
    Thread-safe rate limiter using sliding window algorithm.

    Provides both IP-based and user-based rate limiting with
    configurable windows and limits per endpoint.
    """

    def __init__(self):
        self._ip_requests: Dict[str, list] = defaultdict(list)
        self._user_requests: Dict[str, list] = defaultdict(list)
        self._lock = threading.Lock()

        # Default rate limits (requests per window)
        self.default_limits = {
            'ip': {'requests': 100, 'window': 60},      # 100 requests per minute per IP
            'user': {'requests': 200, 'window': 60},    # 200 requests per minute per user
        }

        # Endpoint-specific limits (more restrictive for expensive operations)
        self.endpoint_limits = {
            '/api/scan': {'requests': 10, 'window': 60},         # 10 scans per minute
            '/api/scan-stream': {'requests': 5, 'window': 60},   # 5 streaming scans per minute
            '/api/quick-scan': {'requests': 20, 'window': 60},   # 20 quick scans per minute
            '/health': {'requests': 60, 'window': 60},           # 60 health checks per minute
            '/api/status': {'requests': 60, 'window': 60},       # 60 status checks per minute
        }

    def _cleanup_old_requests(self, requests: list, window: int) -> list:
        """Remove requests older than the window period."""
        cutoff = time.time() - window
        return [req for req in requests if req > cutoff]

    def _get_limit_for_endpoint(self, endpoint: str) -> Dict:
        """Get rate limit configuration for a specific endpoint."""
        return self.endpoint_limits.get(endpoint, self.default_limits['ip'])

    def check_rate_limit(
        self,
        identifier: str,
        endpoint: str,
        limit_type: str = 'ip'
    ) -> tuple[bool, Optional[int]]:
        """
        Check if a request should be rate limited.

        Args:
            identifier: IP address or user ID
            endpoint: The API endpoint being accessed
            limit_type: 'ip' or 'user'

        Returns:
            Tuple of (is_allowed, retry_after_seconds)
        """
        limit_config = self._get_limit_for_endpoint(endpoint)
        max_requests = limit_config['requests']
        window = limit_config['window']

        key = f"{limit_type}:{identifier}:{endpoint}"

        with self._lock:
            # Get request storage based on type
            storage = self._ip_requests if limit_type == 'ip' else self._user_requests

            # Clean up old requests
            storage[key] = self._cleanup_old_requests(storage[key], window)

            # Check if limit exceeded
            if len(storage[key]) >= max_requests:
                # Calculate retry-after time
                oldest_request = min(storage[key]) if storage[key] else time.time()
                retry_after = int(oldest_request + window - time.time()) + 1
                return False, max(1, retry_after)

            # Record this request
            storage[key].append(time.time())
            return True, None

    def get_remaining_requests(self, identifier: str, endpoint: str) -> int:
        """Get the number of remaining requests allowed."""
        limit_config = self._get_limit_for_endpoint(endpoint)
        max_requests = limit_config['requests']
        window = limit_config['window']

        key = f"ip:{identifier}:{endpoint}"

        with self._lock:
            self._ip_requests[key] = self._cleanup_old_requests(
                self._ip_requests[key], window
            )
            return max(0, max_requests - len(self._ip_requests[key]))


# Global rate limiter instance
_rate_limiter = RateLimiter()


def rate_limit(
    limit_type: str = 'ip',
    custom_identifier: Optional[Callable] = None
):
    """
    Decorator to apply rate limiting to Flask routes.

    Usage:
        @app.route('/api/scan', methods=['POST'])
        @rate_limit(limit_type='ip')
        def scan():
            ...

    Args:
        limit_type: 'ip' or 'user' based limiting
        custom_identifier: Optional function to extract custom identifier

    Returns:
        Decorated function with rate limiting applied
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get identifier
            if custom_identifier:
                identifier = custom_identifier()
            elif limit_type == 'user' and hasattr(g, 'current_user') and g.current_user:
                identifier = g.current_user.get('id', request.remote_addr)
            else:
                # Use X-Forwarded-For header if behind a proxy, otherwise use remote_addr
                identifier = request.headers.get('X-Forwarded-For', request.remote_addr)
                if identifier:
                    # Take the first IP if multiple are present
                    identifier = identifier.split(',')[0].strip()

            # Get endpoint
            endpoint = request.path

            # Check rate limit
            is_allowed, retry_after = _rate_limiter.check_rate_limit(
                identifier, endpoint, limit_type
            )

            if not is_allowed:
                # Return 429 Too Many Requests with helpful headers
                response = jsonify({
                    'success': False,
                    'error': 'Rate limit exceeded',
                    'message': f'Too many requests. Please try again in {retry_after} seconds.',
                    'retry_after': retry_after
                })
                response.status_code = 429
                response.headers['Retry-After'] = str(retry_after)
                response.headers['X-RateLimit-Limit'] = str(
                    _rate_limiter._get_limit_for_endpoint(endpoint)['requests']
                )
                response.headers['X-RateLimit-Remaining'] = '0'
                response.headers['X-RateLimit-Reset'] = str(int(time.time() + retry_after))
                return response

            # Add rate limit headers to successful responses
            remaining = _rate_limiter.get_remaining_requests(identifier, endpoint)

            # Execute the actual function
            result = f(*args, **kwargs)

            # Add rate limit headers to response if it's a Response object
            if hasattr(result, 'headers'):
                result.headers['X-RateLimit-Limit'] = str(
                    _rate_limiter._get_limit_for_endpoint(endpoint)['requests']
                )
                result.headers['X-RateLimit-Remaining'] = str(remaining)

            return result

        return decorated_function
    return decorator


def get_rate_limiter() -> RateLimiter:
    """Get the global rate limiter instance."""
    return _rate_limiter
