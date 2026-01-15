"""
Role-Based Access Control (RBAC) Module

Implements hierarchical role-based permissions:
- Predefined roles with specific permissions
- Permission inheritance
- Route-level access control

OWASP Reference: Proper authorization prevents privilege escalation
(OWASP Top 10 - A01:2021 Broken Access Control)
"""

from enum import Enum
from typing import List, Set, Optional
from functools import wraps
from flask import jsonify, g


class Permission(Enum):
    """
    Available permissions in the system.

    Permissions are granular actions that can be assigned to roles.
    """
    # Scan permissions
    SCAN_READ = "scan:read"           # View scan results
    SCAN_CREATE = "scan:create"       # Create new scans
    SCAN_DELETE = "scan:delete"       # Delete scan results

    # User permissions
    USER_READ = "user:read"           # View user info
    USER_MANAGE = "user:manage"       # Manage users (admin)

    # System permissions
    SYSTEM_STATUS = "system:status"   # View system status
    SYSTEM_ADMIN = "system:admin"     # Full system access


class Role(Enum):
    """
    Predefined roles with associated permissions.

    Roles are hierarchical - higher roles inherit lower role permissions.
    """
    # Guest: Very limited access (unauthenticated users)
    GUEST = "guest"

    # User: Standard authenticated user
    USER = "user"

    # Analyst: Can perform scans and view detailed results
    ANALYST = "analyst"

    # Admin: Full system access
    ADMIN = "admin"


# Role to permissions mapping
ROLE_PERMISSIONS: dict[Role, Set[Permission]] = {
    Role.GUEST: {
        Permission.SYSTEM_STATUS,
    },

    Role.USER: {
        Permission.SYSTEM_STATUS,
        Permission.USER_READ,
        Permission.SCAN_READ,
    },

    Role.ANALYST: {
        Permission.SYSTEM_STATUS,
        Permission.USER_READ,
        Permission.SCAN_READ,
        Permission.SCAN_CREATE,
    },

    Role.ADMIN: {
        Permission.SYSTEM_STATUS,
        Permission.USER_READ,
        Permission.USER_MANAGE,
        Permission.SCAN_READ,
        Permission.SCAN_CREATE,
        Permission.SCAN_DELETE,
        Permission.SYSTEM_ADMIN,
    },
}


def get_role_permissions(role: Role) -> Set[Permission]:
    """
    Get all permissions for a role.

    Args:
        role: Role enum value

    Returns:
        Set of Permission values
    """
    return ROLE_PERMISSIONS.get(role, set())


def get_user_permissions(roles: List[str]) -> Set[Permission]:
    """
    Get all permissions for a user based on their roles.

    Combines permissions from all assigned roles.

    Args:
        roles: List of role names

    Returns:
        Set of Permission values
    """
    permissions = set()
    for role_name in roles:
        try:
            role = Role(role_name)
            permissions.update(get_role_permissions(role))
        except ValueError:
            # Unknown role - skip
            continue
    return permissions


def has_permission(user: Optional[dict], permission: Permission) -> bool:
    """
    Check if a user has a specific permission.

    Args:
        user: User dict with 'roles' key, or None for guest
        permission: Permission to check

    Returns:
        True if user has permission, False otherwise
    """
    if user is None:
        # Guest access
        return permission in get_role_permissions(Role.GUEST)

    roles = user.get('roles', ['user'])
    permissions = get_user_permissions(roles)
    return permission in permissions


def require_permission(permission: Permission):
    """
    Decorator to require a specific permission for a route.

    Usage:
        @app.route('/api/scan', methods=['POST'])
        @require_auth
        @require_permission(Permission.SCAN_CREATE)
        def create_scan():
            ...

    Args:
        permission: Required Permission enum value

    Returns:
        Decorated function with permission check
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get current user from context (set by require_auth)
            user = getattr(g, 'current_user', None)

            if not has_permission(user, permission):
                return jsonify({
                    'success': False,
                    'error': 'Access denied',
                    'message': f'Required permission: {permission.value}'
                }), 403

            return f(*args, **kwargs)

        return decorated_function
    return decorator


def require_any_permission(*permissions: Permission):
    """
    Decorator to require any one of the specified permissions.

    Usage:
        @require_any_permission(Permission.SCAN_CREATE, Permission.SYSTEM_ADMIN)
        def some_route():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = getattr(g, 'current_user', None)

            for permission in permissions:
                if has_permission(user, permission):
                    return f(*args, **kwargs)

            return jsonify({
                'success': False,
                'error': 'Access denied',
                'message': f'Required one of: {", ".join(p.value for p in permissions)}'
            }), 403

        return decorated_function
    return decorator


def require_all_permissions(*permissions: Permission):
    """
    Decorator to require all of the specified permissions.

    Usage:
        @require_all_permissions(Permission.SCAN_CREATE, Permission.USER_MANAGE)
        def admin_scan():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = getattr(g, 'current_user', None)

            missing = []
            for permission in permissions:
                if not has_permission(user, permission):
                    missing.append(permission)

            if missing:
                return jsonify({
                    'success': False,
                    'error': 'Access denied',
                    'message': f'Missing permissions: {", ".join(p.value for p in missing)}'
                }), 403

            return f(*args, **kwargs)

        return decorated_function
    return decorator
