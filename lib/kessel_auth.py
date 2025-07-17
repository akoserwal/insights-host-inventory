"""
Kessel-aware authorization interceptor for HBI (Host Based Inventory).

This module provides a decorator that intercepts requests and performs authorization
checks using Kessel's permission system. It supports resource-specific filtering,
caching, metrics, and comprehensive error handling.

Example usage:
    @kessel_auth(RbacResourceType.HOSTS, RbacPermission.READ)
    def get_hosts(kessel_filter=None):
        # Your function implementation
        pass

    @kessel_auth(RbacResourceType.GROUPS, RbacPermission.WRITE, application="inventory")
    def update_group(group_id, kessel_filter=None):
        # Your function implementation
        pass
"""

from __future__ import annotations

import time
from functools import wraps, partial
from http import HTTPStatus
from typing import Dict, Any, Optional, Callable, Tuple, List
from uuid import UUID

from flask import abort, g, current_app, request
from prometheus_client import Counter, Histogram, Gauge

from app import RbacPermission, RbacResourceType
from app.auth import get_current_identity
from app.auth.identity import Identity, IdentityType
from app.common import inventory_config
from app.instrumentation import rbac_failure, rbac_permission_denied
from app.logging import get_logger
from lib.feature_flags import get_flag_value, FLAG_INVENTORY_API_READ_ONLY, FLAG_INVENTORY_KESSEL_HOST_MIGRATION
from lib.kessel import get_kessel_client, Kessel
from lib.middleware import kessel_type, kessel_verb

logger = get_logger(__name__)

# Constants
CHECKED_TYPES = [IdentityType.USER, IdentityType.SERVICE_ACCOUNT]
KESSEL_CACHE_TTL = 300  # 5 minutes default cache TTL
KESSEL_RETRY_ATTEMPTS = 3
KESSEL_TIMEOUT = 30  # seconds

# Metrics
kessel_auth_requests_total = Counter(
    'kessel_auth_requests_total',
    'Total number of Kessel authorization requests',
    ['resource_type', 'permission', 'application', 'result']
)

kessel_auth_duration_seconds = Histogram(
    'kessel_auth_duration_seconds',
    'Duration of Kessel authorization requests',
    ['resource_type', 'permission', 'application']
)

kessel_auth_cache_hits_total = Counter(
    'kessel_auth_cache_hits_total',
    'Total number of Kessel authorization cache hits',
    ['resource_type', 'permission', 'application']
)

kessel_auth_active_requests = Gauge(
    'kessel_auth_active_requests',
    'Number of active Kessel authorization requests'
)

# Cache for Kessel authorization results
_kessel_auth_cache: Dict[str, Tuple[float, bool, Optional[Dict[str, Any]]]] = {}


class KesselAuthError(Exception):
    """Base exception for Kessel authorization errors."""
    pass


class KesselAuthConnectionError(KesselAuthError):
    """Exception raised when Kessel service is unavailable."""
    pass


class KesselAuthPermissionError(KesselAuthError):
    """Exception raised when user lacks required permissions."""
    pass


class KesselAuthValidator:
    """Validator for Kessel authorization results."""
    
    @staticmethod
    def validate_workspaces(workspaces: List[str]) -> List[str]:
        """
        Validate that workspace IDs are valid UUIDs.
        
        Args:
            workspaces: List of workspace IDs to validate
            
        Returns:
            List of validated workspace IDs
            
        Raises:
            KesselAuthError: If any workspace ID is invalid
        """
        validated_workspaces = []
        
        for workspace_id in workspaces:
            try:
                # Validate UUID format
                UUID(workspace_id)
                validated_workspaces.append(workspace_id)
            except (ValueError, TypeError) as e:
                logger.error(f"Invalid workspace UUID: {workspace_id}")
                raise KesselAuthError(f"Invalid workspace UUID: {workspace_id}") from e
        
        return validated_workspaces


class KesselAuthCache:
    """Cache manager for Kessel authorization results."""
    
    @staticmethod
    def _generate_cache_key(
        identity: Identity, 
        resource_type: RbacResourceType, 
        permission: RbacPermission, 
        application: str
    ) -> str:
        """Generate a cache key for the authorization result."""
        user_id = identity.user.get('user_id', '') if hasattr(identity, 'user') and identity.user else ''
        org_id = identity.org_id if hasattr(identity, 'org_id') else ''
        
        return f"kessel_auth:{org_id}:{user_id}:{application}:{resource_type.value}:{permission.value}"
    
    @staticmethod
    def get(
        identity: Identity, 
        resource_type: RbacResourceType, 
        permission: RbacPermission, 
        application: str
    ) -> Optional[Tuple[bool, Optional[Dict[str, Any]]]]:
        """
        Get cached authorization result.
        
        Returns:
            Tuple of (allowed, filter) or None if not cached or expired
        """
        cache_key = KesselAuthCache._generate_cache_key(identity, resource_type, permission, application)
        
        if cache_key in _kessel_auth_cache:
            timestamp, allowed, auth_filter = _kessel_auth_cache[cache_key]
            
            if time.time() - timestamp < KESSEL_CACHE_TTL:
                kessel_auth_cache_hits_total.labels(
                    resource_type=resource_type.value,
                    permission=permission.value,
                    application=application
                ).inc()
                return allowed, auth_filter
            else:
                # Cache expired, remove it
                del _kessel_auth_cache[cache_key]
        
        return None
    
    @staticmethod
    def set(
        identity: Identity, 
        resource_type: RbacResourceType, 
        permission: RbacPermission, 
        application: str, 
        allowed: bool, 
        auth_filter: Optional[Dict[str, Any]]
    ) -> None:
        """Cache authorization result."""
        cache_key = KesselAuthCache._generate_cache_key(identity, resource_type, permission, application)
        _kessel_auth_cache[cache_key] = (time.time(), allowed, auth_filter)
    
    @staticmethod
    def clear() -> None:
        """Clear all cached authorization results."""
        _kessel_auth_cache.clear()


class KesselAuthInterceptor:
    """Main class for Kessel authorization interception."""
    
    def __init__(
        self,
        resource_type: RbacResourceType,
        permission: RbacPermission,
        application: str = "inventory",
        cache_enabled: bool = True,
        require_kessel_migration: bool = True
    ):
        """
        Initialize the Kessel authorization interceptor.
        
        Args:
            resource_type: Type of resource being accessed
            permission: Required permission level
            application: Application name for Kessel relation
            cache_enabled: Whether to cache authorization results
            require_kessel_migration: Whether to require Kessel migration flag
        """
        self.resource_type = resource_type
        self.permission = permission
        self.application = application
        self.cache_enabled = cache_enabled
        self.require_kessel_migration = require_kessel_migration
        
    def _check_read_only_mode(self) -> None:
        """Check if API is in read-only mode for write operations."""
        if self.permission == RbacPermission.WRITE and get_flag_value(FLAG_INVENTORY_API_READ_ONLY):
            abort(503, "Inventory API is currently in read-only mode.")
    
    def _should_bypass_kessel(self) -> bool:
        """Check if Kessel authorization should be bypassed."""
        config = inventory_config()
        
        # Bypass if RBAC is disabled entirely
        if config.bypass_rbac:
            return True
        
        # Bypass if Kessel migration is not enabled and required
        if self.require_kessel_migration and not get_flag_value(FLAG_INVENTORY_KESSEL_HOST_MIGRATION):
            return True
        
        return False
    
    def _check_identity_type(self, identity: Identity) -> bool:
        """Check if identity type requires authorization."""
        if identity.identity_type not in CHECKED_TYPES:
            # System identities get full access to hosts, but not to other resources
            return self.resource_type == RbacResourceType.HOSTS
        
        return True
    
    def _get_kessel_authorization(
        self, 
        kessel_client: Kessel, 
        identity: Identity
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Get authorization result from Kessel service.
        
        Returns:
            Tuple of (allowed, filter)
        """
        # Check cache first
        if self.cache_enabled:
            cached_result = KesselAuthCache.get(identity, self.resource_type, self.permission, self.application)
            if cached_result is not None:
                return cached_result
        
        # Build relation string for Kessel
        relation = f"{self.application}_{kessel_type(self.resource_type)}_{kessel_verb(self.permission)}"
        
        try:
            # Query Kessel for allowed workspaces
            workspaces = kessel_client.ListAllowedWorkspaces(identity, relation)
            
            # Validate workspace IDs
            validated_workspaces = KesselAuthValidator.validate_workspaces(workspaces)
            
            # Determine authorization result
            if len(validated_workspaces) == 0:
                allowed = False
                auth_filter = None
            else:
                allowed = True
                auth_filter = {"groups": validated_workspaces}
            
            # Cache the result
            if self.cache_enabled:
                KesselAuthCache.set(identity, self.resource_type, self.permission, self.application, allowed, auth_filter)
            
            return allowed, auth_filter
            
        except Exception as e:
            logger.error(f"Kessel authorization error: {e}")
            raise KesselAuthConnectionError(f"Failed to connect to Kessel service: {e}")
    
    def authorize(self, identity: Identity) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Perform authorization check.
        
        Args:
            identity: Current user identity
            
        Returns:
            Tuple of (allowed, filter)
        """
        # Track access control method
        g.access_control_rule = "Kessel"
        
        # Check if identity type requires authorization
        if not self._check_identity_type(identity):
            return False, None
        
        # Get Kessel client
        kessel_client = get_kessel_client(current_app)
        
        # Perform authorization check
        with kessel_auth_duration_seconds.labels(
            resource_type=self.resource_type.value,
            permission=self.permission.value,
            application=self.application
        ).time():
            kessel_auth_active_requests.inc()
            try:
                allowed, auth_filter = self._get_kessel_authorization(kessel_client, identity)
                
                # Record metrics
                result = "allowed" if allowed else "denied"
                kessel_auth_requests_total.labels(
                    resource_type=self.resource_type.value,
                    permission=self.permission.value,
                    application=self.application,
                    result=result
                ).inc()
                
                if not allowed:
                    # Log permission denied
                    rbac_permission_denied(logger, self.permission.value, [])
                
                return allowed, auth_filter
                
            finally:
                kessel_auth_active_requests.dec()


def kessel_auth(
    resource_type: RbacResourceType,
    permission: RbacPermission,
    application: str = "inventory",
    cache_enabled: bool = True,
    require_kessel_migration: bool = True,
    fallback_to_rbac: bool = False
) -> Callable:
    """
    Decorator for Kessel-aware authorization.
    
    This decorator intercepts requests and performs authorization checks using
    Kessel's permission system. It supports resource-specific filtering,
    caching, metrics, and comprehensive error handling.
    
    Args:
        resource_type: Type of resource being accessed (RbacResourceType)
        permission: Required permission level (RbacPermission)
        application: Application name for Kessel relation (default: "inventory")
        cache_enabled: Whether to cache authorization results (default: True)
        require_kessel_migration: Whether to require Kessel migration flag (default: True)
        fallback_to_rbac: Whether to fallback to RBAC if Kessel fails (default: False)
    
    Returns:
        Decorated function
    
    Example:
        @kessel_auth(RbacResourceType.HOSTS, RbacPermission.READ)
        def get_hosts(kessel_filter=None):
            # Your function implementation
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Create interceptor instance
            interceptor = KesselAuthInterceptor(
                resource_type=resource_type,
                permission=permission,
                application=application,
                cache_enabled=cache_enabled,
                require_kessel_migration=require_kessel_migration
            )
            
            # Check read-only mode
            interceptor._check_read_only_mode()
            
            # Check if should bypass Kessel
            if interceptor._should_bypass_kessel():
                logger.debug("Bypassing Kessel authorization")
                return func(*args, **kwargs)
            
            # Get current identity
            current_identity = get_current_identity()
            
            try:
                # Perform authorization
                allowed, kessel_filter = interceptor.authorize(current_identity)
                
                if allowed:
                    # Add filter to function call if needed
                    if kessel_filter:
                        return partial(func, kessel_filter=kessel_filter)(*args, **kwargs)
                    else:
                        return func(*args, **kwargs)
                else:
                    abort(HTTPStatus.FORBIDDEN, "Access denied by Kessel authorization")
                    
            except KesselAuthConnectionError as e:
                logger.error(f"Kessel service unavailable: {e}")
                
                if fallback_to_rbac:
                    # Fallback to RBAC if enabled
                    logger.info("Falling back to RBAC authorization")
                    from lib.middleware import rbac
                    rbac_decorator = rbac(resource_type, permission, application)
                    return rbac_decorator(func)(*args, **kwargs)
                else:
                    abort(503, "Authorization service unavailable")
            
            except KesselAuthError as e:
                logger.error(f"Kessel authorization error: {e}")
                abort(500, "Authorization error")
            
            except Exception as e:
                logger.error(f"Unexpected error in Kessel authorization: {e}")
                abort(500, "Internal server error")
        
        return wrapper
    return decorator


def kessel_group_id_check(kessel_filter: Optional[Dict[str, Any]], requested_ids: set) -> None:
    """
    Check if requested group IDs are allowed by Kessel filter.
    
    Args:
        kessel_filter: Filter returned by Kessel authorization
        requested_ids: Set of group IDs being requested
        
    Raises:
        HTTPException: If any requested ID is not allowed
    """
    if kessel_filter and "groups" in kessel_filter:
        allowed_groups = set(kessel_filter["groups"])
        disallowed_ids = requested_ids.difference(allowed_groups)
        
        if disallowed_ids:
            joined_ids = ", ".join(disallowed_ids)
            logger.warning(f"Kessel denied access to groups: {joined_ids}")
            abort(HTTPStatus.FORBIDDEN, f"You do not have access to the following groups: {joined_ids}")


def clear_kessel_auth_cache() -> None:
    """Clear all cached Kessel authorization results."""
    KesselAuthCache.clear()
    logger.info("Kessel authorization cache cleared")


def get_kessel_auth_cache_stats() -> Dict[str, Any]:
    """Get statistics about the Kessel authorization cache."""
    return {
        "cache_size": len(_kessel_auth_cache),
        "cache_ttl": KESSEL_CACHE_TTL,
        "entries": list(_kessel_auth_cache.keys())
    }


# Convenience decorators for common use cases
def kessel_read_hosts(func: Callable) -> Callable:
    """Decorator for read access to hosts."""
    return kessel_auth(RbacResourceType.HOSTS, RbacPermission.READ)(func)


def kessel_write_hosts(func: Callable) -> Callable:
    """Decorator for write access to hosts."""
    return kessel_auth(RbacResourceType.HOSTS, RbacPermission.WRITE)(func)


def kessel_read_groups(func: Callable) -> Callable:
    """Decorator for read access to groups."""
    return kessel_auth(RbacResourceType.GROUPS, RbacPermission.READ)(func)


def kessel_write_groups(func: Callable) -> Callable:
    """Decorator for write access to groups."""
    return kessel_auth(RbacResourceType.GROUPS, RbacPermission.WRITE)(func)


def kessel_admin_all(func: Callable) -> Callable:
    """Decorator for admin access to all resources."""
    return kessel_auth(RbacResourceType.ALL, RbacPermission.ADMIN)(func) 