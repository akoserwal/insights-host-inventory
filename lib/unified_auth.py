"""
Unified Authorization Interceptor for HBI.

This module provides a comprehensive authorization decorator that can handle both
Kessel and RBAC authorization flows based on feature flags and operation types.
It implements the flow shown in the authorization diagrams.

The decorator automatically:
1. Extracts identity from HTTP request
2. Identifies operation type (read/view, modify/delete, create, unbounded query)
3. Checks feature flags to determine authorization method
4. Applies appropriate authorization (Kessel or RBAC)
5. Returns filtered results or denies access
"""

from __future__ import annotations

import inspect
import time
from functools import wraps, partial
from http import HTTPStatus
from typing import Dict, Any, Optional, Callable, Tuple, List, Union
from enum import Enum

from flask import abort, g, current_app, request
from prometheus_client import Counter, Histogram

from app import RbacPermission, RbacResourceType
from app.auth import get_current_identity
from app.auth.identity import Identity, IdentityType
from app.common import inventory_config
from app.instrumentation import rbac_failure, rbac_permission_denied
from app.logging import get_logger
from lib.feature_flags import get_flag_value, FLAG_INVENTORY_API_READ_ONLY, FLAG_INVENTORY_KESSEL_HOST_MIGRATION
from lib.kessel import get_kessel_client, Kessel
from lib.middleware import (
    get_rbac_filter, 
    get_kessel_filter, 
    kessel_type, 
    kessel_verb,
    _build_rbac_request_headers
)

logger = get_logger(__name__)


class OperationType(Enum):
    """Types of operations that can be performed."""
    READ = "read"           # read/view operations
    MODIFY = "modify"       # modify/delete operations  
    CREATE = "create"       # create operations
    UNBOUNDED = "unbounded" # unbounded query operations


class AuthorizationMethod(Enum):
    """Methods of authorization available."""
    KESSEL = "kessel"
    RBAC = "rbac"
    BYPASS = "bypass"


class AuthorizationResult:
    """Result of authorization check."""
    
    def __init__(
        self, 
        allowed: bool, 
        method: AuthorizationMethod, 
        filters: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.allowed = allowed
        self.method = method
        self.filters = filters or {}
        self.metadata = metadata or {}
        self.timestamp = time.time()


class OperationTypeDetector:
    """Detects operation type based on HTTP method and endpoint metadata."""
    
    # HTTP method to operation type mapping
    HTTP_METHOD_MAPPING = {
        'GET': OperationType.READ,
        'HEAD': OperationType.READ,
        'POST': OperationType.CREATE,
        'PUT': OperationType.MODIFY,
        'PATCH': OperationType.MODIFY,
        'DELETE': OperationType.MODIFY,
    }
    
    # Endpoint patterns that indicate unbounded queries
    UNBOUNDED_PATTERNS = [
        'search',
        'query',
        'filter',
        'bulk',
        'export',
        'report'
    ]
    
    @classmethod
    def detect_operation_type(
        cls, 
        http_method: str, 
        endpoint: str, 
        function_name: str,
        explicit_type: Optional[OperationType] = None
    ) -> OperationType:
        """
        Detect operation type based on HTTP method, endpoint, and function name.
        
        Args:
            http_method: HTTP method (GET, POST, etc.)
            endpoint: URL endpoint
            function_name: Name of the handler function
            explicit_type: Explicitly specified operation type
            
        Returns:
            Detected operation type
        """
        # If explicitly specified, use that
        if explicit_type:
            return explicit_type
            
        # Check for unbounded query patterns
        endpoint_lower = endpoint.lower()
        function_lower = function_name.lower()
        
        for pattern in cls.UNBOUNDED_PATTERNS:
            if pattern in endpoint_lower or pattern in function_lower:
                return OperationType.UNBOUNDED
                
        # Fall back to HTTP method mapping
        return cls.HTTP_METHOD_MAPPING.get(http_method.upper(), OperationType.READ)


class AuthorizationDecisionEngine:
    """Makes authorization decisions based on available information."""
    
    def __init__(self):
        self.logger = get_logger(self.__class__.__name__)
        
    def determine_authorization_method(
        self, 
        operation_type: OperationType,
        resource_type: RbacResourceType,
        explicit_method: Optional[AuthorizationMethod] = None
    ) -> AuthorizationMethod:
        """
        Determine which authorization method to use.
        
        Args:
            operation_type: Type of operation being performed
            resource_type: Type of resource being accessed
            explicit_method: Explicitly specified method
            
        Returns:
            Authorization method to use
        """
        # If explicitly specified, use that
        if explicit_method:
            return explicit_method
            
        # Check if authorization is bypassed
        config = inventory_config()
        if config.bypass_rbac:
            return AuthorizationMethod.BYPASS
            
        # Check Kessel feature flag
        if get_flag_value(FLAG_INVENTORY_KESSEL_HOST_MIGRATION):
            # Use Kessel for hosts, but fallback to RBAC for groups (per existing logic)
            if resource_type not in [RbacResourceType.GROUPS]:
                return AuthorizationMethod.KESSEL
                
        # Default to RBAC
        return AuthorizationMethod.RBAC
    
    def perform_authorization(
        self,
        identity: Identity,
        operation_type: OperationType,
        resource_type: RbacResourceType,
        permission: RbacPermission,
        application: str = "inventory"
    ) -> AuthorizationResult:
        """
        Perform authorization check using the appropriate method.
        
        Args:
            identity: Current user identity
            operation_type: Type of operation
            resource_type: Type of resource
            permission: Required permission
            application: Application name
            
        Returns:
            Authorization result
        """
        # Determine authorization method
        method = self.determine_authorization_method(operation_type, resource_type)
        
        self.logger.debug(
            f"Authorization check: method={method.value}, operation={operation_type.value}, "
            f"resource={resource_type.value}, permission={permission.value}"
        )
        
        # Track access control method
        g.access_control_rule = method.value.upper()
        
        if method == AuthorizationMethod.BYPASS:
            return AuthorizationResult(
                allowed=True,
                method=method,
                metadata={"reason": "authorization_bypassed"}
            )
            
        elif method == AuthorizationMethod.KESSEL:
            return self._perform_kessel_authorization(
                identity, resource_type, permission, application
            )
            
        elif method == AuthorizationMethod.RBAC:
            return self._perform_rbac_authorization(
                identity, resource_type, permission, application
            )
            
        else:
            raise ValueError(f"Unknown authorization method: {method}")
    
    def _perform_kessel_authorization(
        self,
        identity: Identity,
        resource_type: RbacResourceType,
        permission: RbacPermission,
        application: str
    ) -> AuthorizationResult:
        """Perform Kessel authorization."""
        try:
            kessel_client = get_kessel_client(current_app)
            allowed, filters = get_kessel_filter(
                kessel_client, identity, application, resource_type, permission
            )
            
            return AuthorizationResult(
                allowed=allowed,
                method=AuthorizationMethod.KESSEL,
                filters=filters,
                metadata={"kessel_client": True}
            )
            
        except Exception as e:
            self.logger.error(f"Kessel authorization failed: {e}")
            return AuthorizationResult(
                allowed=False,
                method=AuthorizationMethod.KESSEL,
                metadata={"error": str(e), "kessel_client": True}
            )
    
    def _perform_rbac_authorization(
        self,
        identity: Identity,
        resource_type: RbacResourceType,
        permission: RbacPermission,
        application: str
    ) -> AuthorizationResult:
        """Perform RBAC authorization."""
        try:
            request_headers = _build_rbac_request_headers()
            allowed, filters = get_rbac_filter(
                resource_type, permission, identity, request_headers, application
            )
            
            return AuthorizationResult(
                allowed=allowed,
                method=AuthorizationMethod.RBAC,
                filters=filters,
                metadata={"rbac_client": True}
            )
            
        except Exception as e:
            self.logger.error(f"RBAC authorization failed: {e}")
            return AuthorizationResult(
                allowed=False,
                method=AuthorizationMethod.RBAC,
                metadata={"error": str(e), "rbac_client": True}
            )


# Metrics for unified authorization
unified_auth_requests_total = Counter(
    'unified_auth_requests_total',
    'Total number of unified authorization requests',
    ['method', 'operation_type', 'resource_type', 'permission', 'result']
)

unified_auth_duration_seconds = Histogram(
    'unified_auth_duration_seconds',
    'Duration of unified authorization requests',
    ['method', 'operation_type', 'resource_type', 'permission']
)


def unified_auth(
    resource_type: RbacResourceType,
    permission: Optional[RbacPermission] = None,
    application: str = "inventory",
    operation_type: Optional[OperationType] = None,
    auth_method: Optional[AuthorizationMethod] = None,
    filter_param_name: str = "auth_filter"
) -> Callable:
    """
    Unified authorization decorator that handles both Kessel and RBAC.
    
    This decorator implements the authorization flow shown in the diagrams:
    1. HTTP Request -> Identity Extraction
    2. Identify Operation Type
    3. Feature Flag Check (Kessel Enabled/Disabled)
    4. Apply appropriate authorization (Kessel or RBAC)
    5. Return filtered results or deny access
    
    Args:
        resource_type: Type of resource being accessed
        permission: Required permission (auto-detected if not provided)
        application: Application name
        operation_type: Type of operation (auto-detected if not provided)
        auth_method: Authorization method (auto-detected if not provided)
        filter_param_name: Name of filter parameter to inject
        
    Returns:
        Decorated function
        
    Example:
        @unified_auth(RbacResourceType.HOSTS)
        def get_hosts(auth_filter=None):
            # Function implementation
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Extract request information
            http_method = request.method
            endpoint = request.endpoint or ""
            function_name = func.__name__
            
            # Detect operation type
            detected_operation_type = OperationTypeDetector.detect_operation_type(
                http_method, endpoint, function_name, operation_type
            )
            
            # Auto-detect permission if not provided
            detected_permission = permission
            if not detected_permission:
                if detected_operation_type == OperationType.READ:
                    detected_permission = RbacPermission.READ
                elif detected_operation_type in [OperationType.MODIFY, OperationType.CREATE]:
                    detected_permission = RbacPermission.WRITE
                elif detected_operation_type == OperationType.UNBOUNDED:
                    detected_permission = RbacPermission.ADMIN
                else:
                    detected_permission = RbacPermission.READ
            
            # Check read-only mode
            if detected_permission == RbacPermission.WRITE and get_flag_value(FLAG_INVENTORY_API_READ_ONLY):
                abort(503, "Inventory API is currently in read-only mode.")
            
            # Get current identity
            current_identity = get_current_identity()
            
            # Create decision engine
            decision_engine = AuthorizationDecisionEngine()
            
            # Perform authorization
            with unified_auth_duration_seconds.labels(
                method=auth_method.value if auth_method else "auto",
                operation_type=detected_operation_type.value,
                resource_type=resource_type.value,
                permission=detected_permission.value
            ).time():
                
                auth_result = decision_engine.perform_authorization(
                    current_identity,
                    detected_operation_type,
                    resource_type,
                    detected_permission,
                    application
                )
            
            # Record metrics
            unified_auth_requests_total.labels(
                method=auth_result.method.value,
                operation_type=detected_operation_type.value,
                resource_type=resource_type.value,
                permission=detected_permission.value,
                result="allowed" if auth_result.allowed else "denied"
            ).inc()
            
            # Handle authorization result
            if auth_result.allowed:
                # Inject filter parameter if filters are present
                if auth_result.filters:
                    kwargs[filter_param_name] = auth_result.filters
                
                # Log successful authorization
                logger.debug(
                    f"Authorization successful: method={auth_result.method.value}, "
                    f"filters={bool(auth_result.filters)}"
                )
                
                # Call the original function
                return func(*args, **kwargs)
            else:
                # Log denied authorization
                logger.warning(
                    f"Authorization denied: method={auth_result.method.value}, "
                    f"operation={detected_operation_type.value}, "
                    f"resource={resource_type.value}, "
                    f"permission={detected_permission.value}"
                )
                
                # Deny access
                abort(HTTPStatus.FORBIDDEN, "Access denied by authorization system")
        
        return wrapper
    return decorator


def check_bulk_resources(
    auth_filter: Optional[Dict[str, Any]], 
    requested_resource_ids: List[str],
    resource_type: RbacResourceType
) -> None:
    """
    Check if user has access to multiple resources (bulk check).
    
    Args:
        auth_filter: Filter returned by authorization
        requested_resource_ids: List of resource IDs being requested
        resource_type: Type of resources being checked
        
    Raises:
        HTTPException: If any requested resource is not allowed
    """
    if not auth_filter:
        return  # No filter means unrestricted access
    
    if resource_type == RbacResourceType.GROUPS and "groups" in auth_filter:
        allowed_groups = set(auth_filter["groups"])
        requested_groups = set(requested_resource_ids)
        
        disallowed_groups = requested_groups.difference(allowed_groups)
        if disallowed_groups:
            joined_ids = ", ".join(disallowed_groups)
            logger.warning(f"Bulk check denied access to resources: {joined_ids}")
            abort(
                HTTPStatus.FORBIDDEN, 
                f"You do not have access to the following {resource_type.value}: {joined_ids}"
            )


def lookup_allowed_resources(
    auth_filter: Optional[Dict[str, Any]],
    resource_type: RbacResourceType
) -> List[str]:
    """
    Look up resources that the user has access to.
    
    Args:
        auth_filter: Filter returned by authorization
        resource_type: Type of resources to look up
        
    Returns:
        List of resource IDs the user can access
    """
    if not auth_filter:
        return []  # No filter means unrestricted access - return empty list to indicate no filtering
    
    if resource_type == RbacResourceType.GROUPS and "groups" in auth_filter:
        return auth_filter["groups"]
    
    return []


# Convenience decorators that match common patterns
def auth_read(resource_type: RbacResourceType, application: str = "inventory") -> Callable:
    """Decorator for read operations."""
    return unified_auth(
        resource_type=resource_type,
        permission=RbacPermission.READ,
        application=application,
        operation_type=OperationType.READ
    )


def auth_write(resource_type: RbacResourceType, application: str = "inventory") -> Callable:
    """Decorator for write operations."""
    return unified_auth(
        resource_type=resource_type,
        permission=RbacPermission.WRITE,
        application=application,
        operation_type=OperationType.MODIFY
    )


def auth_create(resource_type: RbacResourceType, application: str = "inventory") -> Callable:
    """Decorator for create operations."""
    return unified_auth(
        resource_type=resource_type,
        permission=RbacPermission.WRITE,
        application=application,
        operation_type=OperationType.CREATE
    )


def auth_admin(resource_type: RbacResourceType, application: str = "inventory") -> Callable:
    """Decorator for admin operations."""
    return unified_auth(
        resource_type=resource_type,
        permission=RbacPermission.ADMIN,
        application=application,
        operation_type=OperationType.UNBOUNDED
    )


# Resource-specific convenience decorators
def auth_hosts_read(func: Callable) -> Callable:
    """Decorator for host read operations."""
    return auth_read(RbacResourceType.HOSTS)(func)


def auth_hosts_write(func: Callable) -> Callable:
    """Decorator for host write operations."""
    return auth_write(RbacResourceType.HOSTS)(func)


def auth_groups_read(func: Callable) -> Callable:
    """Decorator for group read operations."""
    return auth_read(RbacResourceType.GROUPS)(func)


def auth_groups_write(func: Callable) -> Callable:
    """Decorator for group write operations."""
    return auth_write(RbacResourceType.GROUPS)(func)


def auth_staleness_read(func: Callable) -> Callable:
    """Decorator for staleness read operations."""
    return auth_read(RbacResourceType.STALENESS)(func)


def auth_staleness_write(func: Callable) -> Callable:
    """Decorator for staleness write operations."""
    return auth_write(RbacResourceType.STALENESS)(func)


# Utility functions for metadata access
def get_authorization_metadata() -> Dict[str, Any]:
    """Get authorization metadata from Flask context."""
    return {
        "access_control_rule": getattr(g, "access_control_rule", "unknown"),
        "request_id": getattr(g, "request_id", None),
        "timestamp": time.time()
    }


def is_authorization_bypassed() -> bool:
    """Check if authorization is currently bypassed."""
    return inventory_config().bypass_rbac


def get_current_authorization_method() -> Optional[str]:
    """Get the current authorization method from Flask context."""
    return getattr(g, "access_control_rule", None) 