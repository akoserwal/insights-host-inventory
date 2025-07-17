# Kessel Authorization Decorator for HBI

## Overview

The Kessel authorization decorator provides a comprehensive authorization interceptor for Host Based Inventory (HBI) that integrates with the Kessel permission system. It offers resource-specific filtering, caching, metrics, and comprehensive error handling.

## Features

- **Resource-specific authorization**: Support for different resource types (hosts, groups, staleness, etc.)
- **Permission-based access control**: Read, write, and admin permission levels
- **Workspace filtering**: Automatically filters results based on allowed workspaces
- **Caching**: Configurable caching of authorization results to improve performance
- **Metrics**: Prometheus metrics for monitoring authorization performance
- **Error handling**: Comprehensive error handling with fallback options
- **RBAC fallback**: Optional fallback to existing RBAC system
- **Convenience decorators**: Pre-configured decorators for common use cases

## Installation

The Kessel authorization decorator is located in `lib/kessel_auth.py` and can be imported directly:

```python
from lib.kessel_auth import kessel_auth, kessel_read_hosts, kessel_write_hosts
```

## Basic Usage

### Simple Authorization

```python
from lib.kessel_auth import kessel_auth
from app import RbacResourceType, RbacPermission

@kessel_auth(RbacResourceType.HOSTS, RbacPermission.READ)
def get_hosts(kessel_filter=None):
    """Get hosts with Kessel authorization."""
    if kessel_filter and "groups" in kessel_filter:
        # User has limited access to specific groups
        allowed_groups = kessel_filter["groups"]
        return query_hosts_by_groups(allowed_groups)
    else:
        # User has unrestricted access
        return query_all_hosts()
```

### Convenience Decorators

```python
from lib.kessel_auth import kessel_read_hosts, kessel_write_hosts

@kessel_read_hosts
def get_host_by_id(host_id, kessel_filter=None):
    """Get a specific host by ID."""
    return query_host_by_id(host_id)

@kessel_write_hosts
def update_host(host_id, kessel_filter=None):
    """Update a host."""
    return update_host_by_id(host_id)
```

## Configuration Options

The `@kessel_auth` decorator accepts several configuration parameters:

### Required Parameters

- `resource_type`: Type of resource being accessed (`RbacResourceType`)
- `permission`: Required permission level (`RbacPermission`)

### Optional Parameters

- `application`: Application name for Kessel relation (default: "inventory")
- `cache_enabled`: Whether to cache authorization results (default: True)
- `require_kessel_migration`: Whether to require Kessel migration flag (default: True)
- `fallback_to_rbac`: Whether to fallback to RBAC if Kessel fails (default: False)

### Example with Custom Configuration

```python
@kessel_auth(
    RbacResourceType.HOSTS,
    RbacPermission.READ,
    application="custom-app",
    cache_enabled=True,
    require_kessel_migration=False,
    fallback_to_rbac=True
)
def custom_endpoint(kessel_filter=None):
    """Custom configured endpoint."""
    return {"message": "success"}
```

## Resource Types

The decorator supports the following resource types:

- `RbacResourceType.HOSTS`: Host resources
- `RbacResourceType.GROUPS`: Group resources
- `RbacResourceType.STALENESS`: Staleness configuration
- `RbacResourceType.ALL`: All resources (admin only)

## Permission Levels

- `RbacPermission.READ`: Read-only access
- `RbacPermission.WRITE`: Read and write access
- `RbacPermission.ADMIN`: Full administrative access

## Filter Handling

When a user has limited access, the decorator injects a `kessel_filter` parameter:

```python
kessel_filter = {
    "groups": ["group-uuid-1", "group-uuid-2", "group-uuid-3"]
}
```

Your function should use this filter to limit the results:

```python
@kessel_auth(RbacResourceType.HOSTS, RbacPermission.READ)
def get_hosts(kessel_filter=None):
    if kessel_filter and "groups" in kessel_filter:
        # Filter by allowed groups
        allowed_groups = kessel_filter["groups"]
        return Host.query.filter(Host.group_id.in_(allowed_groups)).all()
    else:
        # Return all hosts
        return Host.query.all()
```

## Group ID Checking

For operations that target specific groups, use the `kessel_group_id_check` function:

```python
from lib.kessel_auth import kessel_group_id_check

@kessel_write_groups
def update_group(group_id, kessel_filter=None):
    # Check if user has access to this specific group
    kessel_group_id_check(kessel_filter, {group_id})
    
    # Proceed with update
    return update_group_by_id(group_id)
```

## Error Handling

The decorator handles various error conditions:

- **KesselAuthConnectionError**: Kessel service unavailable (503)
- **KesselAuthPermissionError**: User lacks permissions (403)
- **KesselAuthError**: General authorization error (500)
- **General exceptions**: Unexpected errors (500)

### Fallback to RBAC

When `fallback_to_rbac=True`, the decorator will fall back to the existing RBAC system if Kessel is unavailable:

```python
@kessel_auth(
    RbacResourceType.HOSTS,
    RbacPermission.READ,
    fallback_to_rbac=True
)
def get_hosts_with_fallback(kessel_filter=None):
    """Get hosts with RBAC fallback."""
    return query_hosts()
```

## Metrics

The decorator exposes several Prometheus metrics:

- `kessel_auth_requests_total`: Total authorization requests
- `kessel_auth_duration_seconds`: Request duration
- `kessel_auth_cache_hits_total`: Cache hit count
- `kessel_auth_active_requests`: Active request count

## Caching

Authorization results are cached to improve performance:

- **Cache TTL**: 300 seconds (5 minutes) by default
- **Cache key**: Based on user identity, resource type, permission, and application
- **Cache management**: Automatic expiration and cleanup

### Cache Management Functions

```python
from lib.kessel_auth import clear_kessel_auth_cache, get_kessel_auth_cache_stats

# Clear all cached results
clear_kessel_auth_cache()

# Get cache statistics
stats = get_kessel_auth_cache_stats()
```

## Feature Flags

The decorator respects several feature flags:

- `FLAG_INVENTORY_KESSEL_HOST_MIGRATION`: Enables Kessel authorization
- `FLAG_INVENTORY_API_READ_ONLY`: Disables write operations

## Convenience Decorators

Pre-configured decorators for common use cases:

```python
from lib.kessel_auth import (
    kessel_read_hosts,
    kessel_write_hosts,
    kessel_read_groups,
    kessel_write_groups,
    kessel_admin_all
)

@kessel_read_hosts
def get_hosts(): pass

@kessel_write_hosts
def update_host(): pass

@kessel_read_groups
def get_groups(): pass

@kessel_write_groups
def update_group(): pass

@kessel_admin_all
def admin_operation(): pass
```

## Migration from RBAC

### Gradual Migration

1. Start with `fallback_to_rbac=True` for safety
2. Monitor metrics and logs
3. Gradually disable fallback as confidence increases
4. Replace `@rbac` decorators with `@kessel_auth`

### Example Migration

```python
# Before (RBAC)
@rbac(RbacResourceType.HOSTS, RbacPermission.READ)
def get_hosts(rbac_filter=None):
    return query_hosts(rbac_filter)

# After (Kessel with fallback)
@kessel_auth(
    RbacResourceType.HOSTS,
    RbacPermission.READ,
    fallback_to_rbac=True
)
def get_hosts(kessel_filter=None):
    return query_hosts(kessel_filter)

# Final (Kessel only)
@kessel_auth(RbacResourceType.HOSTS, RbacPermission.READ)
def get_hosts(kessel_filter=None):
    return query_hosts(kessel_filter)
```

## Testing

For testing, you can:

1. Use the `bypass_rbac` configuration to disable authorization
2. Mock the Kessel client
3. Use the cache management functions to clear state between tests

```python
# Test setup
def setUp(self):
    clear_kessel_auth_cache()
    
# Mock Kessel client
with patch('lib.kessel_auth.get_kessel_client') as mock_client:
    mock_client.return_value.ListAllowedWorkspaces.return_value = ['group1', 'group2']
    result = your_function()
```

## Debugging

Enable debug logging to see authorization decisions:

```python
@kessel_auth(RbacResourceType.HOSTS, RbacPermission.READ)
def debug_endpoint(kessel_filter=None):
    from flask import g
    
    # Check access control rule
    access_rule = getattr(g, 'access_control_rule', 'unknown')
    logger.info(f"Access control rule: {access_rule}")
    
    # Log filter information
    if kessel_filter:
        logger.info(f"Authorization filter: {kessel_filter}")
    
    return {"access_rule": access_rule, "filter": kessel_filter}
```

## Best Practices

1. **Always handle the kessel_filter parameter** in your functions
2. **Use convenience decorators** for common patterns
3. **Enable caching** for better performance
4. **Monitor metrics** to track authorization performance
5. **Use fallback_to_rbac** during migration periods
6. **Test thoroughly** with different permission scenarios
7. **Clear cache** when user permissions change
8. **Log authorization decisions** for debugging

## Troubleshooting

### Common Issues

1. **503 Service Unavailable**: Kessel service is down
   - Check Kessel service status
   - Enable `fallback_to_rbac` if needed

2. **403 Forbidden**: User lacks permissions
   - Check user's group memberships
   - Verify Kessel permissions configuration

3. **500 Internal Server Error**: Authorization error
   - Check logs for specific error details
   - Verify Kessel client configuration

### Performance Issues

1. **Slow authorization**: 
   - Enable caching
   - Monitor `kessel_auth_duration_seconds` metric
   - Check Kessel service performance

2. **High cache miss rate**:
   - Adjust cache TTL
   - Monitor `kessel_auth_cache_hits_total` metric

## Configuration Reference

### Environment Variables

- `KESSEL_TARGET_URL`: Kessel service URL
- `BYPASS_RBAC`: Bypass all authorization (testing only)
- `RBAC_TIMEOUT`: Timeout for authorization requests

### Feature Flags

- `hbi.api.kessel-host-migration`: Enable Kessel authorization
- `hbi.api.read-only`: Disable write operations

## Support

For issues or questions:

1. Check the logs for specific error messages
2. Review the metrics for performance insights
3. Consult the example code in `examples/kessel_auth_example.py`
4. File an issue with detailed error information 