# Authorization System for HBI

This document describes the authorization system for Host Based Inventory (HBI), which provides two main authorization decorators:

1. **Kessel-specific decorator** (`@kessel_auth`) - Direct integration with Kessel authorization
2. **Unified authorization decorator** (`@unified_auth`) - Smart decorator that handles both Kessel and RBAC based on feature flags

## 🔄 Architecture Overview

The authorization system implements the following flow:

```
HTTP Request 
    ↓
Identity Extraction 
    ↓
Identify Operation Type (read/view, modify/delete, create, unbounded query)
    ↓
@unified_auth Decorator
    ↓
Feature Flag Check
    ↓
┌─────────────────┬─────────────────┐
│  Kessel Enabled │ Kessel Disabled │
└─────────────────┴─────────────────┘
    ↓                     ↓
Kessel Authorization  RBAC Authorization
    ↓                     ↓
└─────────────────┬─────────────────┘
                  ↓
        Authorization Decision
                  ↓
    ┌─────────────┴─────────────┐
    │ Allowed + Filter │ Denied │
    └─────────────────┴─────────────┘
                  ↓
            Call Handler Function
```

## 🚀 Quick Start

### Unified Authorization (Recommended)

```python
from lib.unified_auth import unified_auth
from app import RbacResourceType, RbacPermission

@unified_auth(RbacResourceType.HOSTS)
def get_hosts(auth_filter=None):
    """
    Automatically detects:
    - Operation type: READ (from GET request)
    - Permission: READ (from operation type)
    - Authorization method: Kessel or RBAC (from feature flags)
    """
    if auth_filter and "groups" in auth_filter:
        # User has limited access to specific groups
        return query_hosts_by_groups(auth_filter["groups"])
    else:
        # User has unrestricted access
        return query_all_hosts()
```

### Kessel-Specific Authorization

```python
from lib.kessel_auth import kessel_auth
from app import RbacResourceType, RbacPermission

@kessel_auth(RbacResourceType.HOSTS, RbacPermission.READ)
def get_hosts(kessel_filter=None):
    """Direct Kessel authorization - bypasses RBAC entirely"""
    if kessel_filter and "groups" in kessel_filter:
        return query_hosts_by_groups(kessel_filter["groups"])
    else:
        return query_all_hosts()
```

## 📋 Operation Types

The system automatically detects operation types based on HTTP methods and endpoint patterns:

| Operation Type | HTTP Methods | Endpoint Patterns | Auto-Permission |
|---------------|-------------|------------------|----------------|
| `READ` | GET, HEAD | - | `READ` |
| `MODIFY` | PUT, PATCH, DELETE | - | `WRITE` |
| `CREATE` | POST | - | `WRITE` |
| `UNBOUNDED` | Any | search, query, filter, bulk, export, report | `ADMIN` |

### Manual Operation Type Override

```python
@unified_auth(
    RbacResourceType.HOSTS,
    operation_type=OperationType.UNBOUNDED,
    permission=RbacPermission.ADMIN
)
def complex_search(auth_filter=None):
    """Override automatic detection for complex operations"""
    pass
```

## 🔧 Configuration Options

### Unified Authorization Options

```python
@unified_auth(
    resource_type=RbacResourceType.HOSTS,           # Required
    permission=RbacPermission.READ,                 # Optional - auto-detected
    application="inventory",                        # Optional - default: "inventory"
    operation_type=OperationType.READ,              # Optional - auto-detected
    auth_method=AuthorizationMethod.KESSEL,         # Optional - auto-detected
    filter_param_name="auth_filter"                 # Optional - default: "auth_filter"
)
def my_endpoint(auth_filter=None):
    pass
```

### Kessel-Specific Options

```python
@kessel_auth(
    resource_type=RbacResourceType.HOSTS,           # Required
    permission=RbacPermission.READ,                 # Required
    application="inventory",                        # Optional - default: "inventory"
    cache_enabled=True,                             # Optional - default: True
    require_kessel_migration=True,                  # Optional - default: True
    fallback_to_rbac=False                          # Optional - default: False
)
def my_endpoint(kessel_filter=None):
    pass
```

## 🎯 Usage Patterns

### 1. Basic CRUD Operations

```python
# Read operations
@unified_auth(RbacResourceType.HOSTS)
def get_hosts(auth_filter=None): pass

@unified_auth(RbacResourceType.HOSTS)
def get_host_by_id(host_id, auth_filter=None): pass

# Write operations  
@unified_auth(RbacResourceType.HOSTS, permission=RbacPermission.WRITE)
def update_host(host_id, auth_filter=None): pass

@unified_auth(RbacResourceType.HOSTS, permission=RbacPermission.WRITE)
def delete_host(host_id, auth_filter=None): pass
```

### 2. Bulk Operations

```python
from lib.unified_auth import check_bulk_resources

@unified_auth(RbacResourceType.GROUPS, permission=RbacPermission.WRITE)
def bulk_update_groups(auth_filter=None):
    group_ids = request.get_json().get("group_ids", [])
    
    # Verify user has access to all requested groups
    check_bulk_resources(auth_filter, group_ids, RbacResourceType.GROUPS)
    
    # Process groups
    for group_id in group_ids:
        update_group(group_id)
```

### 3. Resource Lookup

```python
from lib.unified_auth import lookup_allowed_resources

@unified_auth(RbacResourceType.GROUPS)
def get_accessible_groups(auth_filter=None):
    # Get groups user can access
    accessible_groups = lookup_allowed_resources(auth_filter, RbacResourceType.GROUPS)
    
    if accessible_groups:
        # Return specific groups
        return query_groups_by_ids(accessible_groups)
    else:
        # Return all groups (unrestricted access)
        return query_all_groups()
```

### 4. Convenience Decorators

```python
from lib.unified_auth import auth_read, auth_write, auth_create, auth_admin

@auth_read(RbacResourceType.HOSTS)
def get_hosts(): pass

@auth_write(RbacResourceType.HOSTS) 
def update_host(): pass

@auth_create(RbacResourceType.GROUPS)
def create_group(): pass

@auth_admin(RbacResourceType.HOSTS)
def admin_operation(): pass
```

## 🔄 Migration Guide

### From Existing @rbac Decorator

```python
# Before
@rbac(RbacResourceType.HOSTS, RbacPermission.READ)
def get_hosts(rbac_filter=None):
    return query_hosts(rbac_filter)

# After (Phase 1: Unified with fallback)
@unified_auth(RbacResourceType.HOSTS)
def get_hosts(auth_filter=None):
    return query_hosts(auth_filter)

# After (Phase 2: Kessel-specific)
@kessel_auth(RbacResourceType.HOSTS, RbacPermission.READ)
def get_hosts(kessel_filter=None):
    return query_hosts(kessel_filter)
```

### Migration Steps

1. **Phase 1**: Replace `@rbac` with `@unified_auth`
   - Maintains backward compatibility
   - Automatically switches between RBAC and Kessel based on feature flags
   - Change filter parameter name from `rbac_filter` to `auth_filter`

2. **Phase 2**: Monitor and validate
   - Enable Kessel feature flag: `FLAG_INVENTORY_KESSEL_HOST_MIGRATION`
   - Monitor metrics and logs
   - Verify authorization behavior

3. **Phase 3**: Optimize (optional)
   - Replace with `@kessel_auth` for Kessel-only endpoints
   - Remove feature flag dependencies

## 📊 Monitoring and Metrics

### Prometheus Metrics

#### Unified Authorization
- `unified_auth_requests_total{method, operation_type, resource_type, permission, result}`
- `unified_auth_duration_seconds{method, operation_type, resource_type, permission}`

#### Kessel-Specific
- `kessel_auth_requests_total{resource_type, permission, application, result}`
- `kessel_auth_duration_seconds{resource_type, permission, application}`
- `kessel_auth_cache_hits_total{resource_type, permission, application}`
- `kessel_auth_active_requests`

### Logging

```python
from lib.unified_auth import get_authorization_metadata

@unified_auth(RbacResourceType.HOSTS)
def my_endpoint(auth_filter=None):
    metadata = get_authorization_metadata()
    logger.info(f"Authorization: {metadata['access_control_rule']}")
    logger.info(f"Filter applied: {bool(auth_filter)}")
```

## 🧪 Testing

### Unit Tests

```python
from unittest.mock import patch
from lib.unified_auth import unified_auth, AuthorizationResult, AuthorizationMethod

@patch('lib.unified_auth.get_current_identity')
@patch('lib.unified_auth.AuthorizationDecisionEngine.perform_authorization')
def test_my_endpoint(mock_auth, mock_identity):
    mock_identity.return_value = create_mock_identity()
    mock_auth.return_value = AuthorizationResult(
        allowed=True,
        method=AuthorizationMethod.KESSEL,
        filters={"groups": ["group1", "group2"]}
    )
    
    @unified_auth(RbacResourceType.HOSTS)
    def my_endpoint(auth_filter=None):
        return {"filter": auth_filter}
    
    with app.test_request_context('/', method='GET'):
        result = my_endpoint()
        assert result["filter"] == {"groups": ["group1", "group2"]}
```

### Integration Tests

```python
def test_complete_flow():
    """Test complete authorization flow with real components"""
    # Setup test user with specific group permissions
    # Make request to endpoint
    # Verify correct filtering applied
    pass
```

## 🔧 Configuration

### Feature Flags

- `FLAG_INVENTORY_KESSEL_HOST_MIGRATION`: Enable Kessel authorization for hosts
- `FLAG_INVENTORY_API_READ_ONLY`: Disable write operations globally

### Environment Variables

- `BYPASS_RBAC`: Bypass all authorization (testing only)
- `KESSEL_TARGET_URL`: Kessel service URL
- `RBAC_ENDPOINT`: RBAC service URL

### Application Configuration

```python
# In your app configuration
KESSEL_CACHE_TTL = 300  # 5 minutes
RBAC_TIMEOUT = 30       # 30 seconds
```

## 🚨 Error Handling

### HTTP Status Codes

- `403 Forbidden`: User lacks required permissions
- `503 Service Unavailable`: Authorization service unavailable or API in read-only mode
- `500 Internal Server Error`: Authorization system error

### Error Scenarios

```python
@unified_auth(RbacResourceType.HOSTS)
def my_endpoint(auth_filter=None):
    """
    Automatic error handling:
    - KesselAuthConnectionError → 503
    - KesselAuthPermissionError → 403
    - RbacAuthError → 403/503
    - General exceptions → 500
    """
    pass
```

## 📝 Best Practices

### 1. Always Handle Filters

```python
@unified_auth(RbacResourceType.HOSTS)
def get_hosts(auth_filter=None):
    if auth_filter and "groups" in auth_filter:
        # Apply filtering
        return Host.query.filter(Host.group_id.in_(auth_filter["groups"])).all()
    else:
        # Unrestricted access
        return Host.query.all()
```

### 2. Use Bulk Checks for Multi-Resource Operations

```python
@unified_auth(RbacResourceType.GROUPS, permission=RbacPermission.WRITE)
def update_multiple_groups(auth_filter=None):
    group_ids = get_group_ids_from_request()
    check_bulk_resources(auth_filter, group_ids, RbacResourceType.GROUPS)
    # Proceed with updates
```

### 3. Cache Considerations

```python
# Clear cache when permissions change
from lib.kessel_auth import clear_kessel_auth_cache

def update_user_permissions():
    # Update permissions
    clear_kessel_auth_cache()  # Clear stale cache
```

### 4. Monitoring

```python
from lib.unified_auth import get_authorization_metadata

@unified_auth(RbacResourceType.HOSTS)
def my_endpoint(auth_filter=None):
    metadata = get_authorization_metadata()
    
    # Log authorization decisions
    logger.info(f"Auth method: {metadata['access_control_rule']}")
    logger.info(f"Filtered: {bool(auth_filter)}")
    
    # Add to response for debugging
    return {
        "data": get_data(),
        "auth_info": metadata  # Remove in production
    }
```

## 📚 API Reference

### Unified Authorization

- `@unified_auth(resource_type, permission?, application?, operation_type?, auth_method?, filter_param_name?)`
- `@auth_read(resource_type, application?)`
- `@auth_write(resource_type, application?)`
- `@auth_create(resource_type, application?)`
- `@auth_admin(resource_type, application?)`
- `check_bulk_resources(auth_filter, resource_ids, resource_type)`
- `lookup_allowed_resources(auth_filter, resource_type)`

### Kessel-Specific

- `@kessel_auth(resource_type, permission, application?, cache_enabled?, require_kessel_migration?, fallback_to_rbac?)`
- `@kessel_read_hosts(func)`
- `@kessel_write_hosts(func)`
- `@kessel_read_groups(func)`
- `@kessel_write_groups(func)`
- `kessel_group_id_check(kessel_filter, requested_ids)`

### Utilities

- `get_authorization_metadata()` - Get current authorization info
- `is_authorization_bypassed()` - Check if authorization is bypassed
- `get_current_authorization_method()` - Get current authorization method

## 🆘 Troubleshooting

### Common Issues

1. **403 Forbidden**: Check user permissions in Kessel/RBAC
2. **503 Service Unavailable**: Check Kessel/RBAC service status
3. **Filter not applied**: Ensure filter parameter is handled in function
4. **Cache issues**: Clear cache after permission changes

### Debug Mode

```python
@unified_auth(RbacResourceType.HOSTS)
def debug_endpoint(auth_filter=None):
    from lib.unified_auth import get_authorization_metadata
    
    metadata = get_authorization_metadata()
    return {
        "auth_method": metadata["access_control_rule"],
        "filter": auth_filter,
        "has_filter": bool(auth_filter)
    }
```

## 🔗 Related Documentation

- [Kessel Authorization Documentation](docs/kessel_authorization.md)
- [RBAC Integration Guide](docs/rbac_integration.md)
- [Feature Flag Configuration](docs/feature_flags.md)
- [Monitoring and Metrics](docs/monitoring.md) 