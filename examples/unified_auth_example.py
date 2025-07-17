"""
Example usage of the unified authorization decorator based on the flow diagrams.

This file demonstrates how to use the @unified_auth decorator to implement
the authorization flow shown in the diagrams:

1. HTTP Request -> Identity Extraction
2. Identify Operation Type (read/view, modify/delete, create, unbounded query)
3. Feature Flag Check (Kessel Enabled/Disabled)
4. Apply appropriate authorization (Kessel or RBAC)
5. Return filtered results or deny access

The examples show various patterns including bulk checks, resource lookups,
and different operation types.
"""

from flask import Flask, jsonify, request
from typing import Dict, Any, Optional, List

from app import RbacPermission, RbacResourceType
from lib.unified_auth import (
    unified_auth,
    auth_read,
    auth_write,
    auth_create,
    auth_admin,
    auth_hosts_read,
    auth_hosts_write,
    auth_groups_read,
    auth_groups_write,
    check_bulk_resources,
    lookup_allowed_resources,
    get_authorization_metadata,
    OperationType,
    AuthorizationMethod
)
from app.logging import get_logger

logger = get_logger(__name__)

app = Flask(__name__)


# Example 1: Basic unified authorization with automatic operation type detection
@unified_auth(RbacResourceType.HOSTS)
def get_hosts(auth_filter=None):
    """
    GET /hosts - Automatically detected as READ operation.
    
    The decorator will:
    1. Extract identity from HTTP request
    2. Detect operation type as READ based on HTTP method
    3. Check feature flags to determine Kessel vs RBAC
    4. Apply appropriate authorization
    5. Inject auth_filter if user has limited access
    """
    logger.info("Getting hosts with unified authorization")
    
    # Get authorization metadata
    auth_metadata = get_authorization_metadata()
    logger.info(f"Authorization method: {auth_metadata['access_control_rule']}")
    
    if auth_filter and "groups" in auth_filter:
        allowed_groups = auth_filter["groups"]
        logger.info(f"User has access to groups: {allowed_groups}")
        # Query would filter by these groups
        hosts = [
            {"id": "host1", "name": "server1", "group": "group1"},
            {"id": "host2", "name": "server2", "group": "group2"}
        ]
        return jsonify({
            "hosts": hosts,
            "filtered_by_groups": allowed_groups,
            "auth_method": auth_metadata["access_control_rule"]
        })
    else:
        logger.info("User has unrestricted access to all hosts")
        hosts = [
            {"id": "host1", "name": "server1", "group": "group1"},
            {"id": "host2", "name": "server2", "group": "group2"},
            {"id": "host3", "name": "server3", "group": "group3"}
        ]
        return jsonify({
            "hosts": hosts,
            "auth_method": auth_metadata["access_control_rule"]
        })


# Example 2: Explicit operation type and permission specification
@unified_auth(
    RbacResourceType.HOSTS,
    permission=RbacPermission.WRITE,
    operation_type=OperationType.MODIFY
)
def update_host(host_id: str, auth_filter=None):
    """
    PUT /hosts/<host_id> - Explicitly configured as MODIFY operation with WRITE permission.
    
    This shows how to override automatic detection when needed.
    """
    logger.info(f"Updating host {host_id}")
    
    # In a real implementation, you'd verify the host's group is accessible
    if auth_filter and "groups" in auth_filter:
        # Check if this host's group is in the allowed groups
        # This would typically involve a database query
        allowed_groups = auth_filter["groups"]
        logger.info(f"User can modify hosts in groups: {allowed_groups}")
    
    update_data = request.get_json()
    
    return jsonify({
        "message": f"Host {host_id} updated successfully",
        "auth_method": get_authorization_metadata()["access_control_rule"]
    })


# Example 3: Bulk operations with resource checking
@unified_auth(RbacResourceType.GROUPS, permission=RbacPermission.WRITE)
def bulk_update_groups(auth_filter=None):
    """
    POST /groups/bulk - Bulk update multiple groups.
    
    This demonstrates the bulk check functionality shown in the sequence diagram.
    """
    logger.info("Bulk updating groups")
    
    request_data = request.get_json()
    group_ids = request_data.get("group_ids", [])
    
    # Perform bulk check - this will abort if any group is not accessible
    check_bulk_resources(auth_filter, group_ids, RbacResourceType.GROUPS)
    
    # Process each group
    results = []
    for group_id in group_ids:
        # Your update logic here
        results.append({
            "group_id": group_id,
            "status": "updated",
            "timestamp": "2024-01-01T00:00:00Z"
        })
    
    return jsonify({
        "results": results,
        "processed_count": len(group_ids),
        "auth_method": get_authorization_metadata()["access_control_rule"]
    })


# Example 4: Resource lookup operation
@unified_auth(RbacResourceType.GROUPS, permission=RbacPermission.READ)
def lookup_accessible_groups(auth_filter=None):
    """
    GET /groups/accessible - Look up groups the user can access.
    
    This demonstrates the lookup resources functionality from the sequence diagram.
    """
    logger.info("Looking up accessible groups")
    
    # Get list of groups user can access
    accessible_groups = lookup_allowed_resources(auth_filter, RbacResourceType.GROUPS)
    
    if accessible_groups:
        # User has limited access to specific groups
        groups_data = []
        for group_id in accessible_groups:
            # In real implementation, query database for each group
            groups_data.append({
                "id": group_id,
                "name": f"Group {group_id}",
                "description": f"Description for group {group_id}"
            })
        
        return jsonify({
            "groups": groups_data,
            "access_type": "filtered",
            "auth_method": get_authorization_metadata()["access_control_rule"]
        })
    else:
        # User has unrestricted access - return all groups
        all_groups = [
            {"id": "group1", "name": "Group 1", "description": "First group"},
            {"id": "group2", "name": "Group 2", "description": "Second group"},
            {"id": "group3", "name": "Group 3", "description": "Third group"}
        ]
        
        return jsonify({
            "groups": all_groups,
            "access_type": "unrestricted",
            "auth_method": get_authorization_metadata()["access_control_rule"]
        })


# Example 5: Unbounded query operation
@unified_auth(
    RbacResourceType.HOSTS,
    permission=RbacPermission.ADMIN,
    operation_type=OperationType.UNBOUNDED
)
def search_hosts(auth_filter=None):
    """
    GET /hosts/search - Unbounded query operation requiring admin permissions.
    
    This demonstrates unbounded queries that might return large datasets.
    """
    logger.info("Performing unbounded host search")
    
    search_params = request.args
    query = search_params.get("query", "")
    
    # This would be a complex search across all hosts
    # Admin permissions are typically required for such operations
    
    return jsonify({
        "message": f"Search completed for query: {query}",
        "operation_type": "unbounded",
        "auth_method": get_authorization_metadata()["access_control_rule"]
    })


# Example 6: Using convenience decorators
@auth_hosts_read
def get_host_by_id(host_id: str, auth_filter=None):
    """
    GET /hosts/<host_id> - Using convenience decorator for host read operations.
    
    This shows the simplified decorator usage.
    """
    logger.info(f"Getting host {host_id}")
    
    # In real implementation, check if host's group is accessible
    if auth_filter and "groups" in auth_filter:
        allowed_groups = auth_filter["groups"]
        # Verify host belongs to an allowed group
        logger.info(f"Checking if host {host_id} is in allowed groups: {allowed_groups}")
    
    return jsonify({
        "host_id": host_id,
        "name": f"host-{host_id}",
        "status": "active",
        "auth_method": get_authorization_metadata()["access_control_rule"]
    })


@auth_groups_write
def create_group(auth_filter=None):
    """
    POST /groups - Using convenience decorator for group create operations.
    """
    logger.info("Creating new group")
    
    group_data = request.get_json()
    group_name = group_data.get("name", "new-group")
    
    # In real implementation, ensure group is created in user's accessible workspace
    if auth_filter and "groups" in auth_filter:
        logger.info(f"User can create groups in workspaces: {auth_filter['groups']}")
    
    return jsonify({
        "message": f"Group {group_name} created successfully",
        "group_id": "new-group-id",
        "auth_method": get_authorization_metadata()["access_control_rule"]
    })


# Example 7: Force specific authorization method
@unified_auth(
    RbacResourceType.HOSTS,
    permission=RbacPermission.READ,
    auth_method=AuthorizationMethod.KESSEL
)
def get_hosts_kessel_only(auth_filter=None):
    """
    GET /hosts/kessel - Force Kessel authorization only.
    
    This bypasses feature flag checks and forces Kessel authorization.
    """
    logger.info("Getting hosts with forced Kessel authorization")
    
    return jsonify({
        "hosts": ["host1", "host2"],
        "auth_method": "KESSEL",
        "forced": True
    })


# Example 8: Custom filter parameter name
@unified_auth(
    RbacResourceType.GROUPS,
    permission=RbacPermission.READ,
    filter_param_name="custom_filter"
)
def get_groups_custom_filter(custom_filter=None):
    """
    GET /groups/custom - Using custom filter parameter name.
    
    This shows how to customize the injected parameter name.
    """
    logger.info("Getting groups with custom filter parameter")
    
    if custom_filter and "groups" in custom_filter:
        allowed_groups = custom_filter["groups"]
        return jsonify({
            "groups": allowed_groups,
            "filter_param": "custom_filter"
        })
    
    return jsonify({
        "groups": ["group1", "group2", "group3"],
        "filter_param": "custom_filter"
    })


# Example 9: Multiple authorization checks in one endpoint
@unified_auth(RbacResourceType.HOSTS, permission=RbacPermission.READ)
def get_hosts_with_groups(auth_filter=None):
    """
    GET /hosts-with-groups - Multiple authorization checks within one endpoint.
    
    This shows how to perform additional authorization checks within a function.
    """
    logger.info("Getting hosts with associated groups")
    
    # Primary authorization is for hosts (handled by decorator)
    hosts_data = []
    if auth_filter and "groups" in auth_filter:
        allowed_groups = auth_filter["groups"]
        # Query hosts in allowed groups
        hosts_data = [
            {"id": "host1", "name": "server1", "group": "group1"},
            {"id": "host2", "name": "server2", "group": "group2"}
        ]
    
    # If we also want to show group details, we might need additional checks
    # This would typically involve calling authorization functions directly
    
    return jsonify({
        "hosts": hosts_data,
        "auth_method": get_authorization_metadata()["access_control_rule"]
    })


# Example 10: Error handling and debugging
@unified_auth(RbacResourceType.HOSTS)
def debug_authorization(auth_filter=None):
    """
    GET /debug - Debug authorization flow.
    
    This shows how to inspect the authorization process.
    """
    logger.info("Debug authorization endpoint")
    
    # Get detailed authorization metadata
    auth_metadata = get_authorization_metadata()
    
    return jsonify({
        "authorization_metadata": auth_metadata,
        "auth_filter": auth_filter,
        "has_filter": bool(auth_filter),
        "filter_keys": list(auth_filter.keys()) if auth_filter else [],
        "request_method": request.method,
        "endpoint": request.endpoint
    })


# Flask routes setup
def setup_routes():
    """Set up Flask routes for the examples."""
    app.add_url_rule('/hosts', 'get_hosts', get_hosts, methods=['GET'])
    app.add_url_rule('/hosts/<host_id>', 'update_host', update_host, methods=['PUT'])
    app.add_url_rule('/hosts/<host_id>', 'get_host_by_id', get_host_by_id, methods=['GET'])
    app.add_url_rule('/groups/bulk', 'bulk_update_groups', bulk_update_groups, methods=['POST'])
    app.add_url_rule('/groups/accessible', 'lookup_accessible_groups', lookup_accessible_groups, methods=['GET'])
    app.add_url_rule('/hosts/search', 'search_hosts', search_hosts, methods=['GET'])
    app.add_url_rule('/groups', 'create_group', create_group, methods=['POST'])
    app.add_url_rule('/hosts/kessel', 'get_hosts_kessel_only', get_hosts_kessel_only, methods=['GET'])
    app.add_url_rule('/groups/custom', 'get_groups_custom_filter', get_groups_custom_filter, methods=['GET'])
    app.add_url_rule('/hosts-with-groups', 'get_hosts_with_groups', get_hosts_with_groups, methods=['GET'])
    app.add_url_rule('/debug', 'debug_authorization', debug_authorization, methods=['GET'])


# Request flow demonstration
@app.before_request
def log_request_flow():
    """Log the request flow as shown in the diagrams."""
    logger.info(f"=== HTTP Request Flow ===")
    logger.info(f"1. HTTP Request: {request.method} {request.path}")
    logger.info(f"2. Identity Extraction: {request.headers.get('x-rh-identity', 'Not found')}")
    logger.info(f"3. Endpoint: {request.endpoint}")


@app.after_request
def log_response_flow(response):
    """Log the response flow."""
    auth_method = get_authorization_metadata().get("access_control_rule", "unknown")
    logger.info(f"4. Authorization Decision: {auth_method}")
    logger.info(f"5. Response: {response.status_code}")
    logger.info(f"=== End Request Flow ===")
    return response


if __name__ == "__main__":
    setup_routes()
    app.run(debug=True)


# Example usage with curl commands:
"""
# 1. Get hosts (READ operation - auto-detected)
curl -X GET http://localhost:5000/hosts \
  -H "x-rh-identity: <base64-encoded-identity>"

# 2. Update host (MODIFY operation - auto-detected)
curl -X PUT http://localhost:5000/hosts/host-123 \
  -H "Content-Type: application/json" \
  -H "x-rh-identity: <base64-encoded-identity>" \
  -d '{"name": "updated-host"}'

# 3. Bulk update groups (with bulk check)
curl -X POST http://localhost:5000/groups/bulk \
  -H "Content-Type: application/json" \
  -H "x-rh-identity: <base64-encoded-identity>" \
  -d '{"group_ids": ["group1", "group2", "group3"]}'

# 4. Look up accessible groups
curl -X GET http://localhost:5000/groups/accessible \
  -H "x-rh-identity: <base64-encoded-identity>"

# 5. Search hosts (UNBOUNDED operation)
curl -X GET "http://localhost:5000/hosts/search?query=server" \
  -H "x-rh-identity: <base64-encoded-identity>"

# 6. Debug authorization
curl -X GET http://localhost:5000/debug \
  -H "x-rh-identity: <base64-encoded-identity>"
""" 