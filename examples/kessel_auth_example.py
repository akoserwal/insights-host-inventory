"""
Example usage of the Kessel authorization decorator for HBI.

This file demonstrates various ways to use the @kessel_auth decorator
for different types of operations and resources.
"""

from flask import jsonify, request
from typing import Dict, Any, Optional

from app import RbacPermission, RbacResourceType
from lib.kessel_auth import (
    kessel_auth, 
    kessel_read_hosts, 
    kessel_write_hosts,
    kessel_read_groups,
    kessel_write_groups,
    kessel_admin_all,
    kessel_group_id_check
)
from app.logging import get_logger

logger = get_logger(__name__)


# Example 1: Basic usage with explicit parameters
@kessel_auth(RbacResourceType.HOSTS, RbacPermission.READ)
def get_hosts(kessel_filter: Optional[Dict[str, Any]] = None):
    """
    Get hosts with Kessel authorization.
    
    The kessel_filter parameter will be automatically injected by the decorator
    if the user has limited access to specific groups.
    """
    logger.info("Getting hosts with Kessel authorization")
    
    # Use the kessel_filter to limit query results
    if kessel_filter and "groups" in kessel_filter:
        allowed_groups = kessel_filter["groups"]
        logger.info(f"User has access to groups: {allowed_groups}")
        # Your database query logic here would filter by these groups
        return jsonify({
            "hosts": ["host1", "host2"],  # Filtered results
            "filtered_by_groups": allowed_groups
        })
    else:
        logger.info("User has unrestricted access to all hosts")
        # Return all hosts
        return jsonify({"hosts": ["host1", "host2", "host3", "host4"]})


# Example 2: Using convenience decorators
@kessel_read_hosts
def get_host_by_id(host_id: str, kessel_filter: Optional[Dict[str, Any]] = None):
    """Get a specific host by ID with read permission check."""
    logger.info(f"Getting host {host_id}")
    
    # Check if user has access to this host's group
    if kessel_filter:
        # In a real implementation, you'd check if the host's group is in the filter
        pass
    
    return jsonify({"host_id": host_id, "name": f"host-{host_id}"})


@kessel_write_hosts
def update_host(host_id: str, kessel_filter: Optional[Dict[str, Any]] = None):
    """Update a host with write permission check."""
    logger.info(f"Updating host {host_id}")
    
    # Get the update data from request
    update_data = request.get_json()
    
    # Check if user has access to modify this host
    if kessel_filter:
        # In a real implementation, you'd verify the host's group is in the filter
        pass
    
    return jsonify({"message": f"Host {host_id} updated successfully"})


# Example 3: Group operations
@kessel_read_groups
def get_groups(kessel_filter: Optional[Dict[str, Any]] = None):
    """Get groups with Kessel authorization."""
    logger.info("Getting groups with Kessel authorization")
    
    if kessel_filter and "groups" in kessel_filter:
        allowed_groups = kessel_filter["groups"]
        return jsonify({"groups": allowed_groups})
    else:
        return jsonify({"groups": ["group1", "group2", "group3"]})


@kessel_write_groups
def create_group(kessel_filter: Optional[Dict[str, Any]] = None):
    """Create a new group with write permission check."""
    logger.info("Creating new group")
    
    group_data = request.get_json()
    group_name = group_data.get("name", "new-group")
    
    # In a real implementation, you'd create the group and ensure
    # it's created in a workspace the user has access to
    
    return jsonify({"message": f"Group {group_name} created successfully"})


@kessel_write_groups
def update_group(group_id: str, kessel_filter: Optional[Dict[str, Any]] = None):
    """Update a group with explicit group ID checking."""
    logger.info(f"Updating group {group_id}")
    
    # Check if user has access to this specific group
    kessel_group_id_check(kessel_filter, {group_id})
    
    update_data = request.get_json()
    
    return jsonify({"message": f"Group {group_id} updated successfully"})


# Example 4: Admin operations
@kessel_admin_all
def admin_operation(kessel_filter: Optional[Dict[str, Any]] = None):
    """Admin operation requiring full access."""
    logger.info("Performing admin operation")
    
    # Admin operations typically don't need filtering
    return jsonify({"message": "Admin operation completed successfully"})


# Example 5: Custom application and configuration
@kessel_auth(
    RbacResourceType.HOSTS, 
    RbacPermission.READ,
    application="custom-app",
    cache_enabled=True,
    require_kessel_migration=False,
    fallback_to_rbac=True
)
def custom_configured_endpoint(kessel_filter: Optional[Dict[str, Any]] = None):
    """
    Example with custom configuration options.
    
    This shows how to:
    - Use a custom application name
    - Enable caching
    - Disable requirement for Kessel migration flag
    - Enable fallback to RBAC if Kessel is unavailable
    """
    logger.info("Custom configured endpoint")
    
    return jsonify({"message": "Custom endpoint accessed successfully"})


# Example 6: Error handling
@kessel_auth(RbacResourceType.HOSTS, RbacPermission.READ)
def error_handling_example(kessel_filter: Optional[Dict[str, Any]] = None):
    """
    Example showing how errors are handled.
    
    The decorator automatically handles:
    - KesselAuthConnectionError -> 503 Service Unavailable
    - KesselAuthPermissionError -> 403 Forbidden
    - KesselAuthError -> 500 Internal Server Error
    - General exceptions -> 500 Internal Server Error
    """
    logger.info("Error handling example")
    
    # Your business logic here
    # If any errors occur in Kessel authorization, they're handled by the decorator
    
    return jsonify({"message": "Success"})


# Example 7: Batch operations with group checking
@kessel_write_groups
def batch_update_groups(kessel_filter: Optional[Dict[str, Any]] = None):
    """Update multiple groups with batch group ID checking."""
    logger.info("Batch updating groups")
    
    group_ids = request.get_json().get("group_ids", [])
    
    # Check if user has access to all requested groups
    kessel_group_id_check(kessel_filter, set(group_ids))
    
    # Process each group
    results = []
    for group_id in group_ids:
        # Your update logic here
        results.append(f"Updated group {group_id}")
    
    return jsonify({"results": results})


# Example 8: Conditional authorization based on parameters
@kessel_auth(RbacResourceType.HOSTS, RbacPermission.READ)
def conditional_access(resource_type: str, kessel_filter: Optional[Dict[str, Any]] = None):
    """
    Example where authorization might vary based on parameters.
    
    Note: The decorator authorization happens before the function runs,
    so you can't conditionally authorize based on parameters.
    Instead, you might need multiple endpoints or check permissions
    within the function.
    """
    logger.info(f"Accessing resource type: {resource_type}")
    
    if resource_type == "sensitive":
        # You might need additional checks here
        if not kessel_filter:
            # Only users with unrestricted access can see sensitive data
            return jsonify({"data": "sensitive information"})
        else:
            return jsonify({"error": "Access denied to sensitive data"}), 403
    
    return jsonify({"data": f"Regular {resource_type} data"})


# Example 9: Integration with existing RBAC patterns
def hybrid_authorization_example():
    """
    Example showing how to integrate Kessel auth with existing patterns.
    
    You might want to gradually migrate from RBAC to Kessel, or use
    both systems depending on conditions.
    """
    
    # Option 1: Use the fallback_to_rbac parameter
    @kessel_auth(
        RbacResourceType.HOSTS, 
        RbacPermission.READ,
        fallback_to_rbac=True
    )
    def with_rbac_fallback(kessel_filter: Optional[Dict[str, Any]] = None):
        return jsonify({"message": "Success with fallback"})
    
    # Option 2: Conditionally apply different decorators
    # (This would require more complex logic based on feature flags)
    
    return with_rbac_fallback


# Example 10: Testing and debugging
@kessel_auth(RbacResourceType.HOSTS, RbacPermission.READ)
def debug_authorization(kessel_filter: Optional[Dict[str, Any]] = None):
    """
    Example for testing and debugging authorization.
    
    This shows how to inspect the authorization results.
    """
    from flask import g
    
    logger.info("Debug authorization example")
    
    # Check what access control rule was used
    access_rule = getattr(g, 'access_control_rule', 'unknown')
    logger.info(f"Access control rule: {access_rule}")
    
    # Log the filter information
    if kessel_filter:
        logger.info(f"Authorization filter: {kessel_filter}")
    else:
        logger.info("No authorization filter applied (unrestricted access)")
    
    return jsonify({
        "access_control_rule": access_rule,
        "kessel_filter": kessel_filter,
        "message": "Debug info retrieved"
    })


# Example usage in a Flask blueprint or app
def register_routes(app):
    """Register the example routes with a Flask app."""
    app.add_url_rule('/hosts', 'get_hosts', get_hosts, methods=['GET'])
    app.add_url_rule('/hosts/<host_id>', 'get_host_by_id', get_host_by_id, methods=['GET'])
    app.add_url_rule('/hosts/<host_id>', 'update_host', update_host, methods=['PUT'])
    app.add_url_rule('/groups', 'get_groups', get_groups, methods=['GET'])
    app.add_url_rule('/groups', 'create_group', create_group, methods=['POST'])
    app.add_url_rule('/groups/<group_id>', 'update_group', update_group, methods=['PUT'])
    app.add_url_rule('/groups/batch', 'batch_update_groups', batch_update_groups, methods=['PUT'])
    app.add_url_rule('/admin/operation', 'admin_operation', admin_operation, methods=['POST'])
    app.add_url_rule('/custom', 'custom_configured_endpoint', custom_configured_endpoint, methods=['GET'])
    app.add_url_rule('/debug', 'debug_authorization', debug_authorization, methods=['GET']) 