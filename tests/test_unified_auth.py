"""
Tests for the unified authorization system.

This module contains comprehensive tests for the unified authorization interceptor
that handles both Kessel and RBAC authorization flows based on feature flags
and operation types.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from flask import Flask, g
from http import HTTPStatus

from app import RbacResourceType, RbacPermission
from app.auth.identity import Identity, IdentityType
from lib.unified_auth import (
    unified_auth,
    OperationType,
    AuthorizationMethod,
    AuthorizationResult,
    OperationTypeDetector,
    AuthorizationDecisionEngine,
    auth_read,
    auth_write,
    auth_create,
    auth_admin,
    check_bulk_resources,
    lookup_allowed_resources,
    get_authorization_metadata,
    is_authorization_bypassed,
    get_current_authorization_method
)


class TestOperationTypeDetector:
    """Tests for operation type detection."""
    
    def test_explicit_operation_type(self):
        """Test that explicit operation type is used when provided."""
        result = OperationTypeDetector.detect_operation_type(
            "GET", "/hosts", "get_hosts", OperationType.UNBOUNDED
        )
        assert result == OperationType.UNBOUNDED
    
    def test_http_method_mapping(self):
        """Test HTTP method to operation type mapping."""
        test_cases = [
            ("GET", OperationType.READ),
            ("HEAD", OperationType.READ),
            ("POST", OperationType.CREATE),
            ("PUT", OperationType.MODIFY),
            ("PATCH", OperationType.MODIFY),
            ("DELETE", OperationType.MODIFY),
        ]
        
        for method, expected_type in test_cases:
            result = OperationTypeDetector.detect_operation_type(
                method, "/hosts", "some_function"
            )
            assert result == expected_type
    
    def test_unbounded_patterns_in_endpoint(self):
        """Test detection of unbounded patterns in endpoint."""
        unbounded_endpoints = [
            "/hosts/search",
            "/hosts/query",
            "/hosts/filter",
            "/hosts/bulk",
            "/hosts/export",
            "/hosts/report"
        ]
        
        for endpoint in unbounded_endpoints:
            result = OperationTypeDetector.detect_operation_type(
                "GET", endpoint, "some_function"
            )
            assert result == OperationType.UNBOUNDED
    
    def test_unbounded_patterns_in_function_name(self):
        """Test detection of unbounded patterns in function name."""
        unbounded_functions = [
            "search_hosts",
            "query_hosts",
            "filter_hosts",
            "bulk_update",
            "export_data",
            "report_hosts"
        ]
        
        for function_name in unbounded_functions:
            result = OperationTypeDetector.detect_operation_type(
                "GET", "/hosts", function_name
            )
            assert result == OperationType.UNBOUNDED
    
    def test_case_insensitive_pattern_matching(self):
        """Test that pattern matching is case insensitive."""
        result = OperationTypeDetector.detect_operation_type(
            "GET", "/hosts/SEARCH", "SEARCH_HOSTS"
        )
        assert result == OperationType.UNBOUNDED
    
    def test_default_fallback(self):
        """Test fallback to READ for unknown HTTP methods."""
        result = OperationTypeDetector.detect_operation_type(
            "UNKNOWN", "/hosts", "some_function"
        )
        assert result == OperationType.READ


class TestAuthorizationResult:
    """Tests for AuthorizationResult class."""
    
    def test_authorization_result_creation(self):
        """Test creation of AuthorizationResult."""
        filters = {"groups": ["group1", "group2"]}
        metadata = {"kessel_client": True}
        
        result = AuthorizationResult(
            allowed=True,
            method=AuthorizationMethod.KESSEL,
            filters=filters,
            metadata=metadata
        )
        
        assert result.allowed is True
        assert result.method == AuthorizationMethod.KESSEL
        assert result.filters == filters
        assert result.metadata == metadata
        assert result.timestamp is not None
    
    def test_authorization_result_defaults(self):
        """Test default values for AuthorizationResult."""
        result = AuthorizationResult(
            allowed=False,
            method=AuthorizationMethod.RBAC
        )
        
        assert result.allowed is False
        assert result.method == AuthorizationMethod.RBAC
        assert result.filters == {}
        assert result.metadata == {}


class TestAuthorizationDecisionEngine:
    """Tests for AuthorizationDecisionEngine."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.engine = AuthorizationDecisionEngine()
        self.mock_identity = Mock(spec=Identity)
        self.mock_identity.identity_type = IdentityType.USER
        self.mock_identity.org_id = "test-org"
        self.mock_identity.user = {"user_id": "test-user"}
    
    @patch('lib.unified_auth.inventory_config')
    def test_determine_authorization_method_explicit(self, mock_config):
        """Test explicit authorization method specification."""
        mock_config.return_value.bypass_rbac = False
        
        result = self.engine.determine_authorization_method(
            OperationType.READ,
            RbacResourceType.HOSTS,
            AuthorizationMethod.KESSEL
        )
        
        assert result == AuthorizationMethod.KESSEL
    
    @patch('lib.unified_auth.inventory_config')
    def test_determine_authorization_method_bypass(self, mock_config):
        """Test bypass authorization method."""
        mock_config.return_value.bypass_rbac = True
        
        result = self.engine.determine_authorization_method(
            OperationType.READ,
            RbacResourceType.HOSTS
        )
        
        assert result == AuthorizationMethod.BYPASS
    
    @patch('lib.unified_auth.inventory_config')
    @patch('lib.unified_auth.get_flag_value')
    def test_determine_authorization_method_kessel_enabled(self, mock_flag, mock_config):
        """Test Kessel authorization when feature flag is enabled."""
        mock_config.return_value.bypass_rbac = False
        mock_flag.return_value = True
        
        result = self.engine.determine_authorization_method(
            OperationType.READ,
            RbacResourceType.HOSTS
        )
        
        assert result == AuthorizationMethod.KESSEL
    
    @patch('lib.unified_auth.inventory_config')
    @patch('lib.unified_auth.get_flag_value')
    def test_determine_authorization_method_kessel_groups_fallback(self, mock_flag, mock_config):
        """Test fallback to RBAC for groups even when Kessel is enabled."""
        mock_config.return_value.bypass_rbac = False
        mock_flag.return_value = True
        
        result = self.engine.determine_authorization_method(
            OperationType.READ,
            RbacResourceType.GROUPS
        )
        
        assert result == AuthorizationMethod.RBAC
    
    @patch('lib.unified_auth.inventory_config')
    @patch('lib.unified_auth.get_flag_value')
    def test_determine_authorization_method_rbac_default(self, mock_flag, mock_config):
        """Test default to RBAC when Kessel is disabled."""
        mock_config.return_value.bypass_rbac = False
        mock_flag.return_value = False
        
        result = self.engine.determine_authorization_method(
            OperationType.READ,
            RbacResourceType.HOSTS
        )
        
        assert result == AuthorizationMethod.RBAC
    
    @patch('lib.unified_auth.get_kessel_client')
    @patch('lib.unified_auth.get_kessel_filter')
    def test_perform_kessel_authorization_success(self, mock_filter, mock_client):
        """Test successful Kessel authorization."""
        mock_filter.return_value = (True, {"groups": ["group1", "group2"]})
        
        result = self.engine._perform_kessel_authorization(
            self.mock_identity,
            RbacResourceType.HOSTS,
            RbacPermission.READ,
            "inventory"
        )
        
        assert result.allowed is True
        assert result.method == AuthorizationMethod.KESSEL
        assert result.filters == {"groups": ["group1", "group2"]}
        assert result.metadata["kessel_client"] is True
    
    @patch('lib.unified_auth.get_kessel_client')
    @patch('lib.unified_auth.get_kessel_filter')
    def test_perform_kessel_authorization_failure(self, mock_filter, mock_client):
        """Test Kessel authorization failure."""
        mock_filter.side_effect = Exception("Kessel connection failed")
        
        result = self.engine._perform_kessel_authorization(
            self.mock_identity,
            RbacResourceType.HOSTS,
            RbacPermission.READ,
            "inventory"
        )
        
        assert result.allowed is False
        assert result.method == AuthorizationMethod.KESSEL
        assert "error" in result.metadata
        assert result.metadata["kessel_client"] is True
    
    @patch('lib.unified_auth._build_rbac_request_headers')
    @patch('lib.unified_auth.get_rbac_filter')
    def test_perform_rbac_authorization_success(self, mock_filter, mock_headers):
        """Test successful RBAC authorization."""
        mock_headers.return_value = {"x-rh-identity": "test"}
        mock_filter.return_value = (True, {"groups": ["group1", "group2"]})
        
        result = self.engine._perform_rbac_authorization(
            self.mock_identity,
            RbacResourceType.HOSTS,
            RbacPermission.READ,
            "inventory"
        )
        
        assert result.allowed is True
        assert result.method == AuthorizationMethod.RBAC
        assert result.filters == {"groups": ["group1", "group2"]}
        assert result.metadata["rbac_client"] is True
    
    @patch('lib.unified_auth._build_rbac_request_headers')
    @patch('lib.unified_auth.get_rbac_filter')
    def test_perform_rbac_authorization_failure(self, mock_filter, mock_headers):
        """Test RBAC authorization failure."""
        mock_headers.return_value = {"x-rh-identity": "test"}
        mock_filter.side_effect = Exception("RBAC connection failed")
        
        result = self.engine._perform_rbac_authorization(
            self.mock_identity,
            RbacResourceType.HOSTS,
            RbacPermission.READ,
            "inventory"
        )
        
        assert result.allowed is False
        assert result.method == AuthorizationMethod.RBAC
        assert "error" in result.metadata
        assert result.metadata["rbac_client"] is True


class TestUnifiedAuthDecorator:
    """Tests for the unified authorization decorator."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.app = Flask(__name__)
        self.app.config['TESTING'] = True
        
        self.mock_identity = Mock(spec=Identity)
        self.mock_identity.identity_type = IdentityType.USER
        self.mock_identity.org_id = "test-org"
        self.mock_identity.user = {"user_id": "test-user"}
    
    @patch('lib.unified_auth.get_current_identity')
    @patch('lib.unified_auth.get_flag_value')
    def test_successful_authorization_with_filter(self, mock_flag, mock_identity):
        """Test successful authorization with filter injection."""
        mock_identity.return_value = self.mock_identity
        mock_flag.return_value = False  # Disable read-only mode
        
        @unified_auth(RbacResourceType.HOSTS)
        def test_func(auth_filter=None):
            return {"filter": auth_filter}
        
        with self.app.test_request_context('/', method='GET'):
            with patch.object(AuthorizationDecisionEngine, 'perform_authorization') as mock_auth:
                mock_auth.return_value = AuthorizationResult(
                    allowed=True,
                    method=AuthorizationMethod.KESSEL,
                    filters={"groups": ["group1", "group2"]}
                )
                
                result = test_func()
                
                assert result["filter"] == {"groups": ["group1", "group2"]}
                assert hasattr(g, 'access_control_rule')
    
    @patch('lib.unified_auth.get_current_identity')
    @patch('lib.unified_auth.get_flag_value')
    def test_authorization_denied(self, mock_flag, mock_identity):
        """Test authorization denial."""
        mock_identity.return_value = self.mock_identity
        mock_flag.return_value = False  # Disable read-only mode
        
        @unified_auth(RbacResourceType.HOSTS)
        def test_func(auth_filter=None):
            return {"result": "success"}
        
        with self.app.test_request_context('/', method='GET'):
            with patch.object(AuthorizationDecisionEngine, 'perform_authorization') as mock_auth:
                mock_auth.return_value = AuthorizationResult(
                    allowed=False,
                    method=AuthorizationMethod.KESSEL
                )
                
                with pytest.raises(Exception) as excinfo:
                    test_func()
                
                assert "403" in str(excinfo.value) or "Forbidden" in str(excinfo.value)
    
    @patch('lib.unified_auth.get_current_identity')
    @patch('lib.unified_auth.get_flag_value')
    def test_read_only_mode_blocks_writes(self, mock_flag, mock_identity):
        """Test that read-only mode blocks write operations."""
        mock_identity.return_value = self.mock_identity
        mock_flag.side_effect = lambda flag: flag == "hbi.api.read-only"  # Enable read-only mode
        
        @unified_auth(RbacResourceType.HOSTS, permission=RbacPermission.WRITE)
        def test_func(auth_filter=None):
            return {"result": "success"}
        
        with self.app.test_request_context('/', method='POST'):
            with pytest.raises(Exception) as excinfo:
                test_func()
            
            assert "503" in str(excinfo.value) or "read-only" in str(excinfo.value).lower()
    
    @patch('lib.unified_auth.get_current_identity')
    @patch('lib.unified_auth.get_flag_value')
    def test_auto_permission_detection(self, mock_flag, mock_identity):
        """Test automatic permission detection based on operation type."""
        mock_identity.return_value = self.mock_identity
        mock_flag.return_value = False
        
        @unified_auth(RbacResourceType.HOSTS)  # No explicit permission
        def test_func(auth_filter=None):
            return {"result": "success"}
        
        with self.app.test_request_context('/', method='GET'):
            with patch.object(AuthorizationDecisionEngine, 'perform_authorization') as mock_auth:
                mock_auth.return_value = AuthorizationResult(
                    allowed=True,
                    method=AuthorizationMethod.KESSEL
                )
                
                test_func()
                
                # Verify READ permission was auto-detected for GET request
                args, kwargs = mock_auth.call_args
                assert args[3] == RbacPermission.READ  # permission argument
    
    @patch('lib.unified_auth.get_current_identity')
    @patch('lib.unified_auth.get_flag_value')
    def test_custom_filter_parameter_name(self, mock_flag, mock_identity):
        """Test custom filter parameter name."""
        mock_identity.return_value = self.mock_identity
        mock_flag.return_value = False
        
        @unified_auth(RbacResourceType.HOSTS, filter_param_name="custom_filter")
        def test_func(custom_filter=None):
            return {"filter": custom_filter}
        
        with self.app.test_request_context('/', method='GET'):
            with patch.object(AuthorizationDecisionEngine, 'perform_authorization') as mock_auth:
                mock_auth.return_value = AuthorizationResult(
                    allowed=True,
                    method=AuthorizationMethod.KESSEL,
                    filters={"groups": ["group1"]}
                )
                
                result = test_func()
                
                assert result["filter"] == {"groups": ["group1"]}


class TestConvenienceDecorators:
    """Tests for convenience decorators."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.app = Flask(__name__)
        self.app.config['TESTING'] = True
    
    @patch('lib.unified_auth.unified_auth')
    def test_auth_read_decorator(self, mock_unified_auth):
        """Test auth_read convenience decorator."""
        mock_decorator = Mock()
        mock_unified_auth.return_value = mock_decorator
        
        @auth_read(RbacResourceType.HOSTS)
        def test_func():
            return "success"
        
        mock_unified_auth.assert_called_once_with(
            resource_type=RbacResourceType.HOSTS,
            permission=RbacPermission.READ,
            application="inventory",
            operation_type=OperationType.READ
        )
    
    @patch('lib.unified_auth.unified_auth')
    def test_auth_write_decorator(self, mock_unified_auth):
        """Test auth_write convenience decorator."""
        mock_decorator = Mock()
        mock_unified_auth.return_value = mock_decorator
        
        @auth_write(RbacResourceType.HOSTS)
        def test_func():
            return "success"
        
        mock_unified_auth.assert_called_once_with(
            resource_type=RbacResourceType.HOSTS,
            permission=RbacPermission.WRITE,
            application="inventory",
            operation_type=OperationType.MODIFY
        )
    
    @patch('lib.unified_auth.unified_auth')
    def test_auth_create_decorator(self, mock_unified_auth):
        """Test auth_create convenience decorator."""
        mock_decorator = Mock()
        mock_unified_auth.return_value = mock_decorator
        
        @auth_create(RbacResourceType.HOSTS)
        def test_func():
            return "success"
        
        mock_unified_auth.assert_called_once_with(
            resource_type=RbacResourceType.HOSTS,
            permission=RbacPermission.WRITE,
            application="inventory",
            operation_type=OperationType.CREATE
        )
    
    @patch('lib.unified_auth.unified_auth')
    def test_auth_admin_decorator(self, mock_unified_auth):
        """Test auth_admin convenience decorator."""
        mock_decorator = Mock()
        mock_unified_auth.return_value = mock_decorator
        
        @auth_admin(RbacResourceType.HOSTS)
        def test_func():
            return "success"
        
        mock_unified_auth.assert_called_once_with(
            resource_type=RbacResourceType.HOSTS,
            permission=RbacPermission.ADMIN,
            application="inventory",
            operation_type=OperationType.UNBOUNDED
        )


class TestBulkResourceCheck:
    """Tests for bulk resource checking functionality."""
    
    def test_bulk_check_no_filter(self):
        """Test bulk check with no filter (unrestricted access)."""
        auth_filter = None
        requested_ids = ["group1", "group2", "group3"]
        
        # Should not raise exception
        check_bulk_resources(auth_filter, requested_ids, RbacResourceType.GROUPS)
    
    def test_bulk_check_allowed_groups(self):
        """Test bulk check with allowed groups."""
        auth_filter = {"groups": ["group1", "group2", "group3"]}
        requested_ids = ["group1", "group2"]
        
        # Should not raise exception
        check_bulk_resources(auth_filter, requested_ids, RbacResourceType.GROUPS)
    
    def test_bulk_check_denied_groups(self):
        """Test bulk check with denied groups."""
        auth_filter = {"groups": ["group1", "group2"]}
        requested_ids = ["group1", "group3"]  # group3 not allowed
        
        # Should raise exception
        with pytest.raises(Exception) as excinfo:
            check_bulk_resources(auth_filter, requested_ids, RbacResourceType.GROUPS)
        
        assert "403" in str(excinfo.value) or "Forbidden" in str(excinfo.value)
        assert "group3" in str(excinfo.value)
    
    def test_bulk_check_empty_filter(self):
        """Test bulk check with empty filter."""
        auth_filter = {}
        requested_ids = ["group1", "group2"]
        
        # Should not raise exception
        check_bulk_resources(auth_filter, requested_ids, RbacResourceType.GROUPS)


class TestResourceLookup:
    """Tests for resource lookup functionality."""
    
    def test_lookup_no_filter(self):
        """Test resource lookup with no filter (unrestricted access)."""
        auth_filter = None
        
        result = lookup_allowed_resources(auth_filter, RbacResourceType.GROUPS)
        
        assert result == []  # Empty list indicates no filtering needed
    
    def test_lookup_with_groups_filter(self):
        """Test resource lookup with groups filter."""
        auth_filter = {"groups": ["group1", "group2", "group3"]}
        
        result = lookup_allowed_resources(auth_filter, RbacResourceType.GROUPS)
        
        assert result == ["group1", "group2", "group3"]
    
    def test_lookup_empty_filter(self):
        """Test resource lookup with empty filter."""
        auth_filter = {}
        
        result = lookup_allowed_resources(auth_filter, RbacResourceType.GROUPS)
        
        assert result == []
    
    def test_lookup_wrong_resource_type(self):
        """Test resource lookup with wrong resource type."""
        auth_filter = {"groups": ["group1", "group2"]}
        
        result = lookup_allowed_resources(auth_filter, RbacResourceType.HOSTS)
        
        assert result == []  # No matching resource type


class TestUtilityFunctions:
    """Tests for utility functions."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.app = Flask(__name__)
        self.app.config['TESTING'] = True
    
    def test_get_authorization_metadata(self):
        """Test getting authorization metadata."""
        with self.app.test_request_context('/'):
            g.access_control_rule = "KESSEL"
            g.request_id = "test-request-id"
            
            metadata = get_authorization_metadata()
            
            assert metadata["access_control_rule"] == "KESSEL"
            assert metadata["request_id"] == "test-request-id"
            assert "timestamp" in metadata
    
    def test_get_authorization_metadata_defaults(self):
        """Test getting authorization metadata with defaults."""
        with self.app.test_request_context('/'):
            metadata = get_authorization_metadata()
            
            assert metadata["access_control_rule"] == "unknown"
            assert metadata["request_id"] is None
            assert "timestamp" in metadata
    
    @patch('lib.unified_auth.inventory_config')
    def test_is_authorization_bypassed(self, mock_config):
        """Test checking if authorization is bypassed."""
        mock_config.return_value.bypass_rbac = True
        
        result = is_authorization_bypassed()
        
        assert result is True
    
    def test_get_current_authorization_method(self):
        """Test getting current authorization method."""
        with self.app.test_request_context('/'):
            g.access_control_rule = "KESSEL"
            
            method = get_current_authorization_method()
            
            assert method == "KESSEL"
    
    def test_get_current_authorization_method_none(self):
        """Test getting current authorization method when none set."""
        with self.app.test_request_context('/'):
            method = get_current_authorization_method()
            
            assert method is None


class TestIntegration:
    """Integration tests for the unified authorization system."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.app = Flask(__name__)
        self.app.config['TESTING'] = True
    
    @patch('lib.unified_auth.get_current_identity')
    @patch('lib.unified_auth.get_flag_value')
    @patch('lib.unified_auth.inventory_config')
    @patch('lib.unified_auth.get_kessel_client')
    @patch('lib.unified_auth.get_kessel_filter')
    def test_complete_kessel_flow(self, mock_kessel_filter, mock_client, mock_config, mock_flag, mock_identity):
        """Test complete Kessel authorization flow."""
        # Setup mocks
        mock_identity.return_value = Mock(
            identity_type=IdentityType.USER,
            org_id="test-org",
            user={"user_id": "test-user"}
        )
        mock_config.return_value.bypass_rbac = False
        mock_flag.return_value = True  # Enable Kessel
        mock_kessel_filter.return_value = (True, {"groups": ["group1", "group2"]})
        
        @unified_auth(RbacResourceType.HOSTS)
        def test_func(auth_filter=None):
            return {"filter": auth_filter, "method": get_current_authorization_method()}
        
        with self.app.test_request_context('/', method='GET'):
            result = test_func()
            
            assert result["filter"] == {"groups": ["group1", "group2"]}
            assert result["method"] == "KESSEL"
    
    @patch('lib.unified_auth.get_current_identity')
    @patch('lib.unified_auth.get_flag_value')
    @patch('lib.unified_auth.inventory_config')
    @patch('lib.unified_auth._build_rbac_request_headers')
    @patch('lib.unified_auth.get_rbac_filter')
    def test_complete_rbac_flow(self, mock_rbac_filter, mock_headers, mock_config, mock_flag, mock_identity):
        """Test complete RBAC authorization flow."""
        # Setup mocks
        mock_identity.return_value = Mock(
            identity_type=IdentityType.USER,
            org_id="test-org",
            user={"user_id": "test-user"}
        )
        mock_config.return_value.bypass_rbac = False
        mock_flag.return_value = False  # Disable Kessel
        mock_headers.return_value = {"x-rh-identity": "test"}
        mock_rbac_filter.return_value = (True, {"groups": ["group1", "group2"]})
        
        @unified_auth(RbacResourceType.HOSTS)
        def test_func(auth_filter=None):
            return {"filter": auth_filter, "method": get_current_authorization_method()}
        
        with self.app.test_request_context('/', method='GET'):
            result = test_func()
            
            assert result["filter"] == {"groups": ["group1", "group2"]}
            assert result["method"] == "RBAC"


if __name__ == "__main__":
    pytest.main([__file__]) 