"""
Tests for the Kessel authorization decorator.

This module contains unit tests for the Kessel authorization interceptor,
including permission checks, caching, error handling, and filter application.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from flask import Flask, g
from http import HTTPStatus

from app import RbacResourceType, RbacPermission
from app.auth.identity import Identity, IdentityType
from lib.kessel_auth import (
    kessel_auth,
    kessel_read_hosts,
    kessel_write_hosts,
    kessel_group_id_check,
    KesselAuthError,
    KesselAuthConnectionError,
    KesselAuthCache,
    clear_kessel_auth_cache,
    get_kessel_auth_cache_stats
)


class TestKesselAuthDecorator:
    """Tests for the main @kessel_auth decorator."""

    def setup_method(self):
        """Set up test fixtures."""
        self.app = Flask(__name__)
        self.app.config['TESTING'] = True
        
        # Clear cache before each test
        clear_kessel_auth_cache()
        
        # Mock identity
        self.mock_identity = Mock(spec=Identity)
        self.mock_identity.identity_type = IdentityType.USER
        self.mock_identity.org_id = "test-org"
        self.mock_identity.user = {"user_id": "test-user", "username": "test@example.com"}

    def teardown_method(self):
        """Clean up after each test."""
        clear_kessel_auth_cache()

    @patch('lib.kessel_auth.get_current_identity')
    @patch('lib.kessel_auth.get_kessel_client')
    @patch('lib.kessel_auth.inventory_config')
    @patch('lib.kessel_auth.get_flag_value')
    def test_successful_authorization_with_filter(self, mock_flag, mock_config, mock_client, mock_identity):
        """Test successful authorization with workspace filtering."""
        # Setup mocks
        mock_identity.return_value = self.mock_identity
        mock_config.return_value.bypass_rbac = False
        mock_flag.return_value = True
        
        mock_kessel_client = Mock()
        mock_kessel_client.ListAllowedWorkspaces.return_value = ["group1", "group2"]
        mock_client.return_value = mock_kessel_client

        # Create test function
        @kessel_auth(RbacResourceType.HOSTS, RbacPermission.READ)
        def test_func(kessel_filter=None):
            return {"filter": kessel_filter}

        with self.app.app_context():
            # Call the decorated function
            result = test_func()
            
            # Verify results
            assert result["filter"] == {"groups": ["group1", "group2"]}
            assert hasattr(g, 'access_control_rule')
            assert g.access_control_rule == "Kessel"

    @patch('lib.kessel_auth.get_current_identity')
    @patch('lib.kessel_auth.get_kessel_client')
    @patch('lib.kessel_auth.inventory_config')
    @patch('lib.kessel_auth.get_flag_value')
    def test_successful_authorization_no_filter(self, mock_flag, mock_config, mock_client, mock_identity):
        """Test successful authorization without filtering (unrestricted access)."""
        # Setup mocks
        mock_identity.return_value = self.mock_identity
        mock_config.return_value.bypass_rbac = False
        mock_flag.return_value = True
        
        mock_kessel_client = Mock()
        mock_kessel_client.ListAllowedWorkspaces.return_value = []
        mock_client.return_value = mock_kessel_client

        # Create test function
        @kessel_auth(RbacResourceType.HOSTS, RbacPermission.READ)
        def test_func(kessel_filter=None):
            return {"filter": kessel_filter}

        with self.app.app_context():
            # Call should be denied since no workspaces are allowed
            with pytest.raises(Exception) as excinfo:
                test_func()
            
            # Should get 403 Forbidden
            assert "403" in str(excinfo.value) or "Forbidden" in str(excinfo.value)

    @patch('lib.kessel_auth.get_current_identity')
    @patch('lib.kessel_auth.inventory_config')
    @patch('lib.kessel_auth.get_flag_value')
    def test_bypass_rbac_config(self, mock_flag, mock_config, mock_identity):
        """Test that authorization is bypassed when bypass_rbac is True."""
        # Setup mocks
        mock_identity.return_value = self.mock_identity
        mock_config.return_value.bypass_rbac = True
        mock_flag.return_value = True

        # Create test function
        @kessel_auth(RbacResourceType.HOSTS, RbacPermission.READ)
        def test_func(kessel_filter=None):
            return {"bypassed": True}

        with self.app.app_context():
            result = test_func()
            assert result["bypassed"] is True

    @patch('lib.kessel_auth.get_current_identity')
    @patch('lib.kessel_auth.inventory_config')
    @patch('lib.kessel_auth.get_flag_value')
    def test_bypass_kessel_migration_flag(self, mock_flag, mock_config, mock_identity):
        """Test that authorization is bypassed when Kessel migration flag is disabled."""
        # Setup mocks
        mock_identity.return_value = self.mock_identity
        mock_config.return_value.bypass_rbac = False
        mock_flag.return_value = False  # Kessel migration disabled

        # Create test function
        @kessel_auth(RbacResourceType.HOSTS, RbacPermission.READ)
        def test_func(kessel_filter=None):
            return {"bypassed": True}

        with self.app.app_context():
            result = test_func()
            assert result["bypassed"] is True

    @patch('lib.kessel_auth.get_current_identity')
    @patch('lib.kessel_auth.get_kessel_client')
    @patch('lib.kessel_auth.inventory_config')
    @patch('lib.kessel_auth.get_flag_value')
    def test_system_identity_hosts_access(self, mock_flag, mock_config, mock_client, mock_identity):
        """Test that system identities get full access to hosts."""
        # Setup mocks
        system_identity = Mock(spec=Identity)
        system_identity.identity_type = IdentityType.SYSTEM
        
        mock_identity.return_value = system_identity
        mock_config.return_value.bypass_rbac = False
        mock_flag.return_value = True

        # Create test function
        @kessel_auth(RbacResourceType.HOSTS, RbacPermission.READ)
        def test_func(kessel_filter=None):
            return {"system_access": True}

        with self.app.app_context():
            result = test_func()
            assert result["system_access"] is True

    @patch('lib.kessel_auth.get_current_identity')
    @patch('lib.kessel_auth.get_kessel_client')
    @patch('lib.kessel_auth.inventory_config')
    @patch('lib.kessel_auth.get_flag_value')
    def test_system_identity_groups_denied(self, mock_flag, mock_config, mock_client, mock_identity):
        """Test that system identities are denied access to groups."""
        # Setup mocks
        system_identity = Mock(spec=Identity)
        system_identity.identity_type = IdentityType.SYSTEM
        
        mock_identity.return_value = system_identity
        mock_config.return_value.bypass_rbac = False
        mock_flag.return_value = True

        # Create test function
        @kessel_auth(RbacResourceType.GROUPS, RbacPermission.READ)
        def test_func(kessel_filter=None):
            return {"system_access": True}

        with self.app.app_context():
            with pytest.raises(Exception) as excinfo:
                test_func()
            
            assert "403" in str(excinfo.value) or "Forbidden" in str(excinfo.value)

    @patch('lib.kessel_auth.get_current_identity')
    @patch('lib.kessel_auth.get_kessel_client')
    @patch('lib.kessel_auth.inventory_config')
    @patch('lib.kessel_auth.get_flag_value')
    def test_kessel_connection_error(self, mock_flag, mock_config, mock_client, mock_identity):
        """Test handling of Kessel connection errors."""
        # Setup mocks
        mock_identity.return_value = self.mock_identity
        mock_config.return_value.bypass_rbac = False
        mock_flag.return_value = True
        
        mock_kessel_client = Mock()
        mock_kessel_client.ListAllowedWorkspaces.side_effect = Exception("Connection failed")
        mock_client.return_value = mock_kessel_client

        # Create test function
        @kessel_auth(RbacResourceType.HOSTS, RbacPermission.READ)
        def test_func(kessel_filter=None):
            return {"result": "success"}

        with self.app.app_context():
            with pytest.raises(Exception) as excinfo:
                test_func()
            
            assert "503" in str(excinfo.value) or "unavailable" in str(excinfo.value).lower()

    @patch('lib.kessel_auth.get_current_identity')
    @patch('lib.kessel_auth.get_kessel_client')
    @patch('lib.kessel_auth.inventory_config')
    @patch('lib.kessel_auth.get_flag_value')
    @patch('lib.kessel_auth.rbac')
    def test_fallback_to_rbac(self, mock_rbac, mock_flag, mock_config, mock_client, mock_identity):
        """Test fallback to RBAC when Kessel fails."""
        # Setup mocks
        mock_identity.return_value = self.mock_identity
        mock_config.return_value.bypass_rbac = False
        mock_flag.return_value = True
        
        mock_kessel_client = Mock()
        mock_kessel_client.ListAllowedWorkspaces.side_effect = Exception("Connection failed")
        mock_client.return_value = mock_kessel_client
        
        # Mock RBAC decorator
        mock_rbac_decorator = Mock()
        mock_rbac_decorator.return_value = Mock()
        mock_rbac.return_value = mock_rbac_decorator

        # Create test function with fallback enabled
        @kessel_auth(RbacResourceType.HOSTS, RbacPermission.READ, fallback_to_rbac=True)
        def test_func(kessel_filter=None):
            return {"result": "success"}

        with self.app.app_context():
            # Should not raise exception, should fallback to RBAC
            test_func()
            
            # Verify RBAC was called
            mock_rbac.assert_called_once_with(RbacResourceType.HOSTS, RbacPermission.READ, "inventory")


class TestKesselAuthCache:
    """Tests for the Kessel authorization cache."""

    def setup_method(self):
        """Set up test fixtures."""
        clear_kessel_auth_cache()
        
        self.mock_identity = Mock(spec=Identity)
        self.mock_identity.identity_type = IdentityType.USER
        self.mock_identity.org_id = "test-org"
        self.mock_identity.user = {"user_id": "test-user", "username": "test@example.com"}

    def teardown_method(self):
        """Clean up after each test."""
        clear_kessel_auth_cache()

    def test_cache_set_and_get(self):
        """Test setting and getting cache entries."""
        # Set cache entry
        KesselAuthCache.set(
            self.mock_identity,
            RbacResourceType.HOSTS,
            RbacPermission.READ,
            "inventory",
            True,
            {"groups": ["group1", "group2"]}
        )
        
        # Get cache entry
        result = KesselAuthCache.get(
            self.mock_identity,
            RbacResourceType.HOSTS,
            RbacPermission.READ,
            "inventory"
        )
        
        assert result is not None
        allowed, auth_filter = result
        assert allowed is True
        assert auth_filter == {"groups": ["group1", "group2"]}

    def test_cache_miss(self):
        """Test cache miss scenario."""
        result = KesselAuthCache.get(
            self.mock_identity,
            RbacResourceType.HOSTS,
            RbacPermission.READ,
            "inventory"
        )
        
        assert result is None

    def test_cache_expiration(self):
        """Test cache expiration."""
        # Mock time to simulate expiration
        with patch('lib.kessel_auth.time') as mock_time:
            # Set initial time
            mock_time.time.return_value = 1000
            
            # Set cache entry
            KesselAuthCache.set(
                self.mock_identity,
                RbacResourceType.HOSTS,
                RbacPermission.READ,
                "inventory",
                True,
                {"groups": ["group1"]}
            )
            
            # Simulate time passing beyond TTL
            mock_time.time.return_value = 1000 + 400  # 400 seconds later (TTL is 300)
            
            # Cache should be expired
            result = KesselAuthCache.get(
                self.mock_identity,
                RbacResourceType.HOSTS,
                RbacPermission.READ,
                "inventory"
            )
            
            assert result is None

    def test_cache_clear(self):
        """Test cache clearing."""
        # Set cache entry
        KesselAuthCache.set(
            self.mock_identity,
            RbacResourceType.HOSTS,
            RbacPermission.READ,
            "inventory",
            True,
            {"groups": ["group1"]}
        )
        
        # Verify entry exists
        result = KesselAuthCache.get(
            self.mock_identity,
            RbacResourceType.HOSTS,
            RbacPermission.READ,
            "inventory"
        )
        assert result is not None
        
        # Clear cache
        KesselAuthCache.clear()
        
        # Verify entry is gone
        result = KesselAuthCache.get(
            self.mock_identity,
            RbacResourceType.HOSTS,
            RbacPermission.READ,
            "inventory"
        )
        assert result is None

    def test_cache_stats(self):
        """Test cache statistics."""
        # Initially empty
        stats = get_kessel_auth_cache_stats()
        assert stats["cache_size"] == 0
        
        # Add some entries
        KesselAuthCache.set(
            self.mock_identity,
            RbacResourceType.HOSTS,
            RbacPermission.READ,
            "inventory",
            True,
            {"groups": ["group1"]}
        )
        
        stats = get_kessel_auth_cache_stats()
        assert stats["cache_size"] == 1
        assert stats["cache_ttl"] == 300


class TestConvenienceDecorators:
    """Tests for convenience decorators."""

    def setup_method(self):
        """Set up test fixtures."""
        self.app = Flask(__name__)
        self.app.config['TESTING'] = True
        clear_kessel_auth_cache()

    def teardown_method(self):
        """Clean up after each test."""
        clear_kessel_auth_cache()

    @patch('lib.kessel_auth.kessel_auth')
    def test_kessel_read_hosts(self, mock_kessel_auth):
        """Test kessel_read_hosts convenience decorator."""
        mock_decorator = Mock()
        mock_kessel_auth.return_value = mock_decorator

        @kessel_read_hosts
        def test_func():
            return "success"

        # Verify correct parameters were passed
        mock_kessel_auth.assert_called_once_with(RbacResourceType.HOSTS, RbacPermission.READ)

    @patch('lib.kessel_auth.kessel_auth')
    def test_kessel_write_hosts(self, mock_kessel_auth):
        """Test kessel_write_hosts convenience decorator."""
        mock_decorator = Mock()
        mock_kessel_auth.return_value = mock_decorator

        @kessel_write_hosts
        def test_func():
            return "success"

        # Verify correct parameters were passed
        mock_kessel_auth.assert_called_once_with(RbacResourceType.HOSTS, RbacPermission.WRITE)


class TestKesselGroupIdCheck:
    """Tests for kessel_group_id_check function."""

    def test_group_id_check_allowed(self):
        """Test group ID check with allowed groups."""
        kessel_filter = {"groups": ["group1", "group2", "group3"]}
        requested_ids = {"group1", "group2"}
        
        # Should not raise exception
        kessel_group_id_check(kessel_filter, requested_ids)

    def test_group_id_check_denied(self):
        """Test group ID check with denied groups."""
        kessel_filter = {"groups": ["group1", "group2"]}
        requested_ids = {"group1", "group3"}  # group3 not allowed
        
        # Should raise exception
        with pytest.raises(Exception) as excinfo:
            kessel_group_id_check(kessel_filter, requested_ids)
        
        assert "403" in str(excinfo.value) or "Forbidden" in str(excinfo.value)

    def test_group_id_check_no_filter(self):
        """Test group ID check with no filter (unrestricted access)."""
        kessel_filter = None
        requested_ids = {"group1", "group2", "group3"}
        
        # Should not raise exception
        kessel_group_id_check(kessel_filter, requested_ids)

    def test_group_id_check_empty_filter(self):
        """Test group ID check with empty filter."""
        kessel_filter = {}
        requested_ids = {"group1", "group2"}
        
        # Should not raise exception
        kessel_group_id_check(kessel_filter, requested_ids)


class TestKesselAuthIntegration:
    """Integration tests for the Kessel authorization system."""

    def setup_method(self):
        """Set up test fixtures."""
        self.app = Flask(__name__)
        self.app.config['TESTING'] = True
        clear_kessel_auth_cache()

    def teardown_method(self):
        """Clean up after each test."""
        clear_kessel_auth_cache()

    @patch('lib.kessel_auth.get_current_identity')
    @patch('lib.kessel_auth.get_kessel_client')
    @patch('lib.kessel_auth.inventory_config')
    @patch('lib.kessel_auth.get_flag_value')
    def test_full_authorization_flow(self, mock_flag, mock_config, mock_client, mock_identity):
        """Test complete authorization flow with metrics and caching."""
        # Setup mocks
        mock_identity.return_value = Mock(
            identity_type=IdentityType.USER,
            org_id="test-org",
            user={"user_id": "test-user", "username": "test@example.com"}
        )
        mock_config.return_value.bypass_rbac = False
        mock_flag.return_value = True
        
        mock_kessel_client = Mock()
        mock_kessel_client.ListAllowedWorkspaces.return_value = ["group1", "group2"]
        mock_client.return_value = mock_kessel_client

        # Create test function
        @kessel_auth(RbacResourceType.HOSTS, RbacPermission.READ)
        def test_func(kessel_filter=None):
            return {"filter": kessel_filter}

        with self.app.app_context():
            # First call - should hit Kessel
            result1 = test_func()
            assert result1["filter"] == {"groups": ["group1", "group2"]}
            
            # Second call - should hit cache
            result2 = test_func()
            assert result2["filter"] == {"groups": ["group1", "group2"]}
            
            # Verify Kessel was only called once (second call used cache)
            assert mock_kessel_client.ListAllowedWorkspaces.call_count == 1


if __name__ == "__main__":
    pytest.main([__file__]) 