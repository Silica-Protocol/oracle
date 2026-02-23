"""Standalone Oracle tests that don't require TigerBeetle."""

from __future__ import annotations

import pytest

# Add oracle to path
import sys
from pathlib import Path
oracle_root = Path(__file__).resolve().parents[2]
if str(oracle_root) not in sys.path:
    sys.path.insert(0, str(oracle_root))

from tests.lib.client import OracleClient


class TestStandaloneOracle:
    """Tests for Oracle without TigerBeetle."""
    
    @pytest.mark.asyncio
    @pytest.mark.e2e
    async def test_health(self, standalone_client: OracleClient):
        """Test health endpoint."""
        healthy = await standalone_client.health()
        assert healthy is True
    
    @pytest.mark.asyncio
    @pytest.mark.e2e
    async def test_reputation_new_user(self, standalone_client: OracleClient):
        """Test getting reputation for new user."""
        rep = await standalone_client.get_reputation("test_user_new")
        
        assert rep["user_id"] == "test_user_new"
        assert rep["effective_score"] == 0
        assert rep["successful_submissions"] == 0
    
    @pytest.mark.asyncio
    @pytest.mark.e2e
    async def test_thresholds(self, standalone_client: OracleClient):
        """Test getting thresholds."""
        thresholds = await standalone_client.get_thresholds()
        
        assert thresholds["good_behavior_reward"] == 1
        assert thresholds["restricted_threshold"] == -50
        assert thresholds["temp_ban_threshold"] == -100
        assert thresholds["perm_ban_threshold"] == -200
        assert thresholds["slash_decay_days"] == 90
    
    @pytest.mark.asyncio
    @pytest.mark.e2e
    async def test_stats(self, standalone_client: OracleClient):
        """Test getting stats."""
        stats = await standalone_client.get_stats()
        
        assert "pending_validations" in stats
        assert "pending_reviews" in stats
    
    @pytest.mark.asyncio
    @pytest.mark.e2e
    async def test_pending_reviews_empty(self, standalone_client: OracleClient):
        """Test pending reviews is empty."""
        reviews = await standalone_client.get_pending_reviews()
        
        assert reviews["total"] == 0
        assert reviews["activities"] == []
    
    @pytest.mark.asyncio
    @pytest.mark.e2e
    async def test_slash_history_empty(self, standalone_client: OracleClient):
        """Test slash history for new user."""
        history = await standalone_client.get_slash_history("new_user")
        
        assert history["total_slashes"] == 0
        assert history["events"] == []
    
    @pytest.mark.asyncio
    @pytest.mark.e2e
    async def test_update_thresholds_wrong_key(self, standalone_client: OracleClient):
        """Test that wrong admin key is rejected."""
        with pytest.raises(Exception):
            await standalone_client.update_thresholds(
                {"good_behavior_reward": 5},
                admin_api_key="wrongkey123456789012345678901234567890",
            )
    
    @pytest.mark.asyncio
    @pytest.mark.e2e
    async def test_update_thresholds_valid_key(self, standalone_client: OracleClient):
        """Test updating thresholds with valid key."""
        result = await standalone_client.update_thresholds(
            {"good_behavior_reward": 2},
            admin_api_key="testadminkey12345678901234567890",
        )
        
        assert result["good_behavior_reward"] == 2
        
        # Verify
        thresholds = await standalone_client.get_thresholds()
        assert thresholds["good_behavior_reward"] == 2
