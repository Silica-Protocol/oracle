"""Basic Oracle E2E tests."""

from __future__ import annotations

import pytest

from tests.lib.cluster import OracleCluster
from tests.lib.client import OracleClient
from tests.lib.tigerbeetle import TigerBeetleCluster


@pytest.mark.asyncio
@pytest.mark.e2e
async def test_oracle_startup(oracle: OracleCluster) -> None:
    """Test that Oracle starts and reports healthy."""
    assert len(oracle.nodes) == 1
    
    node = oracle.nodes[0]
    assert node.process is not None
    assert node.process.poll() is None  # Process is running
    
    healthy = await node.is_healthy()
    assert healthy is True


@pytest.mark.asyncio
@pytest.mark.e2e
async def test_oracle_health_endpoint(oracle_client: OracleClient) -> None:
    """Test the health endpoint returns OK."""
    healthy = await oracle_client.health()
    assert healthy is True


@pytest.mark.asyncio
@pytest.mark.e2e
async def test_reputation_get_new_user(oracle_client: OracleClient) -> None:
    """Test getting reputation for a new user."""
    rep = await oracle_client.get_reputation("new_user_123")
    
    assert rep["user_id"] == "new_user_123"
    assert rep["effective_score"] == 0
    assert rep["successful_submissions"] == 0
    assert rep["total_credits_earned"] == 0.0
    assert rep["pending_slashes"] == 0


@pytest.mark.asyncio
@pytest.mark.e2e
async def test_reputation_thresholds(oracle_client: OracleClient) -> None:
    """Test getting reputation thresholds."""
    thresholds = await oracle_client.get_thresholds()
    
    assert thresholds["good_behavior_reward"] == 1
    assert thresholds["restricted_threshold"] == -50
    assert thresholds["temp_ban_threshold"] == -100
    assert thresholds["temp_ban_days"] == 30
    assert thresholds["perm_ban_threshold"] == -200
    assert thresholds["slash_decay_days"] == 90


@pytest.mark.asyncio
@pytest.mark.e2e
async def test_reputation_stats(oracle_client: OracleClient) -> None:
    """Test getting reputation stats."""
    stats = await oracle_client.get_stats()
    
    assert "total_users" in stats
    assert "pending_validations" in stats
    assert "pending_reviews" in stats


@pytest.mark.asyncio
@pytest.mark.e2e
async def test_pending_reviews_empty(oracle_client: OracleClient) -> None:
    """Test that pending reviews starts empty."""
    reviews = await oracle_client.get_pending_reviews()
    
    assert reviews["total"] == 0
    assert reviews["activities"] == []


@pytest.mark.asyncio
@pytest.mark.e2e
async def test_user_slash_history_empty(oracle_client: OracleClient) -> None:
    """Test that a new user has no slash history."""
    history = await oracle_client.get_slash_history("new_user_456")
    
    assert history["user_id"] == "new_user_456"
    assert history["total_slashes"] == 0
    assert history["active_slashes"] == 0
    assert history["total_points_deducted"] == 0
    assert history["events"] == []


@pytest.mark.asyncio
@pytest.mark.e2e
async def test_user_results_empty(oracle_client: OracleClient) -> None:
    """Test that a new user has no results."""
    results = await oracle_client.get_user_results("new_user_789")
    
    assert results["user_id"] == "new_user_789"
    assert results["total_results"] == 0
    assert results["pending"] == 0
    assert results["validated"] == 0
    assert results["rejected"] == 0


@pytest.mark.asyncio
@pytest.mark.e2e
async def test_tigerbeetle_connection(
    tigerbeetle: TigerBeetleCluster,
    oracle: OracleCluster,
) -> None:
    """Test that Oracle can connect to TigerBeetle."""
    # TigerBeetle should be running
    assert len(tigerbeetle.nodes) == 1
    tb_node = tigerbeetle.nodes[0]
    assert tb_node.process is not None
    
    # Oracle should be healthy with TB connection
    oracle_node = oracle.nodes[0]
    healthy = await oracle_node.is_healthy()
    assert healthy is True


@pytest.mark.asyncio
@pytest.mark.e2e
async def test_update_thresholds_requires_admin_key(
    oracle_client: OracleClient,
) -> None:
    """Test that updating thresholds requires valid admin key."""
    with pytest.raises(Exception):  # Should raise 403
        await oracle_client.update_thresholds(
            {"good_behavior_reward": 5},
            admin_api_key="wrong_key",
        )


@pytest.mark.asyncio
@pytest.mark.e2e
async def test_update_thresholds_with_valid_key(
    oracle_client: OracleClient,
) -> None:
    """Test updating thresholds with valid admin key."""
    # Update a threshold
    result = await oracle_client.update_thresholds(
        {"good_behavior_reward": 2},
        admin_api_key="test_admin_key_456",
    )
    
    # Should reflect new value
    assert result["good_behavior_reward"] == 2
    
    # Verify via GET
    thresholds = await oracle_client.get_thresholds()
    assert thresholds["good_behavior_reward"] == 2
