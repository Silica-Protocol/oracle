"""Anti-Gaming E2E tests.

Tests for:
- Task obfuscation
- Result replay detection
- Reputation slashing
- Reward locking
"""

from __future__ import annotations

import pytest

# Add oracle to path
import sys
from pathlib import Path
oracle_root = Path(__file__).resolve().parents[2]
if str(oracle_root) not in sys.path:
    sys.path.insert(0, str(oracle_root))

from tests.lib.client import OracleClient


@pytest.mark.asyncio
@pytest.mark.e2e
@pytest.mark.antigaming
async def test_reputation_initial_score(standalone_client: OracleClient) -> None:
    """Test that new users start with score 0."""
    rep = await standalone_client.get_reputation("user_test_initial")
    
    assert rep["effective_score"] == 0
    assert rep["eligibility"] == "FullAccess"


@pytest.mark.asyncio
@pytest.mark.e2e
@pytest.mark.antigaming
async def test_eligibility_status_full_access(standalone_client: OracleClient) -> None:
    """Test that users with score >= 0 have full access."""
    rep = await standalone_client.get_reputation("user_full_access")
    
    # New user should have full access
    assert rep["effective_score"] >= 0
    # Eligibility should be FullAccess (check the structure)
    eligibility = rep.get("eligibility", {})
    if isinstance(eligibility, dict):
        assert eligibility.get("status") == "FullAccess" or eligibility.get("eligibility") == "FullAccess"
    else:
        assert eligibility == "FullAccess"


@pytest.mark.asyncio
@pytest.mark.e2e
@pytest.mark.antigaming
async def test_reputation_project_metrics_initial(
    standalone_client: OracleClient,
) -> None:
    """Test that project metrics start empty for new users."""
    rep = await standalone_client.get_reputation("user_metrics_test")
    
    # Should have empty project metrics initially
    metrics = rep.get("project_metrics", [])
    assert isinstance(metrics, list)
    # New user has no project metrics yet
    assert len(metrics) == 0


@pytest.mark.asyncio
@pytest.mark.e2e
@pytest.mark.antigaming
async def test_thresholds_governance_values(standalone_client: OracleClient) -> None:
    """Test that governance thresholds are correctly configured."""
    thresholds = await standalone_client.get_thresholds()
    
    # Verify expected defaults
    assert thresholds["good_behavior_reward"] == 1
    assert thresholds["restricted_threshold"] == -50
    assert thresholds["temp_ban_threshold"] == -100
    assert thresholds["temp_ban_days"] == 30
    assert thresholds["perm_ban_threshold"] == -200
    assert thresholds["slash_decay_days"] == 90


@pytest.mark.asyncio
@pytest.mark.e2e
@pytest.mark.antigaming
async def test_pending_reviews_structure(standalone_client: OracleClient) -> None:
    """Test the structure of pending reviews response."""
    reviews = await standalone_client.get_pending_reviews()
    
    assert "total" in reviews
    assert "activities" in reviews
    assert isinstance(reviews["total"], int)
    assert isinstance(reviews["activities"], list)


@pytest.mark.asyncio
@pytest.mark.e2e
@pytest.mark.antigaming
async def test_slash_history_structure(standalone_client: OracleClient) -> None:
    """Test the structure of slash history response."""
    history = await standalone_client.get_slash_history("user_slash_test")
    
    assert "user_id" in history
    assert "total_slashes" in history
    assert "active_slashes" in history
    assert "total_points_deducted" in history
    assert "events" in history
    
    assert history["user_id"] == "user_slash_test"
    assert isinstance(history["events"], list)


@pytest.mark.asyncio
@pytest.mark.e2e
@pytest.mark.antigaming
async def test_user_results_structure(standalone_client: OracleClient) -> None:
    """Test the structure of user results response."""
    results = await standalone_client.get_user_results("user_results_test")
    
    assert "user_id" in results
    assert "total_results" in results
    assert "pending" in results
    assert "validated" in results
    assert "rejected" in results
    assert "results" in results
    
    assert results["user_id"] == "user_results_test"
    assert isinstance(results["results"], list)


@pytest.mark.asyncio
@pytest.mark.e2e
@pytest.mark.antigaming
async def test_stats_structure(standalone_client: OracleClient) -> None:
    """Test the structure of stats response."""
    stats = await standalone_client.get_stats()
    
    assert "total_users" in stats
    assert "total_results_tracked" in stats
    assert "pending_validations" in stats
    assert "pending_reviews" in stats
    
    # All should be non-negative integers
    assert stats["total_users"] >= 0
    assert stats["pending_validations"] >= 0
    assert stats["pending_reviews"] >= 0


@pytest.mark.asyncio
@pytest.mark.e2e
@pytest.mark.antigaming
async def test_multiple_users_independent_scores(
    standalone_client: OracleClient,
) -> None:
    """Test that multiple users have independent reputation scores."""
    rep1 = await standalone_client.get_reputation("user_independent_1")
    rep2 = await standalone_client.get_reputation("user_independent_2")
    
    # Both should start at 0
    assert rep1["effective_score"] == 0
    assert rep2["effective_score"] == 0
    
    # Should be different user records
    assert rep1["user_id"] != rep2["user_id"]


@pytest.mark.asyncio
@pytest.mark.e2e
@pytest.mark.antigaming
async def test_reputation_update_via_governance(
    standalone_client: OracleClient,
) -> None:
    """Test updating reputation thresholds via governance."""
    # Get current thresholds
    original = await standalone_client.get_thresholds()
    original_reward = original["good_behavior_reward"]
    
    # Update threshold
    new_value = original_reward + 1
    updated = await standalone_client.update_thresholds(
        {"good_behavior_reward": new_value},
        admin_api_key="testadminkey12345678901234567890",
    )
    
    assert updated["good_behavior_reward"] == new_value
    
    # Verify persistence
    current = await standalone_client.get_thresholds()
    assert current["good_behavior_reward"] == new_value
    
    # Reset for other tests
    await standalone_client.update_thresholds(
        {"good_behavior_reward": original_reward},
        admin_api_key="testadminkey12345678901234567890",
    )
