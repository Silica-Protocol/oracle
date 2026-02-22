"""Pytest configuration and fixtures for Oracle E2E tests."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import AsyncGenerator

import pytest

from tests.lib import utils as test_utils
from tests.lib.cluster import OracleCluster
from tests.lib.client import OracleClient
from tests.lib.tigerbeetle import TigerBeetleCluster

logger = logging.getLogger(__name__)


def pytest_configure(config: pytest.Config) -> None:
    """Verify binary availability before running tests."""
    if config.option.collectonly or config.option.help:
        return
    
    try:
        binary_path = test_utils.resolve_binary_path()
        logger.info("Using Oracle binary: %s", binary_path)
    except FileNotFoundError as exc:
        pytest.exit(str(exc), returncode=1)


@pytest.fixture
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def tigerbeetle(tmp_path: Path) -> AsyncGenerator[TigerBeetleCluster, None]:
    """Provide a single-node TigerBeetle cluster."""
    cluster = TigerBeetleCluster(
        base_dir=tmp_path / "tigerbeetle",
        node_count=1,
        cluster_id=0,
        starting_port=3000,
    )
    
    async with cluster as tb:
        assert len(tb.nodes) == 1
        yield tb


@pytest.fixture
async def oracle(
    tmp_path: Path,
    tigerbeetle: TigerBeetleCluster,
) -> AsyncGenerator[OracleCluster, None]:
    """Provide a single-node Oracle cluster connected to TigerBeetle."""
    cluster = OracleCluster(
        base_dir=tmp_path / "oracle",
        node_count=1,
        tigerbeetle=tigerbeetle,
        starting_api_port=8765,
    )
    
    async with cluster as oc:
        assert len(oc.nodes) == 1
        yield oc


@pytest.fixture
async def oracle_client(oracle: OracleCluster) -> AsyncGenerator[OracleClient, None]:
    """Provide an Oracle API client."""
    client = oracle.get_client(0)
    async with client:
        assert await client.health(), "Oracle must be healthy"
        yield client
