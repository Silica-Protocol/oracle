"""Pytest configuration and fixtures for Oracle E2E tests."""

from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import AsyncGenerator, Optional

import pytest

# Add oracle directory to path for imports
oracle_root = Path(__file__).resolve().parents[1]
oracle_tests = oracle_root / "tests"
if str(oracle_root) not in sys.path:
    sys.path.insert(0, str(oracle_root))
if str(oracle_tests) not in sys.path:
    sys.path.insert(0, str(oracle_tests))

from tests.lib import utils as test_utils
from tests.lib.cluster import OracleCluster
from tests.lib.client import OracleClient
from tests.lib.tigerbeetle import TigerBeetleCluster
from tests.lib.utils import wait_for_port, allocate_ports

logger = logging.getLogger(__name__)

# Detect if running in Docker
IN_DOCKER = os.path.exists("/.dockerenv") or os.environ.get("DOCKER_CONTAINER") == "true"

# Service addresses (Docker vs local)
TIGERBEETLE_HOST = os.environ.get("TIGERBEETLE_HOST", "tigerbeetle" if IN_DOCKER else "127.0.0.1")
TIGERBEETLE_PORT = int(os.environ.get("TIGERBEETLE_PORT", "3000"))
POSTGRES_HOST = os.environ.get("POSTGRES_HOST", "postgres" if IN_DOCKER else "127.0.0.1")
POSTGRES_PORT = int(os.environ.get("POSTGRES_PORT", "5432"))


def pytest_configure(config: pytest.Config) -> None:
    """Verify binary availability before running tests."""
    if config.option.collectonly or config.option.help:
        return
    
    try:
        binary_path = test_utils.resolve_binary_path()
        logger.info("Using Oracle binary: %s", binary_path)
    except FileNotFoundError as exc:
        pytest.exit(str(exc), returncode=1)


def pytest_addoption(parser: pytest.PytestParser):
    """Add custom command line options."""
    parser.addoption(
        "--skip-tigerbeetle",
        action="store_true",
        default=False,
        help="Skip tests that require TigerBeetle",
    )
    parser.addoption(
        "--tigerbeetle-path",
        action="store",
        default=None,
        help="Path to TigerBeetle binary",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list):
    """Skip TigerBeetle tests if --skip-tigerbeetle is set."""
    if config.getoption("--skip-tigerbeetle"):
        skip_tb = pytest.mark.skip(reason="TigerBeetle tests skipped via --skip-tigerbeetle")
        for item in items:
            if "tigerbeetle" in item.keywords or "requirestb" in item.keywords:
                item.add_marker(skip_tb)


@pytest.fixture
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def tigerbeetle_path(request) -> Optional[Path]:
    """Get TigerBeetle binary path if available."""
    path = request.config.getoption("--tigerbeetle-path")
    if path:
        return Path(path)
    
    # Try environment variable
    env_path = os.environ.get("TIGERBEETLE_PATH")
    if env_path:
        return Path(env_path)
    
    # Try to resolve
    try:
        return test_utils.resolve_tigerbeetle_binary()
    except FileNotFoundError:
        return None


@pytest.fixture
async def tigerbeetle(
    tmp_path: Path,
    tigerbeetle_path: Optional[Path],
    request: pytest.FixtureRequest,
) -> AsyncGenerator[Optional[TigerBeetleCluster], None]:
    """Provide a single-node TigerBeetle cluster.
    
    In Docker mode, connects to the existing TigerBeetle container.
    In local mode, starts a local TigerBeetle instance.
    """
    # In Docker, connect to existing container
    if IN_DOCKER:
        logger.info(f"Running in Docker, connecting to TigerBeetle at {TIGERBEETLE_HOST}:{TIGERBEETLE_PORT}")
        
        # Wait for TigerBeetle to be ready
        ready = await wait_for_port(TIGERBEETLE_PORT, host=TIGERBEETLE_HOST, timeout=30.0)
        if not ready:
            pytest.fail(f"TigerBeetle not available at {TIGERBEETLE_HOST}:{TIGERBEETLE_PORT}")
        
        # Return a minimal cluster-like object for compatibility
        class DockerTigerBeetleCluster:
            def __init__(self, host: str, port: int):
                self.addresses = [f"{host}:{port}"]
                self.cluster_id = 0
                self.nodes = []
                self.connection_string = f"{host}:{port}"
        
        yield DockerTigerBeetleCluster(TIGERBEETLE_HOST, TIGERBEETLE_PORT)
        return
    
    # Local mode - start TigerBeetle if available
    if tigerbeetle_path is None:
        if request.config.getoption("--skip-tigerbeetle"):
            pytest.skip("TigerBeetle binary not available")
            yield None
            return
        else:
            pytest.fail(
                "TigerBeetle binary not found. "
                "Install from https://docs.tigerbeetle.com/ or use --skip-tigerbeetle"
            )
    
    cluster = TigerBeetleCluster(
        base_dir=tmp_path / "tigerbeetle",
        node_count=1,
        cluster_id=0,
        starting_port=TIGERBEETLE_PORT,
        binary_path=tigerbeetle_path,
    )
    
    async with cluster as tb:
        assert len(tb.nodes) == 1
        yield tb


@pytest.fixture
async def oracle(
    tmp_path: Path,
    tigerbeetle: Optional[TigerBeetleCluster],
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


# Standalone Oracle fixtures (no TigerBeetle required)

@pytest.fixture
async def standalone_oracle(tmp_path: Path) -> AsyncGenerator[dict, None]:
    """Start Oracle without TigerBeetle for basic API tests."""
    binary = test_utils.resolve_binary_path()
    api_port = allocate_ports(1, 8800)[0]
    data_dir = tmp_path / "oracle"
    data_dir.mkdir(parents=True, exist_ok=True)
    
    log_path = data_dir / "oracle.log"
    log_file = open(log_path, "w")
    
    env = os.environ.copy()
    env["CHERT_POI_PORT"] = str(api_port)
    env["CHERT_POSTGRES_ENABLED"] = "false"
    env["CHERT_TIGERBEETLE_ADDRESSES"] = ""
    env["CHERT_OBFUSCATION_SECRET"] = "test_secret_key"
    env["CHERT_ADMIN_API_KEY"] = "testadminkey12345678901234567890"
    env["CHERT_ORACLE_API_KEY"] = "testoracleapikey12345678901234567890"
    env["CHERT_API_KEYS"] = "testapikey123456789012345678901234567890"
    env["RUST_LOG"] = "info"
    # Add test BOINC authenticator (min 16 chars, alphanumeric only)
    env["CHERT_BOINC_MILKYWAY_AUTHENTICATOR"] = "testauthfore2etests12345"
    
    process = subprocess.Popen(
        [str(binary)],
        cwd=data_dir,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        env=env,
    )
    
    # Wait for startup
    ready = await wait_for_port(api_port, timeout=30.0)
    if not ready:
        process.kill()
        log_file.close()
        pytest.fail("Oracle failed to start")
    
    yield {
        "process": process,
        "port": api_port,
        "url": f"http://127.0.0.1:{api_port}",
        "log_path": log_path,
    }
    
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    finally:
        log_file.close()


@pytest.fixture
async def standalone_client(standalone_oracle: dict) -> AsyncGenerator[OracleClient, None]:
    """Client for standalone Oracle."""
    client = OracleClient(
        standalone_oracle["url"],
        token="testapikey123456789012345678901234567890",
    )
    async with client:
        yield client
