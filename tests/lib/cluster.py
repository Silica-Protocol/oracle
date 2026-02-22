"""Oracle cluster management for E2E tests."""

from __future__ import annotations

import asyncio
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, TextIO

from .client import OracleClient
from .tigerbeetle import TigerBeetleCluster
from .utils import (
    allocate_ports,
    ensure_clean_directory,
    project_root,
    resolve_binary_path,
    wait_for_port,
)

_HEALTH_TIMEOUT = 30.0


@dataclass
class OracleNodeConfig:
    """Configuration for a single Oracle node."""
    
    node_id: int
    api_port: int
    data_dir: Path
    log_dir: Optional[Path] = None
    
    @property
    def api_url(self) -> str:
        return f"http://127.0.0.1:{self.api_port}"
    
    @property
    def log_path(self) -> Path:
        base = self.log_dir or (self.data_dir / "logs")
        return base / "oracle.log"


@dataclass
class OracleNode:
    """Running Oracle node handle."""
    
    config: OracleNodeConfig
    binary_path: Path
    environment: Dict[str, str]
    tigerbeetle_addresses: str
    tigerbeetle_cluster_id: int
    process: Optional[subprocess.Popen] = field(default=None, init=False)
    _log_file: Optional[TextIO] = field(default=None, init=False, repr=False)
    
    async def start(self) -> None:
        """Start the Oracle node."""
        assert self.process is None, "Node already running"
        assert self.binary_path.exists(), f"Binary not found: {self.binary_path}"
        
        self.config.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log_file = open(self.config.log_path, "w", encoding="utf-8")
        
        env = self.environment.copy()
        env["CHERT_TIGERBEETLE_ADDRESSES"] = self.tigerbeetle_addresses
        env["CHERT_TIGERBEETLE_CLUSTER_ID"] = str(self.tigerbeetle_cluster_id)
        env["CHERT_POI_PORT"] = str(self.config.api_port)
        env["CHERT_POSTGRES_ENABLED"] = "false"  # Use in-memory for tests
        env["CHERT_OBFUSCATION_SECRET"] = "test_obfuscation_secret_123"
        env["CHERT_ADMIN_API_KEY"] = "test_admin_key_456"
        env["CHERT_LOG_LEVEL"] = "debug"
        
        command = [str(self.binary_path)]
        
        self.process = subprocess.Popen(
            command,
            cwd=self.config.data_dir,
            stdout=self._log_file,
            stderr=subprocess.STDOUT,
            env=env,
        )
        
        assert self.process is not None, "Process must be assigned"
        
        # Wait for health endpoint
        ready = await wait_for_port(self.config.api_port, timeout=_HEALTH_TIMEOUT)
        if not ready:
            self.stop()
            raise RuntimeError(
                f"Oracle node {self.config.node_id} failed to start on port {self.config.api_port}"
            )
    
    def stop(self) -> None:
        """Stop the Oracle node."""
        if self.process is None:
            return
        
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        finally:
            self.process = None
            if self._log_file:
                self._log_file.close()
                self._log_file = None
    
    async def is_healthy(self) -> bool:
        """Check if node is healthy."""
        try:
            async with OracleClient(self.config.api_url) as client:
                return await client.health()
        except Exception:
            return False
    
    def get_client(self) -> OracleClient:
        """Get API client for this node."""
        return OracleClient(self.config.api_url)


class OracleCluster:
    """Manages Oracle nodes for E2E tests."""
    
    def __init__(
        self,
        base_dir: Path,
        node_count: int = 1,
        tigerbeetle: Optional[TigerBeetleCluster] = None,
        *,
        starting_api_port: int = 8765,
        binary_path: Optional[Path] = None,
    ):
        assert node_count >= 1, "Need at least 1 node"
        
        self.base_dir = base_dir
        self.node_count = node_count
        self.tigerbeetle = tigerbeetle
        self._binary_path = binary_path or resolve_binary_path()
        self._starting_api_port = starting_api_port
        self.nodes: List[OracleNode] = []
    
    async def setup(self) -> None:
        """Create data directories and configuration."""
        ensure_clean_directory(self.base_dir)
        
        api_ports = allocate_ports(self.node_count, self._starting_api_port)
        
        for i in range(self.node_count):
            node_dir = self.base_dir / f"node-{i}"
            node_dir.mkdir(parents=True, exist_ok=True)
            
            log_dir = node_dir / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)
            
            config = OracleNodeConfig(
                node_id=i,
                api_port=api_ports[i],
                data_dir=node_dir,
                log_dir=log_dir,
            )
            
            tigerbeetle_addresses = ""
            tigerbeetle_cluster_id = 0
            if self.tigerbeetle:
                tigerbeetle_addresses = self.tigerbeetle.connection_string
                tigerbeetle_cluster_id = self.tigerbeetle.cluster_id
            
            node = OracleNode(
                config=config,
                binary_path=self._binary_path,
                environment=self._build_environment(i),
                tigerbeetle_addresses=tigerbeetle_addresses,
                tigerbeetle_cluster_id=tigerbeetle_cluster_id,
            )
            self.nodes.append(node)
        
        assert len(self.nodes) == self.node_count
    
    def _build_environment(self, node_id: int) -> Dict[str, str]:
        """Build environment variables for a node."""
        env = os.environ.copy()
        env["RUST_LOG"] = os.getenv("RUST_LOG", "silica_oracle=debug,info")
        env["SILICA_NODE_ID"] = str(node_id)
        return env
    
    async def start_all(self) -> None:
        """Start all Oracle nodes."""
        assert self.nodes, "Must call setup() first"
        
        await asyncio.gather(*(node.start() for node in self.nodes))
        
        # Verify all healthy
        for node in self.nodes:
            healthy = await node.is_healthy()
            if not healthy:
                raise RuntimeError(f"Node {node.config.node_id} not healthy after start")
    
    async def stop_all(self) -> None:
        """Stop all Oracle nodes."""
        for node in self.nodes:
            node.stop()
    
    def get_client(self, index: int = 0) -> OracleClient:
        """Get API client for a node."""
        assert 0 <= index < len(self.nodes), f"Invalid node index: {index}"
        return self.nodes[index].get_client()
    
    async def __aenter__(self) -> "OracleCluster":
        await self.setup()
        await self.start_all()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.stop_all()
