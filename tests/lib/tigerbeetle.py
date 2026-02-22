"""TigerBeetle cluster management for E2E tests."""

from __future__ import annotations

import asyncio
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, TextIO

from .utils import (
    ensure_clean_directory,
    wait_for_port,
    resolve_tigerbeetle_binary,
    allocate_ports,
)


@dataclass
class TigerBeetleNode:
    """Single TigerBeetle node configuration and handle."""
    
    node_id: int
    port: int
    data_dir: Path
    address: str = "127.0.0.1"
    cluster_id: int = 0
    process: Optional[subprocess.Popen] = field(default=None, init=False)
    _log_file: Optional[TextIO] = field(default=None, init=False, repr=False)
    
    @property
    def replica_address(self) -> str:
        return f"{self.address}:{self.port}"
    
    async def start(self, binary_path: Path, replica_addresses: List[str]) -> None:
        """Start the TigerBeetle replica."""
        assert self.process is None, "Node already running"
        assert binary_path.exists(), f"Binary not found: {binary_path}"
        
        # Format addresses for TigerBeetle
        addresses_arg = ",".join(replica_addresses)
        
        # Start TigerBeetle
        log_path = self.data_dir / f"tigerbeetle_{self.node_id}.log"
        self._log_file = open(log_path, "w", encoding="utf-8")
        
        command = [
            str(binary_path),
            "start",
            f"--addresses={addresses_arg}",
            f"--cache-grid=512MiB",
            f"--cluster={self.cluster_id}",
            f"--replica={self.node_id}",
        ]
        
        env = os.environ.copy()
        env["TB_ADDRESS"] = self.replica_address
        
        self.process = subprocess.Popen(
            command,
            cwd=self.data_dir,
            stdout=self._log_file,
            stderr=subprocess.STDOUT,
            env=env,
        )
        
        assert self.process is not None, "Process must be assigned"
        assert self.process.poll() is None, "Process should be running"
        
        # Wait for port to be available
        ready = await wait_for_port(self.port, timeout=30.0)
        assert ready, f"TigerBeetle node {self.node_id} failed to start on port {self.port}"
    
    async def stop(self) -> None:
        """Stop the TigerBeetle replica."""
        if self.process is None:
            return
        
        self.process.terminate()
        try:
            await asyncio.to_thread(self.process.wait, 5)
        except Exception:
            self.process.kill()
            await asyncio.to_thread(self.process.wait, 5)
        finally:
            self.process = None
            if self._log_file:
                self._log_file.close()
                self._log_file = None
        
        assert self.process is None, "Process must be cleared"


class TigerBeetleCluster:
    """Manages a local TigerBeetle cluster for E2E tests."""
    
    def __init__(
        self,
        base_dir: Path,
        node_count: int = 1,
        cluster_id: int = 0,
        *,
        starting_port: int = 3000,
        binary_path: Optional[Path] = None,
    ) -> None:
        assert node_count >= 1, "Need at least 1 TigerBeetle node"
        assert node_count <= 5, "Maximum 5 nodes supported"
        
        self.base_dir = base_dir
        self.node_count = node_count
        self.cluster_id = cluster_id
        self.starting_port = starting_port
        self._binary_path = binary_path or resolve_tigerbeetle_binary()
        self.nodes: List[TigerBeetleNode] = []
    
    async def setup(self) -> None:
        """Create data directories and format storage."""
        ensure_clean_directory(self.base_dir)
        
        ports = allocate_ports(self.node_count, self.starting_port)
        
        for i in range(self.node_count):
            node_dir = self.base_dir / f"replica_{i}"
            node_dir.mkdir(parents=True, exist_ok=True)
            
            node = TigerBeetleNode(
                node_id=i,
                port=ports[i],
                data_dir=node_dir,
                cluster_id=self.cluster_id,
            )
            self.nodes.append(node)
        
        assert len(self.nodes) == self.node_count, "Node count mismatch"
    
    async def format(self) -> None:
        """Format TigerBeetle storage for all nodes."""
        replica_addresses = [n.replica_address for n in self.nodes]
        addresses_arg = ",".join(replica_addresses)
        
        for node in self.nodes:
            command = [
                str(self._binary_path),
                "format",
                f"--cluster={self.cluster_id}",
                f"--replica={node.node_id}",
                f"--addresses={addresses_arg}",
            ]
            
            result = await asyncio.to_thread(
                subprocess.run,
                command,
                cwd=node.data_dir,
                capture_output=True,
                text=True,
                check=False,
            )
            
            if result.returncode != 0:
                raise RuntimeError(
                    f"TigerBeetle format failed for replica {node.node_id}: {result.stderr}"
                )
    
    async def start(self) -> None:
        """Start all TigerBeetle replicas."""
        assert self.nodes, "Must call setup() first"
        
        replica_addresses = [n.replica_address for n in self.nodes]
        
        await asyncio.gather(
            *(node.start(self._binary_path, replica_addresses) for node in self.nodes)
        )
        
        assert all(n.process is not None for n in self.nodes), "All nodes must be running"
    
    async def stop(self) -> None:
        """Stop all TigerBeetle replicas."""
        await asyncio.gather(*(node.stop() for node in self.nodes))
        assert all(n.process is None for n in self.nodes), "All nodes must be stopped"
    
    @property
    def addresses(self) -> List[str]:
        """Return list of replica addresses."""
        return [n.replica_address for n in self.nodes]
    
    @property
    def connection_string(self) -> str:
        """Return connection string for TigerBeetle client."""
        return ",".join(self.addresses)
    
    async def __aenter__(self) -> "TigerBeetleCluster":
        await self.setup()
        await self.format()
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.stop()
