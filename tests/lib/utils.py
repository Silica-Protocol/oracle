"""Test utilities for Oracle E2E tests."""

from __future__ import annotations

import os
import socket
import asyncio
from pathlib import Path
from typing import List


def project_root() -> Path:
    """Return the oracle project root directory."""
    return Path(__file__).resolve().parents[2]


def ensure_clean_directory(path: Path) -> None:
    """Remove and recreate a directory for test isolation."""
    assert path is not None, "Path must not be None"
    if path.exists():
        import shutil
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)
    assert path.exists(), f"Directory must exist after creation: {path}"
    assert path.is_dir(), f"Path must be a directory: {path}"


def allocate_ports(count: int, starting_port: int = 18000) -> List[int]:
    """Allocate a sequence of available ports for test services."""
    assert count > 0, "Port count must be positive"
    assert starting_port > 1024, "Port must be non-privileged"
    
    ports: List[int] = []
    current = starting_port
    
    while len(ports) < count:
        if current > 65535:
            raise RuntimeError("Exhausted port range")
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", current))
                ports.append(current)
        except OSError:
            pass  # Port in use, try next
        
        current += 1
    
    assert len(ports) == count, "Must allocate requested number of ports"
    assert all(1024 < p <= 65535 for p in ports), "All ports must be in valid range"
    return ports


async def wait_for_port(port: int, host: str = "127.0.0.1", timeout: float = 30.0) -> bool:
    """Wait for a port to become available."""
    assert port > 0, "Port must be positive"
    assert timeout > 0, "Timeout must be positive"
    
    deadline = asyncio.get_event_loop().time() + timeout
    
    while asyncio.get_event_loop().time() < deadline:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=1.0
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (OSError, asyncio.TimeoutError):
            await asyncio.sleep(0.1)
    
    return False


def resolve_binary_path() -> Path:
    """Resolve the oracle binary path."""
    root = project_root()
    
    # Try release build first
    release_path = root / "target" / "release" / "silica-oracle"
    if release_path.exists():
        return release_path
    
    # Try debug build
    debug_path = root / "target" / "debug" / "silica-oracle"
    if debug_path.exists():
        return debug_path
    
    raise FileNotFoundError(
        f"Oracle binary not found. Build with: cargo build --release --bin silica-oracle"
    )


def resolve_tigerbeetle_binary() -> Path:
    """Resolve TigerBeetle binary path."""
    # Check environment override
    env_path = os.environ.get("TIGERBEETLE_PATH")
    if env_path:
        path = Path(env_path)
        if path.exists():
            return path
    
    # Try common locations
    candidates = [
        Path.home() / ".tigerbeetle" / "tigerbeetle",
        Path("/usr/local/bin/tigerbeetle"),
        Path("/opt/tigerbeetle/tigerbeetle"),
    ]
    
    for candidate in candidates:
        if candidate.exists():
            return candidate
    
    raise FileNotFoundError(
        "TigerBeetle binary not found. Install from https://docs.tigerbeetle.com/ "
        "or set TIGERBEETLE_PATH environment variable."
    )


def resolve_silica_binary() -> Path:
    """Resolve Silica protocol binary path."""
    root = project_root().parent / "protocol"
    
    release_path = root / "target" / "release" / "silica"
    if release_path.exists():
        return release_path
    
    debug_path = root / "target" / "debug" / "silica"
    if debug_path.exists():
        return debug_path
    
    raise FileNotFoundError(
        f"Silica binary not found. Build with: cargo build --release --bin silica"
    )
