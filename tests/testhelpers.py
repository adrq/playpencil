# Derived from https://github.com/adrq/agentbeacon/blob/main/tests/testhelpers.py (AGPL-3.0-or-later)
"""Common utilities for test process and file cleanup.

These helpers centralize robust termination of subprocesses and cleanup of
temporary files to reduce duplication and flakiness across tests.
"""

from __future__ import annotations

import os
import socket
import subprocess
import threading
import time
from contextlib import contextmanager
from typing import Any, Dict, Iterable, List, Set

import httpx
import psutil


class PortManager:
    """Thread-safe port allocation manager for test isolation.

    Uses OS-assigned ephemeral ports (bind to port 0) to eliminate
    cross-process TOCTOU races that occur when scanning a fixed range.
    The OS picks from ~28K ephemeral ports, making collisions near-impossible.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._allocated: Set[int] = set()

    def allocate_port(self) -> int:
        """Allocate a free port using OS ephemeral assignment."""
        with self._lock:
            for _ in range(10):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
                sock.close()
                if port not in self._allocated:
                    self._allocated.add(port)
                    return port
            raise RuntimeError("Failed to allocate unique port after 10 attempts")

    def release_port(self, port: int) -> None:
        with self._lock:
            self._allocated.discard(port)

    @contextmanager
    def port_context(self):
        """Context manager for automatic port allocation and cleanup."""
        port = self.allocate_port()
        try:
            yield port
        finally:
            self.release_port(port)


class ProcessTracker:
    """Track and manage test-spawned processes for isolation from external instances.

    Provides PID-based process tracking to avoid conflicts when the daemon
    is running separately outside of tests.

    Example:
        tracker = ProcessTracker()
        proc = start_server(port=9000)
        tracker.register_process(proc, "server", {"port": 9000})

        # Later: count only our processes
        count = tracker.count_alive("daemon")

        # Cleanup only our processes
        tracker.cleanup_all()
    """

    def __init__(self, test_name: str = "unknown"):
        """Initialize process tracker.

        Args:
            test_name: Name of test for debugging purposes
        """
        self._lock = threading.Lock()
        self._processes: Dict[int, Dict[str, Any]] = {}
        self._test_name = test_name

    def register_process(
        self,
        proc: subprocess.Popen,
        process_type: str,
        metadata: Dict[str, Any] = None,
    ) -> int:
        """Register a spawned process for tracking.

        Args:
            proc: subprocess.Popen instance
            process_type: Type identifier (e.g., "daemon")
            metadata: Optional metadata dict (port, db_path, etc.)

        Returns:
            int: Process ID of registered process
        """
        with self._lock:
            pid = proc.pid
            self._processes[pid] = {
                "proc": proc,
                "type": process_type,
                "metadata": metadata or {},
                "parent_pid": None,
            }
            return pid

    def register_child_pid(
        self, child_pid: int, process_type: str, parent_pid: int, metadata: Dict = None
    ) -> None:
        """Register a child PID (e.g., daemon's spawned child processes).

        Args:
            child_pid: PID of child process
            process_type: Type identifier
            parent_pid: PID of parent process
            metadata: Optional metadata dict
        """
        with self._lock:
            self._processes[child_pid] = {
                "proc": None,  # We don't have Popen object for children
                "type": process_type,
                "metadata": metadata or {},
                "parent_pid": parent_pid,
            }

    def is_alive(self, pid: int) -> bool:
        """Check if a tracked PID is still alive.

        Args:
            pid: Process ID to check

        Returns:
            bool: True if process exists and is running
        """
        try:
            proc = psutil.Process(pid)
            return proc.is_running()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    def count_alive(self, process_type: str = None) -> int:
        """Count tracked processes that are still alive.

        Args:
            process_type: Optional type filter
                         If None, counts all tracked processes

        Returns:
            int: Number of alive tracked processes matching criteria
        """
        with self._lock:
            count = 0
            for pid, info in self._processes.items():
                if process_type is None or info["type"] == process_type:
                    if self.is_alive(pid):
                        count += 1
            return count

    def get_pids_by_type(self, process_type: str) -> List[int]:
        """Get list of tracked PIDs by type.

        Args:
            process_type: Type identifier to filter by

        Returns:
            List of PIDs matching the type
        """
        with self._lock:
            return [
                pid
                for pid, info in self._processes.items()
                if info["type"] == process_type
            ]

    def assert_exact_count(self, process_type: str, expected: int) -> None:
        """Assert that exactly N processes of given type are alive.

        Args:
            process_type: Type to check
            expected: Expected count

        Raises:
            AssertionError: If count doesn't match expected
        """
        actual = self.count_alive(process_type)
        assert actual == expected, (
            f"Expected exactly {expected} {process_type} process(es), "
            f"found {actual} in test {self._test_name}"
        )

    def cleanup_all(self, term_timeout: float = 5.0, kill_timeout: float = 2.0) -> None:
        """Terminate all tracked processes gracefully, then forcefully.

        Args:
            term_timeout: Seconds to wait after SIGTERM
            kill_timeout: Seconds to wait after SIGKILL
        """
        with self._lock:
            processes = list(self._processes.values())

        for info in processes:
            proc = info.get("proc")
            if proc is not None:
                _terminate_single_process(proc, term_timeout, kill_timeout)


def _terminate_single_process(
    proc: subprocess.Popen, term_timeout: float = 5.0, kill_timeout: float = 2.0
) -> None:
    """Terminate a single subprocess.Popen instance gracefully, then forcefully.

    Best-effort: swallows errors if the process already exited or disappears.
    """
    try:
        if proc.poll() is None:  # still running
            try:
                proc.terminate()
                proc.wait(timeout=term_timeout)
            except Exception:
                try:
                    proc.kill()
                    proc.wait(timeout=kill_timeout)
                except Exception:
                    pass
    except Exception:
        # If proc is in a weird state, ignore; teardown should be best-effort
        pass


def cleanup_processes(processes: Iterable[subprocess.Popen]) -> None:
    """Terminate a collection of subprocesses and any lingering child processes.

    1) Attempts graceful termination for each provided process, then kill.
    2) Performs a secondary sweep over current process children recursively to
       catch any leftover orphans and ensure clean test isolation.
    """
    # Terminate tracked processes first
    for proc in list(processes):
        _terminate_single_process(proc)

    # Additional cleanup using psutil to catch any orphaned children
    try:
        current = psutil.Process()
        for child in current.children(recursive=True):
            try:
                if child.is_running():
                    try:
                        child.terminate()
                        child.wait(timeout=3)
                    except (psutil.NoSuchProcess, psutil.TimeoutExpired):
                        try:
                            child.kill()
                        except psutil.NoSuchProcess:
                            pass
            except psutil.NoSuchProcess:
                # Child may have exited between listing and action
                continue
    except psutil.NoSuchProcess:
        # Current process vanished? Highly unlikely in tests; ignore.
        pass


def cleanup_files(paths: Iterable[str]) -> None:
    """Best-effort unlink for temporary files created during tests."""
    for p in list(paths):
        try:
            os.unlink(p)
        except OSError:
            pass


def wait_for_port(port: int, timeout: float = 10, health_path: str = "/health") -> bool:
    """Wait for a port to become available for HTTP requests.

    Args:
        port: Port number to check
        timeout: Maximum time to wait in seconds
        health_path: Health check endpoint path

    Returns:
        bool: True if port is ready, False if timeout exceeded
    """
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = httpx.get(f"http://localhost:{port}{health_path}", timeout=1)
            if response.status_code == 200:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(0.1)
    return False
