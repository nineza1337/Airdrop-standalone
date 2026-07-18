"""Paths, logging, TLS key resolution and cooperative Ctrl+C handling."""

from __future__ import annotations

import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths — keys live next to this script (copy from ../opendrop/keys on first run)
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
KEYS_DIR = SCRIPT_DIR / "keys"
DISCOVER_JSON = SCRIPT_DIR / "discover.last.json"
DEBUG = False


def set_debug(value: bool) -> None:
    """Toggle module-wide debug logging (log() reads this global)."""
    global DEBUG
    DEBUG = bool(value)


def log(msg: str, *, level: str = "info") -> None:
    if level == "dbg" and not DEBUG:
        return
    ts = time.strftime("%H:%M:%S")
    prefix = {"info": "[+]", "warn": "[!]", "dbg": "[.]", "err": "[X]"}.get(level, "[?]")
    print(f"{ts} {prefix} {msg}", flush=True)


def hexdump(data: bytes, *, width: int = 16, max_bytes: int = 1024) -> str:
    """Return a hex+ASCII dump for debugging raw packets (capped at max_bytes)."""
    lines: list[str] = []
    view = data[:max_bytes]
    for off in range(0, len(view), width):
        chunk = view[off : off + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"    {off:04x}  {hex_part:<{width * 3}}  {ascii_part}")
    if len(data) > max_bytes:
        lines.append(f"    ... (+{len(data) - max_bytes} more bytes)")
    return "\n".join(lines)


class _FindStop:
    """Cooperative Ctrl+C for find: first press stops scan; second forces quit."""

    def __init__(self) -> None:
        self.requested = False
        self._hits = 0
        self._prev_sigint = None

    def install(self) -> None:
        if threading.current_thread() is threading.main_thread():
            self._prev_sigint = signal.signal(signal.SIGINT, self._on_sigint)

    def restore(self) -> None:
        if self._prev_sigint is not None and threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGINT, self._prev_sigint)
            self._prev_sigint = None

    def _on_sigint(self, signum, frame) -> None:
        self._hits += 1
        if self._hits == 1:
            self.requested = True
            log("Ctrl+C — stopping scan, saving results … (press again to quit immediately)")
        else:
            log("force quit")
            raise KeyboardInterrupt


def resolve_key_dir() -> Path:
    """Prefer ./keys, then ~/.opendrop/keys (same as opendrop), then opendrop/keys."""
    home_keys = Path.home() / ".opendrop" / "keys"
    candidates = [
        KEYS_DIR,
        home_keys,
        SCRIPT_DIR.parent / "opendrop" / "keys",
        SCRIPT_DIR.parent / "Stand_alone" / "keys",
        Path.cwd() / "keys",
    ]
    for d in candidates:
        if (d / "certificate.pem").is_file() and (d / "key.pem").is_file():
            log(f"TLS keys: {d}", level="dbg")
            return d
    return ensure_keys_dir()


def resolve_ca_file() -> Path | None:
    for p in (
        KEYS_DIR / "apple_root_ca.pem",
        SCRIPT_DIR.parent / "opendrop" / "keys" / "apple_root_ca.pem",
        # local dev path removed for public release (was: Own/opendrop2/certs)
    ):
        if p.is_file():
            log(f"Apple root CA: {p}", level="dbg")
            return p
    return None


def ensure_keys_dir() -> Path:
    """Create Stand_alone/keys and copy from opendrop/keys or generate self-signed cert."""
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    src = SCRIPT_DIR.parent / "opendrop" / "keys"
    ca_src = None  # local dev CA path removed for public release
    for name in ("certificate.pem", "key.pem"):
        dst = KEYS_DIR / name
        if dst.is_file():
            continue
        if (src / name).is_file():
            shutil.copy2(src / name, dst)
            log(f"copied {name} from {src}", level="dbg")
    ca_dst = KEYS_DIR / "apple_root_ca.pem"
    if not ca_dst.is_file():
        for candidate in (src / "apple_root_ca.pem", ca_src) if ca_src else (src / "apple_root_ca.pem",):
            if candidate and candidate.is_file():
                shutil.copy2(candidate, ca_dst)
                log(f"copied apple_root_ca.pem from {candidate.parent}", level="dbg")
                break
    cert = KEYS_DIR / "certificate.pem"
    key = KEYS_DIR / "key.pem"
    if not cert.is_file() or not key.is_file():
        log(f"generating self-signed cert in {KEYS_DIR}")
        subprocess.run(
            [
                "openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", "key.pem",
                "-x509", "-days", "365", "-out", "certificate.pem",
                "-subj", "/CN=AirDrop-Standalone",
            ],
            cwd=str(KEYS_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    return KEYS_DIR
