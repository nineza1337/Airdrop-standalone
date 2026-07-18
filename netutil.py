"""IPv6 / socket helpers and companion-link packet mangling."""

from __future__ import annotations

import ipaddress
import random
import secrets
import socket
import string
import subprocess
import uuid

from config import log
from constants import (
    CLINK_MAGIC,
    LINUX_SO_BINDTODEVICE,
    _TEMPLATE_AT,
    _TEMPLATE_SENDER,
    _TEMPLATE_SID,
)


def norm_ipv6(addr: str) -> str:
    """Normalize IPv6 (compressed fe80::... form)."""
    try:
        return ipaddress.ip_address(addr.split("%")[0]).compressed
    except ValueError:
        return addr.split("%")[0].lower()


def expand_ipv6(addr: str) -> str:
    return norm_ipv6(addr)


def scoped(host: str, iface: str) -> str:
    host = expand_ipv6(host)
    if "%" not in host and ":" in host:
        return f"{host}%{iface}"
    return host


def bind_to_iface(sock: socket.socket, iface: str) -> None:
    if not iface:
        return
    try:
        sock.setsockopt(socket.SOL_SOCKET, LINUX_SO_BINDTODEVICE, (iface + "\0").encode())
    except OSError as exc:
        log(f"SO_BINDTODEVICE({iface}): {exc}", level="warn")


def random_sender_name() -> str:
    emoji = "🐍🌙🔥💀👻⭐️🎯📱💻🖥️🌈⚡️🤖👾🎲"
    pool = string.ascii_letters + string.digits + emoji
    styles = (
        lambda: "".join(random.choices(pool, k=random.randint(8, 20))),
        lambda: f"{random.choice(('iPhone', 'iPad', 'Mac', 'AirDrop'))}{random.randint(1, 9999)}",
        lambda: "".join(random.choices(emoji, k=3)) + secrets.token_hex(3),
    )
    return random.choice(styles)()[:48]


def patch_clink_sender(blob: bytes, sender: str, target_ipv6: str | None = None) -> bytes:
    """Patch sender name / sid / at token in companion-link INIT template."""
    out = blob
    if _TEMPLATE_SENDER in out:
        new_name = sender.encode("utf-8")
        # keep DNS label length consistent if possible — pad or trim
        if len(new_name) <= len(_TEMPLATE_SENDER):
            new_name = new_name.ljust(len(_TEMPLATE_SENDER), b"\x00")
        else:
            new_name = new_name[: len(_TEMPLATE_SENDER)]
        out = out.replace(_TEMPLATE_SENDER, new_name, 1)
    new_sid = str(uuid.uuid4()).upper().encode("ascii")
    if len(new_sid) <= len(_TEMPLATE_SID):
        new_sid = new_sid.ljust(len(_TEMPLATE_SID), b"0")
    else:
        new_sid = new_sid[: len(_TEMPLATE_SID)]
    out = out.replace(_TEMPLATE_SID, new_sid, 1)
    new_at = secrets.token_hex(5).encode("ascii")
    out = out.replace(_TEMPLATE_AT, new_at, 1)
    # randomize 8 bytes after magic in template (session nonce area)
    idx = out.find(CLINK_MAGIC)
    if idx >= 0 and idx + 14 <= len(out):
        nonce = secrets.token_bytes(8)
        out = out[: idx + 5] + nonce + out[idx + 13 :]
    if target_ipv6:
        # patch embedded placeholder IPv6 in CLINK_INIT_TEMPLATE if present
        # (redacted from lab pcap — was fe80::58e7:1eff:fe54:ccd3)
        tip = expand_ipv6(target_ipv6)
        parts = tip.split(":")
        if len(parts) == 8:
            raw = b"".join(int(p, 16).to_bytes(2, "big") for p in parts)
            old = bytes.fromhex("fe80000000000000aaaaaaaabbbbcccc")
            if old in out:
                out = out.replace(old, raw, 1)
    return out


def jitter_quic(pkt: bytes) -> bytes:
    """Randomize connection-id bytes in QUIC template (offsets from pcap)."""
    b = bytearray(pkt)
    if len(b) < 32:
        return pkt
    for off in (7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20):
        if off < len(b):
            b[off] = secrets.randbelow(256)
    return bytes(b)


def enum_neighbors(iface: str) -> list[str]:
    try:
        out = subprocess.check_output(
            ["ip", "-6", "neigh", "show", "dev", iface],
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log(f"ip neigh failed: {exc}", level="warn")
        return []
    addrs = []
    for line in out.splitlines():
        line = line.strip()
        if not line or "fe80:" not in line.lower():
            continue
        addr = line.split()[0].split("%")[0]
        if addr.startswith("fe80:"):
            addrs.append(norm_ipv6(addr))
    return sorted(set(addrs))


def probe_port(host: str, port: int, iface: str, timeout: float = 1.0) -> bool:
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(timeout)
        bind_to_iface(s, iface)
        s.connect((scoped(host, iface), port))
        s.close()
        return True
    except OSError:
        return False
