"""Peer port bookkeeping and discovered-device data model."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from config import DISCOVER_JSON, log
from constants import (
    CLINK_MAGIC,
    DEFAULT_ASQUIC_PORT,
    DEFAULT_CLINK_PORT,
    DEFAULT_TLS_PORT,
)
from netutil import norm_ipv6, probe_port


@dataclass
class PeerPorts:
    host: str
    clink: int = DEFAULT_CLINK_PORT
    prepair: int = 0
    asquic: int = DEFAULT_ASQUIC_PORT
    tls: int = DEFAULT_TLS_PORT
    srv_tcp_ports: list[int] = field(default_factory=list)

    def note_tcp_port(self, port: int) -> None:
        if port and port != self.tls and port not in self.srv_tcp_ports:
            self.srv_tcp_ports.append(port)

    def companion_candidates(self) -> list[int]:
        """TCP ports for companion-link / prepair only — never TLS :8770."""
        out: list[int] = []
        for p in (self.clink, self.prepair, *self.srv_tcp_ports):
            if not p or p == self.tls or p in out:
                continue
            # Stale template default — only use if mDNS explicitly listed it.
            if p == DEFAULT_CLINK_PORT and p not in self.srv_tcp_ports:
                continue
            out.append(p)
        return out

    def clink_candidates(self) -> list[int]:
        return self.companion_candidates()

    def open_companion_ports(self, iface: str, timeout: float = 0.8) -> list[int]:
        return [p for p in self.companion_candidates() if probe_port(self.host, p, iface, timeout)]

    def open_tcp_ports(self, iface: str, timeout: float = 0.8) -> list[int]:
        return self.open_companion_ports(iface, timeout)

    def tls_open(self, iface: str, timeout: float = 1.0) -> bool:
        return bool(self.tls and probe_port(self.host, self.tls, iface, timeout))


@dataclass
class FoundDevice:
    ipv6: str
    port: int = 0
    service_id: str = ""
    hostname: str = ""
    txt_name: str | None = None
    discover_name: str | None = None
    flags: int = 0
    discoverable: bool = False
    clink_port: int | None = None
    asquic_port: int | None = None
    prepair_port: int | None = None
    has_tls_airdrop: bool = False
    modern_ios: bool = False
    service_types: list[str] = field(default_factory=list)
    awdl_neighbor: bool = False
    query_only: bool = False
    source: str = ""
    os_info: str = ""
    last_seen: float = field(default_factory=time.time)

    def display_name(self) -> str:
        return self.discover_name or self.txt_name or self.hostname or self.service_id or "?"

    def to_dict(self) -> dict:
        port = self.port or self.prepair_port or self.clink_port or None
        return {
            "name": self.display_name(),
            "address": self.ipv6 if self.ipv6 else "",
            "host": self.hostname,
            "port": port,
            "id": self.service_id,
            "flags": self.flags,
            "discoverable": self.discoverable,
            "txt_name": self.txt_name,
            "discover_name": self.discover_name,
            "clink_port": self.clink_port,
            "asquic_port": self.asquic_port,
            "prepair_port": self.prepair_port,
            "modern_ios": self.modern_ios,
            "service_types": self.service_types,
            "query_only": self.query_only,
            "awdl_neighbor": self.awdl_neighbor,
            "source": self.source,
            "os": self.os_info,
        }


def load_peer_from_discover(host: str) -> FoundDevice | None:
    """Load cached ports/name from discover.last.json (written by find)."""
    if not DISCOVER_JSON.is_file():
        return None
    try:
        rows = json.loads(DISCOVER_JSON.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    host_n = norm_ipv6(host)
    for row in rows:
        addr = row.get("address") or ""
        if addr and norm_ipv6(addr) == host_n:
            return FoundDevice(
                ipv6=host_n,
                port=row.get("port") or 0,
                service_id=row.get("id") or "",
                hostname=row.get("host") or "",
                txt_name=row.get("txt_name") or row.get("name"),
                flags=int(row.get("flags") or 0),
                clink_port=row.get("clink_port"),
                asquic_port=row.get("asquic_port"),
                prepair_port=row.get("prepair_port"),
                has_tls_airdrop=bool(row.get("port")),
                modern_ios=bool(row.get("modern_ios")),
            )
    return None


def found_device_to_ports(dev: FoundDevice) -> PeerPorts:
    clink = dev.clink_port or DEFAULT_CLINK_PORT
    prepair = dev.prepair_port or 0
    if prepair and clink == DEFAULT_CLINK_PORT:
        clink = prepair
    ports = PeerPorts(
        host=dev.ipv6,
        clink=clink,
        prepair=prepair,
        asquic=dev.asquic_port or DEFAULT_ASQUIC_PORT,
        tls=dev.port or DEFAULT_TLS_PORT,
    )
    for p in (dev.clink_port, dev.prepair_port):
        if p:
            ports.note_tcp_port(int(p))
    return ports


def ports_direct(peer: str, tls_port: int = DEFAULT_TLS_PORT) -> PeerPorts:
    """Instant ports for --target (no mDNS sniff — matches opendrop --target)."""
    return PeerPorts(host=norm_ipv6(peer), tls=tls_port)


def _is_tls_record(data: bytes) -> bool:
    return bool(data) and data[0] in (0x14, 0x15, 0x16, 0x17)


def _is_companion_response(data: bytes) -> bool:
    if not data:
        return False
    if CLINK_MAGIC in data:
        return True
    return data[0] in (0x05, 0x06)


def _apply_mdns_srv(ports: PeerPorts, name: str, port: int) -> None:
    name = name.lower()
    if "_asquic._udp" in name:
        ports.asquic = port
        return
    if "_airdrop._tcp" in name:
        ports.tls = port
        return
    if "_companion-link._tcp" in name:
        ports.clink = port
        ports.note_tcp_port(port)
        return
    if "_appsvcprepair._tcp" in name or "_applicationservicepairing._tcp" in name:
        ports.prepair = port
        ports.note_tcp_port(port)
        if ports.clink == DEFAULT_CLINK_PORT:
            ports.clink = port


def _merge_peer_ports(base: PeerPorts, live: PeerPorts) -> PeerPorts:
    """Live mDNS wins; base fills only missing fields."""
    if live.clink != DEFAULT_CLINK_PORT:
        base.clink = live.clink
    if live.prepair:
        base.prepair = live.prepair
    if live.asquic != DEFAULT_ASQUIC_PORT:
        base.asquic = live.asquic
    if live.tls != DEFAULT_TLS_PORT:
        base.tls = live.tls
    for p in live.srv_tcp_ports:
        base.note_tcp_port(p)
    return base
