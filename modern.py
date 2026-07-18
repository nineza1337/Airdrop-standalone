"""Modern AirDrop path: companion-link (TCP) + asquic (UDP QUIC-like)."""

from __future__ import annotations

import random
import socket
import time
from pathlib import Path

from config import log
from constants import (
    ASQUIC_INIT_TEMPLATES,
    ASQUIC_RESP_TEMPLATE,
    CLINK_ACK_TEMPLATE,
    CLINK_INIT_TEMPLATE,
)
from netutil import bind_to_iface, jitter_quic, patch_clink_sender, scoped
from peers import PeerPorts, _is_companion_response, _is_tls_record
from quic_profile import POKE_QUIC_PROFILE

ASQUIC_ALPN = POKE_QUIC_PROFILE["alpn"]


class ModernAirDrop:
    def __init__(self, iface: str, timeout: float = 5.0):
        self.iface = iface
        self.timeout = timeout
        self._clink_sock: socket.socket | None = None

    def close_session(self) -> None:
        if self._clink_sock is not None:
            try:
                self._clink_sock.close()
            except OSError:
                pass
            self._clink_sock = None

    def _tcp(self) -> socket.socket:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        bind_to_iface(s, self.iface)
        return s

    def _udp(self) -> socket.socket:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        bind_to_iface(s, self.iface)
        return s

    def companion_handshake(self, peer: PeerPorts, sender: str) -> socket.socket | None:
        host = scoped(peer.host, self.iface)
        init = patch_clink_sender(CLINK_INIT_TEMPLATE, sender, peer.host)
        ack = patch_clink_sender(CLINK_ACK_TEMPLATE, sender, peer.host)

        candidates = peer.companion_candidates()
        open_first = peer.open_companion_ports(self.iface, 0.8)
        try_order = open_first + [p for p in candidates if p not in open_first]
        if not open_first:
            log(
                f"no companion TCP listener in {candidates} — "
                "open AirDrop share sheet on target (Everyone)",
                level="warn",
            )

        for port in try_order:
            try:
                sock = self._tcp()
                sock.connect((host, port))
                log(f"companion-link TCP -> {peer.host}:{port}")
                sock.sendall(init)
                log(f"  INIT type=0x05 len={len(init)} (Ask embedded in mDNS blob)", level="dbg")

                resp = b""
                try:
                    resp = sock.recv(4096)
                    if resp:
                        log(f"  peer RESP {len(resp)}B head={resp[:12].hex()}", level="dbg")
                except socket.timeout:
                    log("  no TCP response (timeout)", level="dbg")

                if resp and _is_tls_record(resp):
                    log(f"  :{port} is TLS (not companion-link) — skip", level="warn")
                    sock.close()
                    continue
                if resp and not _is_companion_response(resp):
                    log(f"  :{port} unexpected response — skip", level="warn")
                    sock.close()
                    continue

                sock.sendall(ack)
                log(f"  ACK  type=0x06 len={len(ack)}", level="dbg")
                peer.clink = port
                return sock
            except OSError as exc:
                log(f"companion-link :{port} failed: {exc}", level="dbg")

        log("companion-link failed on all ports — open AirDrop share sheet on target", level="err")
        return None

    def companion_session(
        self, peer: PeerPorts, sender: str, *, keep_open: bool = True, bootstrap: bool = False
    ) -> bool:
        """INIT/ACK handshake; optional legacy template bootstrap (real upload uses asquic_client)."""
        sock = self.companion_handshake(peer, sender)
        if not sock:
            return False
        if keep_open:
            self._clink_sock = sock
        else:
            try:
                sock.close()
            except OSError:
                pass
        if bootstrap:
            self.asquic_bootstrap(peer)
        return True

    def asquic_bootstrap(self, peer: PeerPorts, rounds: int = 4) -> None:
        host = scoped(peer.host, self.iface)
        udp = self._udp()
        try:
            sport = random.randint(49152, 65500)
            udp.bind(("::", sport))
        except OSError:
            pass

        log(f"asquic UDP -> {peer.host}:{peer.asquic}")
        for i, tpl in enumerate(ASQUIC_INIT_TEMPLATES[:rounds]):
            pkt = jitter_quic(tpl)
            try:
                udp.sendto(pkt, (host, peer.asquic, 0, 0))
                log(f"  QUIC initial #{i+1} {len(pkt)}B -> :{peer.asquic}", level="dbg")
            except OSError as exc:
                log(f"  UDP send: {exc}", level="dbg")
            time.sleep(0.05)

        # listen briefly for server initials
        deadline = time.time() + min(self.timeout, 2.0)
        while time.time() < deadline:
            try:
                data, addr = udp.recvfrom(65535)
                log(f"  asquic RX {len(data)}B from {addr[0]}:{addr[1]} head={data[:16].hex()}", level="dbg")
            except socket.timeout:
                break
            except OSError:
                break

        # mirror response template once
        try:
            udp.sendto(jitter_quic(ASQUIC_RESP_TEMPLATE), (host, peer.asquic, 0, 0))
        except OSError:
            pass
        udp.close()

    def ask(self, peer: PeerPorts, sender: str) -> bool:
        """Modern Ask = companion INIT (+ optional asquic). No TLS :8770."""
        return self.companion_session(peer, sender)

    def upload(
        self,
        peer: PeerPorts,
        sender: str,
        file_path: Path,
        *,
        after_handshake: bool = False,
    ) -> bool:
        """File transfer over encrypted asquic (QUIC v1) — not yet implemented."""
        if not file_path.is_file():
            log(f"file not found: {file_path}", level="err")
            return False

        size = file_path.stat().st_size
        log(f"upload {file_path.name} ({size} bytes) via asquic path")

        if not after_handshake and not self.companion_session(peer, sender):
            log("upload aborted — companion-link required for modern path", level="err")
            return False

        log(
            "asquic encrypted upload — trying aioquic QUIC v1 client "
            f"({size}B, alpn={ASQUIC_ALPN})",
            level="dbg",
        )
        from asquic_client import AsquicClient

        client = AsquicClient(self.iface, timeout=self.timeout)
        ok = client.upload(peer, file_path)
        if ok:
            log(f"upload completed via asquic ({size}B)", level="ok")
        else:
            log(
                "asquic upload failed — companion session or Apple H3 framing may differ; "
                "capture on Kali to compare with poke_standalone.pcap",
                level="err",
            )
        return ok
