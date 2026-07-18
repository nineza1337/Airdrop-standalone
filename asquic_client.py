"""aioquic client for Apple asquic — QUIC v1 + ALPN h3 (from poke pcap)."""

from __future__ import annotations

import asyncio
import secrets
import socket
import time
from pathlib import Path
from typing import Any, cast

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, H3Event
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated, QuicEvent

from config import log
from netutil import bind_to_iface, scoped
from peers import PeerPorts
from quic_profile import POKE_QUIC_PROFILE

ASQUIC_ALPN = POKE_QUIC_PROFILE["alpn"]


class _AsquicProtocol(QuicConnectionProtocol):
    def __init__(self, quic: QuicConnection, *, stream_handler: Any = None) -> None:
        super().__init__(quic, stream_handler=stream_handler)
        self.h3: H3Connection | None = None
        self.rx = asyncio.Queue[bytes]()
        self.closed_reason: str | None = None

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ConnectionTerminated):
            self.closed_reason = f"code={event.error_code} reason={event.reason_phrase!r}"
            return
        if self.h3 is None:
            return
        for h3_event in self.h3.handle_event(event):
            self._on_h3(h3_event)

    def _on_h3(self, event: H3Event) -> None:
        if isinstance(event, DataReceived):
            self.rx.put_nowait(event.data)


def _configuration() -> QuicConfiguration:
    cfg = QuicConfiguration(is_client=True, alpn_protocols=ASQUIC_ALPN)
    cfg.verify_mode = False
    cfg.max_datagram_frame_size = 65536
    return cfg


async def _awdl_connect(
    peer: PeerPorts,
    iface: str,
    timeout: float,
) -> _AsquicProtocol:
    """UDP/QUIC connect bound to awdl0 link-local (Linux)."""
    host = scoped(peer.host, iface)
    host_plain = host.split("%")[0]
    scope = socket.if_nametoindex(iface)
    local_port = secrets.randbelow(16384) + 49152

    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host_plain, peer.asquic, type=socket.SOCK_DGRAM)
    addr = infos[0][4]
    if len(addr) == 2:
        addr = (f"::ffff:{addr[0]}", addr[1], 0, scope)
    elif len(addr) == 4:
        addr = (addr[0], addr[1], 0, scope)

    configuration = _configuration()
    configuration.server_name = host_plain
    quic = QuicConnection(configuration=configuration)

    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        bind_to_iface(sock, iface)
        sock.bind(("::", local_port, 0, scope))
    except OSError:
        sock.close()
        raise

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: _AsquicProtocol(quic),
        sock=sock,
    )
    protocol = cast(_AsquicProtocol, protocol)
    protocol.connect(addr)
    await asyncio.wait_for(protocol.wait_connected(), timeout=timeout)
    protocol.h3 = H3Connection(protocol._quic, enable_webtransport=False)
    return protocol


class AsquicClient:
    """QUIC v1 client matching poke capture: ALPN h3, SCID/DCID 4–8B, ~1200B Initial."""

    def __init__(self, iface: str, timeout: float = 8.0):
        self.iface = iface
        self.timeout = timeout

    async def _upload_async(self, peer: PeerPorts, file_path: Path) -> bool:
        data = file_path.read_bytes()
        protocol: _AsquicProtocol | None = None
        try:
            protocol = await _awdl_connect(peer, self.iface, self.timeout)
            alpn = protocol._quic.tls.alpn_protocol
            log(f"asquic: handshake ok alpn={alpn!r} -> {peer.host}:{peer.asquic}", level="dbg")

            stream_id = protocol._quic.get_next_available_stream_id(is_unidirectional=False)
            assert protocol.h3 is not None
            protocol.h3.send_data(stream_id=stream_id, data=data, end_stream=True)
            protocol.transmit()

            log(f"asquic: sent {len(data)}B on H3 stream {stream_id}", level="dbg")

            rx_deadline = time.monotonic() + min(self.timeout, 3.0)
            rx_chunks: list[bytes] = []
            while time.monotonic() < rx_deadline:
                try:
                    chunk = await asyncio.wait_for(protocol.rx.get(), timeout=0.5)
                    rx_chunks.append(chunk)
                except asyncio.TimeoutError:
                    break
            if rx_chunks:
                rx = b"".join(rx_chunks)
                log(f"asquic: peer data {len(rx)}B head={rx[:24].hex()}", level="dbg")

            if protocol.closed_reason:
                log(f"asquic: closed {protocol.closed_reason}", level="warn")
                return False
            return True
        except asyncio.TimeoutError:
            log("asquic: QUIC handshake timeout", level="err")
            return False
        except OSError as exc:
            log(f"asquic: {exc}", level="err")
            return False
        finally:
            if protocol is not None:
                protocol.close()
                try:
                    await asyncio.wait_for(protocol.wait_closed(), timeout=2.0)
                except asyncio.TimeoutError:
                    pass

    def upload(self, peer: PeerPorts, file_path: Path) -> bool:
        try:
            return asyncio.run(self._upload_async(peer, file_path))
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(self._upload_async(peer, file_path))
            finally:
                loop.close()
