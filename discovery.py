"""mDNS discovery, port sniffing, and TLS /Discover name lookup."""

from __future__ import annotations

import json
import plistlib
import re
import socket
import ssl
import time
from pathlib import Path

import config
from config import DISCOVER_JSON, _FindStop, log, resolve_ca_file, resolve_key_dir
from constants import (
    APPLE_AIRDROP_SERVICE_SUFFIXES,
    DEFAULT_TLS_PORT,
    MDNS_GROUP,
    MDNS_PORT,
    RECEIVER_FLAG_DISCOVER,
)
from ble import BleWakeBeacon
from netutil import bind_to_iface, enum_neighbors, norm_ipv6, probe_port, scoped
from peers import (
    FoundDevice,
    PeerPorts,
    _apply_mdns_srv,
    _merge_peer_ports,
    found_device_to_ports,
    load_peer_from_discover,
)


def _sniff_peer_mdns(host_n: str, iface: str, sniff_s: float, *, browse: bool) -> PeerPorts:
    ports = PeerPorts(host=host_n)
    try:
        from scapy.all import DNS, sniff  # type: ignore
    except ImportError:
        log("scapy not installed — using cached/default ports", level="warn")
        return ports

    if browse:
        _mdns_send_browse(iface)

    def _match(pkt):
        if not pkt.haslayer(DNS):
            return False
        if pkt.haslayer("IPv6"):
            src = norm_ipv6(pkt["IPv6"].src)
            if src == host_n:
                return True
        d = pkt[DNS]
        for sec in (d.an, d.ar):
            if not sec:
                continue
            for rr in sec:
                if not hasattr(rr, "rrname"):
                    continue
                name = rr.rrname.decode(errors="ignore").lower()
                if rr.type == 28 and norm_ipv6(str(rr.rdata)) == host_n:
                    return True
                if rr.type == 33 and any(
                    k in name
                    for k in ("companion", "asquic", "airdrop", "appsvcprepair", "applicationservicepairing")
                ):
                    return True
        return False

    log(f"mDNS sniff {sniff_s}s for {host_n} ...", level="dbg")
    try:
        pkts = sniff(iface=iface, filter="udp port 5353", timeout=sniff_s, lfilter=_match, store=True)
    except Exception as exc:
        log(f"mDNS sniff: {exc}", level="dbg")
        return ports

    for pkt in pkts:
        if not pkt.haslayer(DNS):
            continue
        if pkt.haslayer("IPv6") and norm_ipv6(pkt["IPv6"].src) != host_n:
            continue
        d = pkt[DNS]
        for sec in (d.an, d.ar):
            if not sec:
                continue
            for rr in sec:
                if rr.type != 33:
                    continue
                name = rr.rrname.decode(errors="ignore")
                _apply_mdns_srv(ports, name, int(rr.port))
    return ports


def discover_ports(
    host: str,
    iface: str,
    sniff_s: float = 10.0,
    *,
    force_rescan: bool = False,
    rescan: bool = True,
) -> PeerPorts:
    """Live mDNS first; merge discover.last.json unless force_rescan."""
    host_n = norm_ipv6(host)
    ports = _sniff_peer_mdns(host_n, iface, sniff_s, browse=True)

    cached = None if force_rescan else load_peer_from_discover(host_n)
    if cached:
        cached_ports = found_device_to_ports(cached)
        log(
            f"ports from {DISCOVER_JSON.name}: clink={cached_ports.clink} prepair={cached_ports.prepair} "
            f"asquic={cached_ports.asquic} tls={cached_ports.tls}",
            level="dbg",
        )
        ports = _merge_peer_ports(cached_ports, ports)

    log(
        f"ports merged clink={ports.clink} prepair={ports.prepair} "
        f"asquic={ports.asquic} tls={ports.tls} srv={ports.srv_tcp_ports}",
        level="dbg",
    )

    open_ports = ports.open_companion_ports(iface)
    if open_ports:
        ports.clink = open_ports[0]
        log(f"companion TCP probe OK -> port {open_ports[0]}", level="dbg")
        return ports

    if not rescan:
        log("companion not listening yet (no rescan — will retry after /Ask popup)", level="dbg")
        return ports

    log(
        "no TCP listener on discovered ports — rescanning mDNS "
        "(target: AirDrop open, share sheet visible, screen unlocked)",
        level="warn",
    )
    for _ in range(3):
        _mdns_send_browse(iface)
        time.sleep(0.4)
    fresh = _sniff_peer_mdns(host_n, iface, max(sniff_s, 12.0), browse=False)
    ports = _merge_peer_ports(ports, fresh)
    log(
        f"ports after rescan clink={ports.clink} prepair={ports.prepair} "
        f"asquic={ports.asquic} tls={ports.tls} srv={ports.srv_tcp_ports}",
        level="dbg",
    )

    open_ports = ports.open_companion_ports(iface)
    if open_ports:
        ports.clink = open_ports[0]
        log(f"companion TCP probe OK after rescan -> port {open_ports[0]}", level="dbg")
    else:
        tls_hint = f" TLS :{ports.tls} open" if ports.tls_open(iface) else ""
        log(
            "no open companion port — open AirDrop share sheet on target; "
            f"re-run find then send immediately.{tls_hint}",
            level="err",
        )
    return ports


def _merge_device_fields(dst: FoundDevice, src: FoundDevice) -> None:
    """Merge src into dst (prefer dst IPv6 / richer data)."""
    if src.ipv6 and not dst.ipv6:
        dst.ipv6 = norm_ipv6(src.ipv6)
        dst.query_only = False
    for attr in (
        "port", "service_id", "hostname", "txt_name", "discover_name",
        "flags", "clink_port", "asquic_port", "prepair_port", "os_info", "source",
    ):
        if not getattr(dst, attr) and getattr(src, attr):
            setattr(dst, attr, getattr(src, attr))
    dst.has_tls_airdrop = dst.has_tls_airdrop or src.has_tls_airdrop
    dst.modern_ios = dst.modern_ios or src.modern_ios
    dst.discoverable = dst.discoverable or src.discoverable
    dst.awdl_neighbor = dst.awdl_neighbor or src.awdl_neighbor
    for st in src.service_types:
        if st not in dst.service_types:
            dst.service_types.append(st)
    if dst.ipv6:
        dst.query_only = False
        if dst.source == "mdns-query" and src.source == "mdns-answer":
            dst.source = "mdns-answer"


def _upsert_query_name(
    devices: dict[str, FoundDevice],
    inst: str,
    svc: str,
    hostmap: dict[str, str],
    *,
    now: float | None = None,
) -> None:
    """Record a device name seen in mDNS QUERY (may have no IPv6 yet)."""
    if now is None:
        now = time.time()
    inst_l = _clean_inst_name(inst).lower()
    known_ip = hostmap.get(inst_l)
    if known_ip:
        dev = _get_or_create_device(devices, known_ip)
        dev.last_seen = now
        if not dev.txt_name:
            dev.txt_name = _clean_inst_name(inst)
        if not dev.source:
            dev.source = "mdns-answer"
        return
    for d in devices.values():
        if d.ipv6 and d.txt_name and _names_related(d.txt_name, inst):
            return
    key = f"name:{inst_l}"
    if key not in devices:
        devices[key] = FoundDevice(
            ipv6="",
            txt_name=_clean_inst_name(inst),
            query_only=True,
            source="mdns-query",
            service_types=[svc],
        )
        log(f"mDNS QUERY seen {inst!r} (no ANSWER / no IPv6 yet)", level="dbg")
    else:
        dev = devices[key]
        dev.last_seen = now
        if svc not in dev.service_types:
            dev.service_types.append(svc)


def _clean_inst_name(name: str) -> str:
    return name.strip()


def _instance_name(rname: str) -> str:
    return _clean_inst_name(_dns_name(rname).split(".")[0])


def _names_related(a: str, b: str) -> bool:
    a, b = _clean_inst_name(a).lower(), _clean_inst_name(b).lower()
    if not a or not b:
        return False
    return a == b or a in b or b in a


def _query_matches_answer(dev: FoundDevice, ans: FoundDevice) -> bool:
    qname = _clean_inst_name(dev.txt_name or "")
    qid = _clean_inst_name(dev.service_id or "").lower()
    aname = _clean_inst_name(ans.txt_name or ans.display_name() or "")
    aid = _clean_inst_name(ans.service_id or "").lower()
    if qname and aname and _names_related(qname, aname):
        return True
    if qname and aid and qname.lower() == aid:
        return True
    if qid and aid and qid == aid:
        return True
    return False


def _enrich_queries_from_answers(devices: dict[str, FoundDevice]) -> None:
    answered = [d for d in devices.values() if d.ipv6]
    for dev in devices.values():
        if dev.ipv6 or not dev.query_only:
            continue
        for ans in answered:
            if not _query_matches_answer(dev, ans):
                continue
            log(f"link {dev.txt_name!r} -> {ans.ipv6} (matched {ans.txt_name!r})", level="dbg")
            _merge_device_fields(dev, ans)
            dev.ipv6 = norm_ipv6(ans.ipv6)
            dev.query_only = False
            dev.source = "mdns-answer"
            break


def finalize_discover_devices(devices: dict[str, FoundDevice]) -> list[FoundDevice]:
    """Merge QUERY names with ANSWER IPv6; dedupe by IP."""
    _enrich_queries_from_answers(devices)

    by_ip: dict[str, FoundDevice] = {}
    orphans: list[FoundDevice] = []
    for dev in devices.values():
        if dev.ipv6:
            k = norm_ipv6(dev.ipv6)
            if k in by_ip:
                existing = by_ip[k]
                _merge_device_fields(existing, dev)
                if len(dev.display_name()) > len(existing.display_name()):
                    existing.txt_name = dev.txt_name
            else:
                by_ip[k] = dev
        else:
            orphans.append(dev)

    answered = list(by_ip.values())
    pruned = list(answered)
    for dev in orphans:
        if dev.ipv6:
            k = norm_ipv6(dev.ipv6)
            if k not in by_ip:
                pruned.append(dev)
            continue
        if dev.query_only and any(_query_matches_answer(dev, a) for a in answered):
            continue
        pruned.append(dev)

    return sorted(pruned, key=lambda d: (not d.ipv6, d.display_name().lower(), d.ipv6))


def _dns_name(raw) -> str:
    if isinstance(raw, bytes):
        return raw.decode(errors="replace").rstrip(".")
    return str(raw).rstrip(".")


def _is_apple_airdrop_service(rname: str) -> bool:
    r = rname.lower()
    return any(s in r for s in APPLE_AIRDROP_SERVICE_SUFFIXES)


def _service_label(rname: str) -> str | None:
    r = rname.lower()
    for s in APPLE_AIRDROP_SERVICE_SUFFIXES:
        if s in r:
            return s
    return None


def _parse_txt_rdata(rdata) -> dict[str, str]:
    """Parse Apple mDNS TXT (keys glued: sn=...sid=...at=...dnm=...)."""
    out: dict[str, str] = {}
    chunks: list[bytes] = []
    if isinstance(rdata, bytes):
        chunks = [rdata]
    elif isinstance(rdata, (list, tuple)):
        chunks = [x if isinstance(x, bytes) else str(x).encode() for x in rdata]
    for chunk in chunks:
        blob = chunk.decode(errors="replace")
        for part in blob.split("\x00"):
            part = part.strip()
            if not part:
                continue
            if "=" not in part:
                continue
            # single key=value
            if re.match(r"^[a-zA-Z]+\=", part) and part.count("=") == 1:
                k, v = part.split("=", 1)
                out[k.strip()] = v.strip()
                continue
            # glued Apple keys
            pattern = r"(sn|sid|at|dnm|flags|rpFl|rpAD|rpBA|rpVr)=([^=]*?)(?=(?:sn|sid|at|dnm|flags|rpFl|rpAD|rpBA|rpVr)=|$)"
            for m in re.finditer(pattern, part):
                out[m.group(1)] = m.group(2)
    return out


def _resolve_ipv6(
    src_ipv6: str | None,
    hostname: str,
    hostmap: dict[str, str],
) -> str | None:
    if src_ipv6 and src_ipv6.startswith("fe80:"):
        return norm_ipv6(src_ipv6)
    host = hostname.rstrip(".").lower()
    if host in hostmap:
        return hostmap[host]
    short = host.split(".")[0]
    return hostmap.get(short)


def _mdns_send_browse(iface: str) -> None:
    try:
        from scapy.all import DNS, DNSQR, IPv6, UDP, sendp  # type: ignore
    except ImportError:
        log("scapy not installed — mDNS browse skipped", level="warn")
        return
    queries = [
        "_airdrop._tcp.local.",
        "_appSvcPrePair._tcp.local.",
        "_applicationServicePairing._tcp.local.",
        "_companion-link._tcp.local.",
        "_asquic._udp.local.",
        "_services._dns-sd._udp.local.",
    ]
    for qname in queries:
        pkt = (
            IPv6(dst=MDNS_GROUP)
            / UDP(sport=MDNS_PORT, dport=MDNS_PORT)
            / DNS(rd=0, qd=DNSQR(qname=qname, qtype="PTR"))
        )
        try:
            sendp(pkt, iface=iface, verbose=0)
            log(f"mDNS browse PTR {qname}", level="dbg")
        except Exception as exc:
            log(f"mDNS send {qname}: {exc}", level="dbg")


def _mdns_query_instance(iface: str, instance: str) -> None:
    """Query SRV for a specific AirDrop/IDS service instance (post-/Ask)."""
    try:
        from scapy.all import DNS, DNSQR, IPv6, UDP, sendp  # type: ignore
    except ImportError:
        return
    inst = instance.strip().upper().rstrip(".")
    if not inst:
        return
    for service in ("_companion-link._tcp.local.", "_asquic._udp.local."):
        qname = f"{inst}.{service}"
        pkt = (
            IPv6(dst=MDNS_GROUP)
            / UDP(sport=MDNS_PORT, dport=MDNS_PORT)
            / DNS(rd=0, qd=DNSQR(qname=qname, qtype="SRV"))
        )
        try:
            sendp(pkt, iface=iface, verbose=0)
            log(f"mDNS query SRV {qname}", level="dbg")
        except Exception as exc:
            log(f"mDNS query {qname}: {exc}", level="dbg")


def resolve_instance_mdns(host_n: str, iface: str, instance: str, sniff_s: float = 4.0) -> PeerPorts:
    """Sniff mDNS answers for IDSSessionID / sid instance after /Ask Accept."""
    ports = PeerPorts(host=host_n)
    try:
        from scapy.all import DNS, sniff  # type: ignore
    except ImportError:
        return ports

    _mdns_query_instance(iface, instance)
    inst_key = instance.strip().upper()[:8]
    deadline = time.monotonic() + sniff_s

    def _match(pkt):
        if not pkt.haslayer(DNS):
            return False
        if pkt.haslayer("IPv6") and norm_ipv6(pkt["IPv6"].src) == host_n:
            return True
        try:
            raw = bytes(pkt[DNS]).lower()
            if instance.strip().lower().encode() in raw:
                return True
        except (TypeError, ValueError):
            pass
        return False

    log(f"mDNS instance sniff {sniff_s}s for {inst_key}... on {host_n}", level="dbg")
    collected = []
    try:
        while time.monotonic() < deadline:
            wait = min(1.5, deadline - time.monotonic())
            if wait <= 0:
                break
            _mdns_query_instance(iface, instance)
            pkts = sniff(iface=iface, filter="udp port 5353", timeout=wait, lfilter=_match, store=True)
            collected.extend(pkts)
    except Exception as exc:
        log(f"mDNS instance sniff: {exc}", level="dbg")
        return ports

    for pkt in collected:
        if not pkt.haslayer(DNS):
            continue
        d = pkt[DNS]
        for sec in (d.an, d.ar):
            if not sec:
                continue
            for rr in sec:
                if rr.type != 33:
                    continue
                name = rr.rrname.decode(errors="ignore")
                _apply_mdns_srv(ports, name, int(rr.port))
    return ports


def _build_hostmap(pkts) -> dict[str, str]:
    hostmap: dict[str, str] = {}
    try:
        from scapy.all import DNS  # type: ignore
    except ImportError:
        return hostmap
    for pkt in pkts:
        if not pkt.haslayer(DNS):
            continue
        dns = pkt[DNS]
        src = None
        if pkt.haslayer("IPv6"):
            src = norm_ipv6(pkt["IPv6"].src)
        for section in (dns.an, dns.ar):
            if not section:
                continue
            for rr in section:
                if rr.type != 28:
                    continue
                name = _dns_name(rr.rrname).lower()
                addr = norm_ipv6(str(rr.rdata))
                if addr.startswith("fe80:"):
                    hostmap[name] = addr
                    hostmap[name.split(".")[0]] = addr
                    if src and src.startswith("fe80:"):
                        hostmap[name] = addr
    return hostmap


def _get_or_create_device(
    devices: dict[str, FoundDevice],
    ipv6: str,
) -> FoundDevice:
    k = norm_ipv6(ipv6)
    if k not in devices:
        devices[k] = FoundDevice(ipv6=k)
    return devices[k]


def _ingest_mdns_packet(
    pkt,
    devices: dict[str, FoundDevice],
    hostmap: dict[str, str],
    *,
    now: float | None = None,
    goodbye: set[str] | None = None,
) -> None:
    if now is None:
        now = time.time()
    try:
        from scapy.all import DNS  # type: ignore
    except ImportError:
        return
    if not pkt.haslayer(DNS):
        return
    dns = pkt[DNS]
    src_ipv6 = None
    if pkt.haslayer("IPv6"):
        src_ipv6 = pkt["IPv6"].src.split("%")[0]

    for section_name, section in (("an", dns.an), ("ar", dns.ar)):
        if not section:
            continue
        for rr in section:
            rname_raw = _dns_name(rr.rrname)
            rname = rname_raw.lower()
            svc = _service_label(rname)

            if rr.type == 28:  # AAAA
                addr = norm_ipv6(str(rr.rdata))
                if addr.startswith("fe80:"):
                    if getattr(rr, "ttl", 1) == 0:
                        if goodbye is not None:
                            goodbye.add(addr)
                        log(f"mDNS AAAA goodbye {addr} -> {rname_raw}", level="dbg")
                        continue
                    hostmap[rname.lower()] = addr
                    hostmap[rname.split(".")[0].lower()] = addr
                    dev = _get_or_create_device(devices, addr)
                    dev.last_seen = now
                    log(f"mDNS AAAA {addr} -> {rname_raw}", level="dbg")
                continue

            if not svc:
                continue

            target = _dns_name(getattr(rr, "target", "")) if rr.type == 33 else ""
            ipv6 = _resolve_ipv6(src_ipv6, target or rname_raw, hostmap)
            if not ipv6:
                continue

            dev = _get_or_create_device(devices, ipv6)
            dev.last_seen = now
            if getattr(rr, "ttl", 1) == 0 and goodbye is not None:
                goodbye.add(norm_ipv6(ipv6))
            inst = _instance_name(rname_raw)
            hostmap[inst.lower()] = ipv6
            if svc not in dev.service_types:
                dev.service_types.append(svc)
            if not dev.source:
                dev.source = "mdns-answer"

            if rr.type == 33:  # SRV
                port = int(rr.port)
                dev.hostname = target or dev.hostname
                if "_airdrop._tcp" in rname:
                    dev.port = port
                    dev.has_tls_airdrop = True
                    dev.service_id = inst or dev.service_id
                    log(f"mDNS SRV _airdrop {dev.ipv6} port={port}", level="dbg")
                elif "_appsvcprepair._tcp" in rname or "_applicationservicepairing._tcp" in rname:
                    dev.prepair_port = port
                    dev.modern_ios = True
                    if not dev.txt_name and inst:
                        dev.txt_name = inst
                    log(f"mDNS SRV {svc} {dev.ipv6} port={port} name={inst!r}", level="dbg")
                elif "_companion-link._tcp" in rname:
                    dev.clink_port = port
                    dev.modern_ios = True
                    log(f"mDNS SRV companion-link {dev.ipv6}:{port}", level="dbg")
                elif "_asquic._udp" in rname:
                    dev.asquic_port = port
                    dev.modern_ios = True
                    log(f"mDNS SRV asquic {dev.ipv6}:{port}", level="dbg")

            elif rr.type == 16:  # TXT
                txt = _parse_txt_rdata(rr.rdata)
                if "dnm" in txt:
                    dev.txt_name = txt["dnm"]
                elif inst and not dev.txt_name:
                    dev.txt_name = inst
                if "sid" in txt:
                    dev.service_id = txt["sid"]
                if "flags" in txt:
                    try:
                        dev.flags = int(txt["flags"])
                    except ValueError:
                        pass
                if "sn" in txt and "sharingd.AirDrop" in txt["sn"]:
                    dev.modern_ios = True
                log(f"mDNS TXT {svc} {dev.ipv6} {txt}", level="dbg")

    # mDNS queries — names heard on the network (may have no IPv6 / ANSWER)
    if dns.qd is not None:
        qlist = dns.qd if isinstance(dns.qd, list) else [dns.qd]
        for q in qlist:
            qname = _dns_name(q.qname)
            svc = _service_label(qname)
            if not svc:
                continue
            inst = _instance_name(qname)
            if not inst or inst.startswith("_"):
                continue
            _upsert_query_name(devices, inst, svc, hostmap, now=now)


def tls_discover(
    host: str,
    port: int,
    iface: str,
    *,
    key_dir: Path,
    ca_file: Path | None,
    timeout: float,
) -> dict | None:
    """POST /Discover and return plist response (ReceiverComputerName if discoverable)."""
    cert = key_dir / "certificate.pem"
    key = key_dir / "key.pem"
    if not cert.is_file() or not key.is_file():
        log(f"missing TLS cert in {key_dir}", level="err")
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if ca_file and ca_file.is_file():
        ctx.load_verify_locations(cafile=str(ca_file))
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    body = plistlib.dumps({}, fmt=plistlib.FMT_BINARY)
    log(f"TLS /Discover -> {host}:{port} body={len(body)}B", level="dbg")
    try:
        raw = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        raw.settimeout(timeout)
        bind_to_iface(raw, iface)
        raw.connect((scoped(host, iface), port))
        sock = ctx.wrap_socket(raw, server_hostname=host.split("%")[0])
        req = (
            f"POST /Discover HTTP/1.1\r\n"
            f"Host: airdrop.local\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"User-Agent: AirDrop/1.0\r\n"
            f"\r\n"
        ).encode("ascii") + body
        sock.sendall(req)
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 262144:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        sock.close()
        if b"200" not in buf.split(b"\r\n", 1)[0]:
            log(f"/Discover HTTP fail: {buf[:80]!r}", level="dbg")
            return None
        idx = buf.find(b"\r\n\r\n")
        if idx < 0:
            return None
        resp_body = buf[idx + 4 :]
        if not resp_body:
            return None
        resp = plistlib.loads(resp_body)
        log(f"/Discover response keys: {list(resp.keys())}", level="dbg")
        if config.DEBUG:
            log(f"/Discover plist: {resp}", level="dbg")
        return resp
    except OSError as exc:
        log(f"TLS /Discover {host}:{port}: {exc}", level="dbg")
        return None


def _prune_stale(
    devices: dict[str, FoundDevice],
    now: float,
    stale_after: float,
    goodbye: set[str],
    current_neighbors: set[str],
    seen: set[str],
) -> int:
    """Drop devices that sent mDNS goodbye or were not re-heard within stale_after.

    Devices still present as AWDL neighbors (owl) are always kept.
    Returns the number removed.
    """
    to_remove: list[str] = []
    for key, dev in devices.items():
        ipk = norm_ipv6(dev.ipv6) if dev.ipv6 else ""
        if ipk and ipk in current_neighbors:
            continue  # still an AWDL neighbor -> keep
        gone = bool(ipk) and ipk in goodbye
        stale = (now - dev.last_seen) > stale_after
        if gone or stale:
            to_remove.append(key)
    for key in to_remove:
        dev = devices.pop(key, None)
        if not dev:
            continue
        skey = dev.ipv6 or f"name:{_clean_inst_name(dev.txt_name or '')}"
        seen.discard(skey)
        reason = "goodbye" if (dev.ipv6 and norm_ipv6(dev.ipv6) in goodbye) else "stale"
        log(f"  - {dev.ipv6 or '(no IPv6)'}  name={dev.display_name()!r} ({reason})")
    return len(to_remove)


def _filter_find_results(devices: dict[str, FoundDevice]) -> list[FoundDevice]:
    results = finalize_discover_devices(devices)
    results = [
        d for d in results
        if d.txt_name or d.service_types or d.ipv6 or d.query_only or d.awdl_neighbor
    ]
    for dev in results:
        if dev.txt_name and (dev.query_only or dev.modern_ios or dev.has_tls_airdrop):
            dev.discoverable = True
    return results


def _run_tls_discover_pass(
    results: list[FoundDevice],
    iface: str,
    *,
    key_dir: Path,
    ca: Path | None,
    timeout: float,
    do_discover: bool,
    stop: _FindStop | None = None,
) -> None:
    if not do_discover:
        return
    if stop and stop.requested:
        log("skipping TLS /Discover (scan interrupted)", level="dbg")
        return
    for dev in results:
        if stop and stop.requested:
            log("TLS /Discover interrupted", level="dbg")
            break
        if not dev.ipv6:
            continue
        if dev.modern_ios:
            if dev.txt_name:
                dev.discoverable = True
            log(f"{dev.ipv6} iOS modern — skip TLS :8770", level="dbg")
            continue
        tls_port = dev.port if dev.has_tls_airdrop else DEFAULT_TLS_PORT
        if not dev.has_tls_airdrop and not probe_port(dev.ipv6, tls_port, iface, 1.0):
            log(f"{dev.ipv6}:{tls_port} not listening — skip /Discover", level="dbg")
            if dev.txt_name:
                dev.discoverable = True
            continue
        if dev.flags and not (dev.flags & RECEIVER_FLAG_DISCOVER):
            log(f"{dev.ipv6} flags=0x{dev.flags:x} — skip /Discover", level="dbg")
            if dev.txt_name:
                dev.discoverable = True
            continue
        resp = tls_discover(dev.ipv6, tls_port, iface, key_dir=key_dir, ca_file=ca, timeout=timeout)
        if resp:
            dev.discover_name = resp.get("ReceiverComputerName")
            dev.discoverable = dev.discover_name is not None
            caps = resp.get("ReceiverMediaCapabilities")
            if isinstance(caps, str):
                try:
                    caps = json.loads(caps)
                except json.JSONDecodeError:
                    caps = None
            if isinstance(caps, dict):
                apple = caps.get("Vendor", {}).get("com.apple", {})
                ver = apple.get("OSVersion")
                build = apple.get("OSBuildVersion")
                if ver and build:
                    dev.os_info = f"{'.'.join(map(str, ver))} ({build})"
        elif dev.txt_name:
            dev.discoverable = True


def _mdns_lfilter(pkt) -> bool:
    try:
        from scapy.all import DNS, UDP  # type: ignore
    except ImportError:
        return False
    if not pkt.haslayer(DNS):
        return False
    if pkt.haslayer(UDP):
        u = pkt[UDP]
        return u.sport == MDNS_PORT or u.dport == MDNS_PORT
    return True


def find_devices(
    iface: str,
    *,
    duration: float = 5.0,
    hci: str = "hci0",
    ble_wake: bool = True,
    do_discover: bool = True,
    timeout: float = 8.0,
    continuous: bool = True,
) -> list[FoundDevice]:
    """BLE wake + mDNS loop until Ctrl+C (default), then save candidates."""
    try:
        from scapy.all import sniff  # type: ignore
    except ImportError:
        log("scapy required for find — pip install scapy", level="err")
        return []

    key_dir = resolve_key_dir()
    ca = resolve_ca_file()
    devices: dict[str, FoundDevice] = {}
    hostmap: dict[str, str] = {}
    beacon: BleWakeBeacon | None = None
    seen: set[str] = set()
    stop = _FindStop()
    stop.install()
    interrupted = False

    if ble_wake and not stop.requested:
        beacon = BleWakeBeacon(hci)
        beacon.start(refresh_s=15.0)
        log(f"BLE wake on {hci} — waiting for beacon ...")
        if beacon.wait_ready(8.0) and not stop.requested:
            for _ in range(20):
                if stop.requested:
                    break
                time.sleep(0.1)
        elif not stop.requested:
            log("BLE wake slow — continuing mDNS anyway", level="dbg")

    if stop.requested:
        interrupted = True
    elif continuous:
        log(f"find loop on {iface} — wake + mDNS every {duration}s (Ctrl+C to stop and save)")
    else:
        log(f"mDNS listen {duration}s on {iface} ...")

    scan = 0
    try:
        while not stop.requested:
            scan += 1
            _mdns_send_browse(iface)
            chunk_timeout = duration if not continuous else max(0.5, duration)
            if not continuous:
                deadline = time.time() + duration
            else:
                deadline = time.time() + chunk_timeout

            chunk_pkts = 0
            goodbye: set[str] = set()
            while time.time() < deadline and not stop.requested:
                remain = deadline - time.time()
                if remain <= 0:
                    break
                try:
                    pkts = sniff(
                        iface=iface,
                        filter="udp port 5353",
                        timeout=min(0.5, max(0.15, remain)),
                        store=True,
                        lfilter=_mdns_lfilter,
                    )
                except KeyboardInterrupt:
                    stop.requested = True
                    interrupted = True
                    break
                except Exception as exc:
                    log(f"mDNS sniff: {exc}", level="dbg")
                    break
                chunk_pkts += len(pkts)
                for pkt in pkts:
                    _ingest_mdns_packet(pkt, devices, hostmap, now=time.time(), goodbye=goodbye)
                    if config.DEBUG:
                        md = describe_mdns_pkt(pkt)
                        if md:
                            log(f"  {md}", level="dbg")

            if stop.requested:
                break

            now = time.time()
            current_neighbors: set[str] = set()
            for neigh in enum_neighbors(iface):
                nk = norm_ipv6(neigh)
                current_neighbors.add(nk)
                if nk not in devices:
                    devices[nk] = FoundDevice(ipv6=nk, awdl_neighbor=True, source="ip-neigh")
                    devices[nk].last_seen = now
                    log(f"ip neigh seed {nk}", level="dbg")
                else:
                    devices[nk].last_seen = now

            # expire devices that closed AirDrop (goodbye) or went silent
            stale_after = max(15.0, duration * 3)
            removed = _prune_stale(devices, now, stale_after, goodbye, current_neighbors, seen)

            results = _filter_find_results(devices)
            for dev in results:
                key = dev.ipv6 or f"name:{_clean_inst_name(dev.txt_name or '')}"
                if key not in seen:
                    seen.add(key)
                    addr = dev.ipv6 or "(no IPv6 yet)"
                    log(f"  + {addr}  name={dev.display_name()!r}")

            if continuous:
                log(
                    f"scan #{scan}: {len(results)} device(s), {chunk_pkts} pkts, "
                    f"-{removed} expired this round — Ctrl+C to save"
                )
            else:
                log(f"mDNS captured {chunk_pkts} packets", level="dbg")
                break

    except KeyboardInterrupt:
        stop.requested = True
        interrupted = True
    finally:
        stop.restore()
        if beacon:
            beacon.stop()

    if interrupted or stop.requested:
        log("stopped — finalizing ...")

    results = _filter_find_results(devices)
    try:
        _run_tls_discover_pass(
            results, iface, key_dir=key_dir, ca=ca, timeout=timeout,
            do_discover=do_discover, stop=stop,
        )
    except KeyboardInterrupt:
        log("TLS /Discover interrupted", level="dbg")
    return results


def describe_mdns_pkt(pkt) -> str | None:
    try:
        from scapy.all import DNS  # type: ignore
    except ImportError:
        return None
    if not pkt.haslayer(DNS):
        return None
    lines: list[str] = []
    dns = pkt[DNS]
    if dns.qr == 0 and dns.qd is not None:
        for q in dns.qd:
            lines.append(f"QUERY {_dns_name(q.qname)} type={q.qtype}")
    for sec, rrs in (("ANS", dns.an), ("ADD", dns.ar)):
        if not rrs:
            continue
        for rr in rrs:
            rname = _dns_name(rr.rrname)
            if rr.type == 16:
                lines.append(f"{sec} {rname} TXT={_parse_txt_rdata(rr.rdata)}")
            elif rr.type == 33:
                lines.append(f"{sec} {rname} SRV port={rr.port} -> {_dns_name(rr.target)}")
            elif rr.type == 28:
                lines.append(f"{sec} {rname} AAAA={rr.rdata}")
    return " | ".join(lines) if lines else None


def print_found_devices(devices: list[FoundDevice]) -> None:
    if not devices:
        log("no AirDrop peers found — open AirDrop share sheet on target + BLE wake", level="warn")
        return
    log(f"=== {len(devices)} device(s) ===")
    for i, dev in enumerate(devices):
        name = dev.display_name()
        if dev.discover_name:
            disc = "yes"
        elif dev.txt_name and not dev.query_only:
            disc = "mdns"
        elif dev.query_only and not dev.ipv6:
            disc = "query-only"
        elif dev.source == "mdns-query":
            disc = "query-only"
        elif dev.awdl_neighbor:
            disc = "awdl-neigh"
        elif dev.txt_name:
            disc = "hint"
        else:
            disc = "no"
        extra = []
        if dev.modern_ios:
            extra.append("ios-modern")
        if dev.prepair_port:
            extra.append(f"prepair:{dev.prepair_port}")
        if dev.clink_port:
            extra.append(f"clink:{dev.clink_port}")
        if dev.asquic_port:
            extra.append(f"asquic:{dev.asquic_port}")
        if dev.has_tls_airdrop and dev.port:
            extra.append(f"tls:{dev.port}")
        if dev.service_id:
            sid = dev.service_id
            extra.append(f"id={sid[:8]}…" if len(sid) > 8 else f"id={sid}")
        if dev.query_only and not dev.ipv6:
            extra.append("seen in mDNS QUERY only — open AirDrop on that device")
        elif dev.awdl_neighbor and not dev.txt_name:
            extra.append("AWDL neighbor — open AirDrop share sheet for name")
        if dev.os_info:
            extra.append(dev.os_info)
        suffix = f"  ({', '.join(extra)})" if extra else ""
        addr = dev.ipv6 or "(no IPv6 yet)"
        log(f"  [{i}] {addr}  name={name!r}  discoverable={disc}{suffix}")
