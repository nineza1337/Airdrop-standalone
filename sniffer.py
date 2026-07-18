"""Live capture of all traffic to/from one IPv6 peer, with pcap export.

Filters on-air packets by IPv6 host (src or dst) and writes a .pcap that opens
directly in Wireshark. Two capture engines:

  tcpdump  (default when available) — lossless kernel capture with full snaplen
           and a large ring buffer; reports kernel drops. Best for completeness.
  scapy    — software-filtered capture with per-packet hexdump and seen/matched
           counters. Best for live inspection and diagnosing empty captures.
"""

from __future__ import annotations

import shlex
import shutil
import signal
import subprocess
import time
from pathlib import Path

from config import log
from netutil import enum_neighbors, norm_ipv6


def _build_bpf(host: str, peer_n: str | None, extra: str | None) -> str:
    base = f"ip6 host {host} and ip6 host {peer_n}" if peer_n else f"ip6 host {host}"
    if extra:
        base = f"({base}) and ({extra})"
    return base


def _file_size(path: Path | None) -> str:
    if not path:
        return "0 B"
    try:
        size = float(path.stat().st_size)
    except OSError:
        return "0 B"
    for unit in ("B", "KB", "MB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def _hexdump(data: bytes, width: int = 16, max_bytes: int = 2048) -> str:
    lines: list[str] = []
    view = data[:max_bytes]
    for off in range(0, len(view), width):
        chunk = view[off : off + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"    {off:04x}  {hex_part:<{width * 3}}  {ascii_part}")
    if len(data) > max_bytes:
        lines.append(f"    ... ({len(data) - max_bytes} more bytes)")
    return "\n".join(lines)


def _proto_label(pkt) -> str:
    if pkt.haslayer("UDP"):
        u = pkt["UDP"]
        return f"UDP {u.sport}->{u.dport}"
    if pkt.haslayer("TCP"):
        t = pkt["TCP"]
        return f"TCP {t.sport}->{t.dport} [{t.sprintf('%TCP.flags%')}]"
    try:
        return pkt.lastlayer().name
    except Exception:
        return "?"


def _extract_payload(pkt) -> bytes:
    try:
        from scapy.all import Raw  # type: ignore
    except ImportError:
        return b""
    if pkt.haslayer(Raw):
        return bytes(pkt[Raw].load)
    for layer in ("UDP", "TCP"):
        if pkt.haslayer(layer):
            payload = pkt[layer].payload
            if payload:
                return bytes(payload)
    return b""


def _print_packet(pkt, idx: int, host: str, show_payload: bool) -> None:
    ts = time.strftime("%H:%M:%S")
    ip6 = pkt["IPv6"] if pkt.haslayer("IPv6") else None
    src = norm_ipv6(ip6.src) if ip6 else "?"
    dst = norm_ipv6(ip6.dst) if ip6 else "?"
    arrow = "->" if src == host else "<-"
    length = len(bytes(pkt))
    log(f"#{idx} {ts} {src} {arrow} {dst}  {_proto_label(pkt)}  {length}B")
    if show_payload:
        payload = _extract_payload(pkt)
        if payload:
            log(_hexdump(payload))


def sniff_device(
    iface: str,
    target: str,
    *,
    peer: str | None = None,
    write: Path | None = None,
    duration: float = 0.0,
    count: int = 0,
    show_payload: bool = True,
    extra_filter: str | None = None,
    engine: str = "auto",
    buffer_kb: int = 8192,
) -> None:
    """
    Capture on-air packets involving `target` IPv6.

    peer         second IPv6; when set, capture only traffic BETWEEN target and
                 peer (both directions). When None, capture all traffic to/from
                 target.
    write        pcap output path (opens in Wireshark); None = display only
    duration     stop after N seconds (0 = until Ctrl+C)
    count        stop after N packets (0 = unlimited)
    show_payload print raw payload hexdump per packet (scapy engine only)
    extra_filter additional BPF expression, ANDed with the host filter
    engine       "auto" (tcpdump if present, else scapy), "tcpdump", or "scapy"
    buffer_kb    tcpdump kernel ring-buffer size in KiB (larger = fewer drops)
    """
    host = norm_ipv6(target)
    peer_n = norm_ipv6(peer) if peer else None

    # Sanity: are these addresses actually current AWDL neighbors? Catches typos.
    try:
        neighbors = set(enum_neighbors(iface))
    except Exception:
        neighbors = set()
    for label, addr in (("target", host), ("peer", peer_n)):
        if addr and neighbors and addr not in neighbors:
            log(
                f"{label} {addr} is NOT a current AWDL neighbor "
                f"(known: {sorted(neighbors)}) — check for a typo or open AirDrop on it",
                level="warn",
            )

    have_tcpdump = shutil.which("tcpdump") is not None
    use_tcpdump = engine == "tcpdump" or (engine == "auto" and have_tcpdump)
    if engine == "tcpdump" and not have_tcpdump:
        log("tcpdump not found — falling back to scapy engine", level="warn")
        use_tcpdump = False

    if use_tcpdump:
        _sniff_tcpdump(
            iface,
            _build_bpf(host, peer_n, extra_filter),
            host,
            peer_n,
            write=write,
            duration=duration,
            count=count,
            buffer_kb=buffer_kb,
        )
        return

    _sniff_scapy(
        iface, host, peer_n,
        write=write, duration=duration, count=count,
        show_payload=show_payload, extra_filter=extra_filter,
    )


def _sniff_tcpdump(
    iface: str,
    bpf: str,
    host: str,
    peer_n: str | None,
    *,
    write: Path | None,
    duration: float,
    count: int,
    buffer_kb: int,
) -> None:
    """Lossless capture via tcpdump: full snaplen, large ring buffer, drop report."""
    tcpdump = shutil.which("tcpdump")
    cmd = [tcpdump, "-i", iface, "-n", "-s", "0", "-U", "-B", str(buffer_kb)]
    if count:
        cmd += ["-c", str(count)]
    if write:
        cmd += ["-w", str(write)]
    cmd += shlex.split(bpf)

    scope = f"between {host} <-> {peer_n}" if peer_n else f"to/from {host}"
    log(f"sniff on {iface} — {scope}  engine=tcpdump  buf={buffer_kb}KiB")
    log(f"  filter: {bpf}")
    log("  Ctrl+C to stop" + (f"; auto-stop {duration:.0f}s" if duration > 0 else ""))

    # display-only: let tcpdump own the terminal; write mode: capture stats + heartbeat
    pipe = subprocess.PIPE if write else None
    try:
        proc = subprocess.Popen(cmd, stdout=pipe, stderr=pipe, text=True)
    except OSError as exc:
        log(f"failed to launch tcpdump: {exc}", level="err")
        return

    start = time.time()
    last_report = start
    try:
        while proc.poll() is None:
            time.sleep(0.3)
            if duration > 0 and time.time() - start >= duration:
                proc.send_signal(signal.SIGINT)
                break
            if write and time.time() - last_report >= 5.0:
                log(f"capturing… {_file_size(write)} written (Ctrl+C to stop)")
                last_report = time.time()
    except KeyboardInterrupt:
        log("Ctrl+C — stopping tcpdump")
        try:
            proc.send_signal(signal.SIGINT)
        except Exception:
            pass

    try:
        _out, err = proc.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        _out, err = proc.communicate()

    dropped = 0
    for line in (err or "").splitlines():
        line = line.strip()
        if not line:
            continue
        if any(k in line for k in ("captured", "received by filter", "dropped by kernel")):
            log(f"tcpdump: {line}")
        if "dropped by kernel" in line:
            head = line.split()[0]
            if head.isdigit():
                dropped = int(head)

    if write:
        log(f"saved -> {write} ({_file_size(write)})")
    if dropped > 0:
        log(
            f"{dropped} packet(s) dropped by kernel — increase --buffer "
            f"(current {buffer_kb}KiB) for a more complete capture",
            level="warn",
        )
    elif write:
        log("0 kernel drops — capture is complete for what reached this interface")


def _sniff_scapy(
    iface: str,
    host: str,
    peer_n: str | None,
    *,
    write: Path | None,
    duration: float,
    count: int,
    show_payload: bool,
    extra_filter: str | None,
) -> None:
    """Software-filtered capture with live hexdump and seen/matched diagnostics."""
    try:
        from scapy.all import AsyncSniffer, PcapWriter  # type: ignore
    except ImportError:
        log("scapy required for sniff — pip install scapy", level="err")
        return

    hosts = {host, peer_n} if peer_n else {host}

    # Host filtering is done in software so we can also count total traffic seen
    # (essential for diagnosing 'captured 0'). extra_filter is passed as BPF.
    bpf = extra_filter or None

    writer = {"w": None}
    stats = {"total": 0, "matched": 0, "bytes": 0}

    def _match(pkt) -> bool:
        if not pkt.haslayer("IPv6"):
            return False
        ip6 = pkt["IPv6"]
        src = norm_ipv6(ip6.src)
        dst = norm_ipv6(ip6.dst)
        if peer_n:
            return src in hosts and dst in hosts
        return src == host or dst == host

    def _on_packet(pkt) -> None:
        stats["total"] += 1
        if not _match(pkt):
            return
        stats["matched"] += 1
        stats["bytes"] += len(bytes(pkt))
        if write:
            if writer["w"] is None:
                # open lazily so the pcap link-layer type is inferred from a real packet
                writer["w"] = PcapWriter(str(write), append=False, sync=True)
            writer["w"].write(pkt)
        _print_packet(pkt, stats["matched"], host, show_payload)

    scope = f"between {host} <-> {peer_n}" if peer_n else f"to/from {host}"
    log(
        f"sniff on {iface} — {scope}"
        + (f"  bpf={bpf!r}" if bpf else "")
        + (f"  -> {write}" if write else "  (display only)")
    )
    if peer_n:
        log("note: --peer captures only unicast between the two — trigger an AirDrop "
            "transfer to generate it (idle traffic is mostly multicast mDNS)")
    log("Ctrl+C to stop" + (f"; auto-stop {duration:.0f}s" if duration > 0 else ""))

    try:
        sniffer = AsyncSniffer(iface=iface, filter=bpf, prn=_on_packet, store=False)
        sniffer.start()
    except Exception as exc:
        log(f"sniffer failed to start: {exc}", level="err")
        if writer["w"] is not None:
            writer["w"].close()
        return

    try:
        deadline = time.time() + duration if duration > 0 else None
        last_report = time.time()
        while True:
            if deadline and time.time() >= deadline:
                break
            if count and stats["matched"] >= count:
                break
            time.sleep(0.2)
            if time.time() - last_report >= 5.0:
                log(
                    f"listening… seen={stats['total']} matched={stats['matched']} "
                    "(Ctrl+C to stop)"
                )
                last_report = time.time()
    except KeyboardInterrupt:
        log("Ctrl+C — stopping sniff")
    finally:
        try:
            sniffer.stop()
        except Exception as exc:
            log(f"sniffer stop: {exc}", level="dbg")
        if writer["w"] is not None:
            writer["w"].close()
        log(
            f"captured {stats['matched']} matched / {stats['total']} seen, "
            f"{stats['bytes']} bytes" + (f" -> {write}" if write else "")
        )
        # Evidence-based diagnosis of an empty capture
        if stats["total"] == 0:
            log(
                "0 packets reached scapy on this interface — owl is likely not "
                "decapsulating AWDL data frames onto awdl0 (see its 'unhandled frame' "
                "warnings). Confirm with: sudo tcpdump -i awdl0 -n",
                level="warn",
            )
        elif stats["matched"] == 0:
            log(
                "traffic was seen but none matched — verify the IPv6 address(es); "
                "in --peer mode unicast only flows during an active AirDrop transfer",
                level="warn",
            )
