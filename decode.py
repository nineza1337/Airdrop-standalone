#!/usr/bin/env python3
"""
Decode an AWDL/AirDrop capture (owl raw-802.11 pcap or awdl0 IPv6 pcap).

Pipeline:
  1. Yield IPv6 packets. For 802.11 data frames the IPv6 header is found by
     anchoring on the Apple SNAP (aa aa 03 00 17 f2) then the 0x86dd ethertype,
     which is robust to QoS vs non-QoS framing (no fixed 16-byte skip needed).
  2. Reassemble TCP streams per direction (companion-link lives here).
  3. Extract companion-link identity: DNS-SD names + AirDrop TXT keys
     (dnm/sid/sn/...), embedded link-local addresses, message types.
  4. Summarise QUIC (asquic) connections.

Usage:
  python3 decode.py owl.pcap
  python3 decode.py owl.pcap --strings        # also dump raw printable runs
  python3 decode.py a_2.pcap --min-flow 200
"""

from __future__ import annotations

import argparse
import re
from collections import Counter, defaultdict

APPLE_SNAP = b"\xaa\xaa\x03\x00\x17\xf2"
IPV6_ETHERTYPE = b"\x86\xdd"
CLINK_MAGIC = bytes.fromhex("e1435f7064")

TXT_KEY_RE = re.compile(
    rb"(sn|sid|at|dnm|flags|rpFl|rpAD|rpBA|rpVr|model|name)=([^\x00-\x1f=]{1,80})"
)


def extract_ipv6_bytes(pkt) -> bytes | None:
    """Pull the IPv6 header+payload out of an 802.11 AWDL data frame."""
    from scapy.layers.dot11 import Dot11  # type: ignore

    if not pkt.haslayer(Dot11):
        return None
    blob = bytes(pkt[Dot11].payload)
    snap = blob.find(APPLE_SNAP)
    if snap < 0:
        return None
    et = blob.find(IPV6_ETHERTYPE, snap, snap + 24)
    if et < 0:
        return None
    ip6 = blob[et + 2 :]
    if not ip6 or (ip6[0] >> 4) != 6:
        return None
    return ip6


def iter_ipv6(path):
    """Yield scapy IPv6 packets from either an 802.11 or an Ethernet/IPv6 pcap."""
    from scapy.all import rdpcap, IPv6  # type: ignore
    from scapy.layers.dot11 import Dot11  # type: ignore

    pkts = rdpcap(path)
    is_dot11 = bool(pkts) and pkts[0].haslayer(Dot11)
    out = []
    for p in pkts:
        ts = float(p.time)
        if is_dot11:
            raw = extract_ipv6_bytes(p)
            if raw:
                try:
                    out.append((ts, IPv6(raw)))
                except Exception:
                    continue
        elif p.haslayer(IPv6):
            out.append((ts, p[IPv6]))
    return out, is_dot11


def reassemble_tcp(ipv6_list):
    """Group TCP payloads into per-direction streams keyed by 4-tuple."""
    from scapy.all import TCP  # type: ignore

    flows = defaultdict(dict)  # (src,sport,dst,dport) -> {seq: payload}
    for _ts, ip6 in ipv6_list:
        if TCP not in ip6:
            continue
        t = ip6[TCP]
        payload = bytes(t.payload)
        if not payload:
            continue
        key = (ip6.src, t.sport, ip6.dst, t.dport)
        # keep the longest payload seen for a given seq (retransmits/overlap)
        prev = flows[key].get(t.seq)
        if prev is None or len(payload) > len(prev):
            flows[key][t.seq] = payload
    streams = {}
    for key, segs in flows.items():
        data = b"".join(segs[s] for s in sorted(segs))
        streams[key] = data
    return streams


def extract_dns_names(blob: bytes) -> list[str]:
    """Reconstruct dotted DNS/DNS-SD names from length-prefixed labels."""
    names: list[str] = []
    i = 0
    n = len(blob)
    while i < n:
        b = blob[i]
        if b == 0 or b == 0xC0:  # end of name / compression pointer
            i += 1
            continue
        if 1 <= b <= 63 and i + 1 + b <= n:
            label = blob[i + 1 : i + 1 + b]
            if all(32 <= c < 127 for c in label):
                # greedily consume following labels to build a full name
                parts = [label.decode("ascii")]
                j = i + 1 + b
                while j < n and 1 <= blob[j] <= 63 and j + 1 + blob[j] <= n:
                    ln = blob[j]
                    lbl = blob[j + 1 : j + 1 + ln]
                    if not all(32 <= c < 127 for c in lbl):
                        break
                    parts.append(lbl.decode("ascii"))
                    j += 1 + ln
                name = ".".join(parts)
                if len(name) >= 4 and any(ch.isalpha() for ch in name):
                    names.append(name)
                i = j
                continue
        i += 1
    # dedupe, keep order
    seen = set()
    uniq = []
    for x in names:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


def extract_link_local(blob: bytes) -> list[str]:
    """Find embedded fe80::/64 addresses (AAAA rdata) in a companion-link blob."""
    out = []
    for m in re.finditer(rb"\xfe\x80\x00\x00\x00\x00\x00\x00", blob):
        off = m.start()
        raw = blob[off : off + 16]
        if len(raw) < 16:
            continue
        groups = [f"{raw[k]:02x}{raw[k+1]:02x}" for k in range(0, 16, 2)]
        addr = ":".join(groups)
        try:
            import ipaddress

            comp = ipaddress.ip_address(addr).compressed
            if comp.startswith("fe80:") and comp not in out:
                out.append(comp)
        except ValueError:
            continue
    return out


def extract_txt(blob: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in TXT_KEY_RE.finditer(blob):
        key = m.group(1).decode("ascii")
        val = m.group(2).decode("utf-8", "replace")
        out.setdefault(key, val)
    return out


def companion_link_report(streams) -> None:
    print("\n=== COMPANION-LINK (TCP) FLOWS ===")
    # merge two directions into conversations
    convos = defaultdict(list)
    for (src, sport, dst, dport), data in streams.items():
        pair = tuple(sorted([(src, sport), (dst, dport)]))
        convos[pair].append((src, sport, dst, dport, data))

    for pair, dirs in sorted(convos.items(), key=lambda kv: -sum(len(d[4]) for d in kv[1])):
        total = sum(len(d[4]) for d in dirs)
        has_clink = any(CLINK_MAGIC in d[4] for d in dirs)
        tag = "companion-link" if has_clink else "tcp"
        (a_ip, a_port), (b_ip, b_port) = pair
        print(f"\n  [{tag}] {a_ip}:{a_port} <-> {b_ip}:{b_port}  ({total} stream bytes)")

        merged = b"".join(d[4] for d in dirs)
        # message types by magic position (type is 4 bytes before the magic)
        types = Counter()
        for d in dirs:
            data = d[4]
            pos = data.find(CLINK_MAGIC)
            while pos != -1:
                t = data[pos - 4] if pos >= 4 else -1
                types[t] += 1
                pos = data.find(CLINK_MAGIC, pos + 1)
        if types:
            name = {0x05: "INIT", 0x06: "ACK"}
            desc = ", ".join(f"{name.get(t, hex(t))}={c}" for t, c in types.most_common())
            print(f"    companion-link messages: {desc}")

        txt = extract_txt(merged)
        if txt:
            print("    AirDrop / TXT records:")
            labels = {
                "dnm": "device name", "sid": "service id", "sn": "service",
                "model": "model", "at": "auth token", "flags": "flags",
                "rpVr": "version", "name": "name",
            }
            for k, v in txt.items():
                print(f"      {labels.get(k, k):12s}: {v}")

        names = extract_dns_names(merged)
        # drop TXT-record bleed (contains '=' or the _dns-sd meta-service)
        names = [x for x in names if "=" not in x and "_dns-sd" not in x]
        svc = [x for x in names if x.startswith("_") or ".local" in x]
        inst = [x for x in names if x not in svc]
        if svc:
            print(f"    DNS-SD services: {', '.join(sorted(set(svc))[:12])}")
        if inst:
            print(f"    instance/host names: {', '.join(sorted(set(inst))[:12])}")

        lls = extract_link_local(merged)
        if lls:
            print(f"    embedded link-local: {', '.join(lls[:8])}")


def quic_report(ipv6_list) -> None:
    from scapy.all import UDP, Raw  # type: ignore

    print("\n=== asquic (QUIC/UDP) ===")
    versions = Counter()
    dcids = Counter()
    initials = Counter()
    servers = Counter()
    short = 0
    for _ts, ip6 in ipv6_list:
        if UDP not in ip6 or Raw not in ip6:
            continue
        load = bytes(ip6[Raw].load)
        if not load:
            continue
        b0 = load[0]
        if (b0 & 0xC0) == 0xC0 and len(load) >= 6:
            versions[load[1:5].hex()] += 1
            dcids[load[5]] += 1
            initials[(ip6.src, ip6.dst)] += 1
            servers[(ip6.dst, ip6[UDP].dport)] += 1
        elif (b0 & 0xC0) == 0x40:
            short += 1
    print(f"  versions: {dict(versions)}  DCID lengths: {dict(dcids)}")
    print(f"  long-header Initials: {sum(initials.values())}  short-header (1-RTT data): {short}")
    if servers:
        print("  QUIC server ports (dst of Initials):")
        for (host, port), c in servers.most_common(8):
            print(f"    {host}:{port}  {c}")


def strings_report(streams) -> None:
    print("\n=== RAW PRINTABLE RUNS (TCP streams) ===")
    printable = re.compile(rb"[\x20-\x7e]{5,}")
    hits = Counter()
    for data in streams.values():
        for m in printable.finditer(data):
            hits[m.group().decode("ascii", "replace")] += 1
    for s, c in hits.most_common(50):
        print(f"  x{c:<3d} {s!r}")


def upload_path_report(ipv6_list, streams) -> None:
    """Summarise whether the capture used legacy TLS :8770 or modern asquic."""
    from scapy.all import TCP, UDP  # type: ignore

    tls8770 = udp_asquic = tcp_ephemeral = 0
    for _ts, ip6 in ipv6_list:
        if TCP in ip6:
            t = ip6[TCP]
            if 8770 in (t.sport, t.dport):
                tls8770 += 1
            elif t.payload:
                tcp_ephemeral += 1
        elif UDP in ip6 and ip6[UDP].payload:
            udp_asquic += 1

    print("\n=== UPLOAD PATH DIAGNOSIS ===")
    print(f"  TCP packets involving :8770 (legacy TLS /Ask+/Upload): {tls8770}")
    print(f"  TCP data on ephemeral ports (companion-link): {tcp_ephemeral}")
    print(f"  UDP data packets (asquic): {udp_asquic}")
    if tls8770 == 0 and (tcp_ephemeral or udp_asquic):
        print(
            "  >> No :8770 in capture — Apple devices transferred via companion-link + asquic.\n"
            "     Kali/opendrop /Ask may still hit :8770, but /Upload body often fails unless\n"
            "     sent as Expect:100-continue + chunked; iPhone may require the modern path."
        )
    elif tls8770:
        print("  >> Legacy TLS :8770 traffic present — inspect decrypted HTTP in Wireshark (TLS keys).")


def main() -> None:
    ap = argparse.ArgumentParser(description="Decode AWDL/AirDrop pcap (owl raw-802.11 or awdl0 IPv6)")
    ap.add_argument("pcap", help="capture file (owl.pcap or awdl0 .pcap)")
    ap.add_argument("--strings", action="store_true", help="dump raw printable runs from TCP streams")
    args = ap.parse_args()

    ipv6_list, is_dot11 = iter_ipv6(args.pcap)
    print(f"=== {args.pcap} ===")
    print(f"source: {'802.11 (owl raw)' if is_dot11 else 'awdl0 IPv6'}   IPv6 packets: {len(ipv6_list)}")

    streams = reassemble_tcp(ipv6_list)
    upload_path_report(ipv6_list, streams)
    companion_link_report(streams)
    quic_report(ipv6_list)
    if args.strings:
        strings_report(streams)


if __name__ == "__main__":
    main()
