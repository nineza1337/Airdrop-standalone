"""QUIC v1 Initial decrypt + TLS ClientHello parse (poke / asquic captures)."""

from __future__ import annotations

import struct
from typing import Any

from aioquic.buffer import Buffer
from aioquic.quic.crypto import CryptoPair
from aioquic.quic.packet import QuicProtocolVersion, pull_quic_header

# From lab pcap — QUIC connection IDs anonymized for public release
POKE_QUIC_PROFILE = {
    "version": QuicProtocolVersion.VERSION_1,
    "alpn": ["h3"],
    "dcid_lengths": (4, 8),
    "scid_length": 4,
    "initial_mtu": 1200,
    "example_flows": [
        {
            "role": "receiver_client",
            "src_port": 59851,
            "dst_port": 60170,
            "dcid": "xxxxxxxxxxxxxxxx",  # redacted from capture
            "scid": "xxxxxxxx",
        },
        {
            "role": "sender_server",
            "src_port": 60170,
            "dst_port": 59851,
            "dcid": "xxxxxxxx",
            "scid": "xxxxxxxx",
        },
    ],
}


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    prefix = first >> 6
    if prefix == 0:
        return first & 0x3F, offset + 1
    if prefix == 1:
        return ((first & 0x3F) << 8) | data[offset + 1], offset + 2
    if prefix == 2:
        val = first & 0x3F
        for i in range(4):
            val = (val << 8) | data[offset + 1 + i]
        return val, offset + 5
    val = first & 0x3F
    for i in range(8):
        val = (val << 8) | data[offset + 1 + i]
    return val, offset + 9


def reassemble_crypto(payload: bytes) -> bytes:
    parts: list[tuple[int, bytes]] = []
    o = 0
    while o < len(payload):
        ftype = payload[o]
        o += 1
        if ftype == 0x06:
            off, o = read_varint(payload, o)
            ln, o = read_varint(payload, o)
            parts.append((off, payload[o : o + ln]))
            o += ln
        elif ftype == 0x00:
            while o < len(payload) and payload[o] == 0:
                o += 1
        else:
            break
    parts.sort(key=lambda x: x[0])
    return b"".join(d for _, d in parts)


def parse_quic_client_hello(crypto: bytes) -> dict[str, Any] | None:
    """QUIC CRYPTO carries TLS handshake without TLS record layer."""
    if len(crypto) < 4 or crypto[0] != 0x01:
        return None
    mlen = (crypto[1] << 16) | (crypto[2] << 8) | crypto[3]
    hs = crypto[4 : 4 + mlen]
    if len(hs) < 35:
        return None
    sid_len = hs[34]
    p = 35 + sid_len
    if p + 2 > len(hs):
        return None
    cs_len = struct.unpack("!H", hs[p : p + 2])[0]
    p += 2 + cs_len
    comp_len = hs[p]
    p += 1 + comp_len
    if p + 2 > len(hs):
        return None
    ext_total = struct.unpack("!H", hs[p : p + 2])[0]
    p += 2
    end = min(p + ext_total, len(hs))
    alpn: list[str] = []
    sni: list[str] = []
    while p + 4 <= end:
        etype, elen = struct.unpack("!HH", hs[p : p + 4])
        edata = hs[p + 4 : p + 4 + elen]
        if etype == 0x0010:
            q = 0
            if len(edata) >= 2:
                list_len = struct.unpack("!H", edata[0:2])[0]
                q = 2
                list_end = min(2 + list_len, len(edata))
                while q < list_end:
                    ln = edata[q]
                    q += 1
                    alpn.append(edata[q : q + ln].decode("ascii", errors="replace"))
                    q += ln
        elif etype == 0x0000 and len(edata) > 5:
            nl = struct.unpack("!H", edata[3:5])[0]
            sni.append(edata[5 : 5 + nl].decode("ascii", errors="replace"))
        p += 4 + elen
    return {"alpn": alpn, "sni": sni, "client_hello_len": len(hs)}


def decrypt_initial_packet(data: bytes) -> dict[str, Any] | None:
    if len(data) < 7 or data[1:5] != b"\x00\x00\x00\x01":
        return None
    buf = Buffer(data=data)
    hdr = pull_quic_header(buf)
    if hdr.packet_type.name != "INITIAL":
        return None
    enc = buf.tell()
    for is_client, exp_pn in ((False, 0), (False, 1), (True, 0), (True, 1)):
        cp = CryptoPair(lambda _t: None, lambda _t: None)
        cp.setup_initial(hdr.destination_cid, is_client=is_client, version=QuicProtocolVersion.VERSION_1)
        try:
            _plain, payload, pn = cp.decrypt_packet(data, enc, exp_pn)
        except Exception:
            continue
        crypto = reassemble_crypto(payload)
        tls = parse_quic_client_hello(crypto)
        if tls and (tls["alpn"] or tls["sni"]):
            return {
                "dcid": hdr.destination_cid.hex(),
                "dcid_len": len(hdr.destination_cid),
                "scid": hdr.source_cid.hex(),
                "scid_len": len(hdr.source_cid),
                "decrypt_is_client": is_client,
                "pn": pn,
                "crypto_len": len(crypto),
                "tls": tls,
            }
    return None
