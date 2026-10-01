"""
Byte-level protocol dissection.

This module walks a captured frame one header at a time, exactly the way a
receiver on the network does, and records what it finds as a list of layers.

    Ethernet   ->  VLAN  ->  IPv4/IPv6  ->  TCP/UDP/ICMP  ->  payload
                        \\-> ARP

Design notes
------------
* Everything is done on raw bytes with ``struct``. No scapy, no dependencies.
  That keeps the logic short enough to read in one sitting, and it works for
  any capture source (live socket, pcap file, hex dump).
* Each layer is appended to :attr:`PacketInfo.layers` as
  ``(name, {field: value})`` so the display layer can print an indented
  protocol tree without this module knowing anything about formatting.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Optional

from . import appproto

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58

IP_PROTO_NAMES = {
    0: "HOPOPT", 1: "ICMP", 2: "IGMP", 3: "GGP", 4: "IPv4", 6: "TCP", 8: "EGP",
    9: "IGP", 17: "UDP", 27: "RDP", 41: "IPv6", 43: "IPv6-Route", 44: "IPv6-Frag",
    47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 59: "IPv6-NoNxt", 60: "IPv6-Opts",
    89: "OSPF", 103: "PIM", 112: "VRRP", 132: "SCTP", 137: "MPLS-in-IP",
}

IPV6_PROTO_NAMES = {
    0: "HOPOPT", 6: "TCP", 17: "UDP", 43: "IPv6-Route", 44: "IPv6-Frag",
    47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 59: "IPv6-NoNxt",
    60: "IPv6-Opts", 135: "Mobility", 136: "UDP-Lite", 137: "MPLS-in-IP",
}

# Well-known ports, used for the "service" column and to guess the app protocol.
TCP_PORTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "domain", 80: "http", 110: "pop3", 111: "sunrpc", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 179: "bgp", 389: "ldap", 443: "https",
    445: "microsoft-ds", 465: "smtps", 512: "exec", 513: "login", 514: "shell",
    587: "submission", 631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1433: "ms-sql-s", 1521: "oracle", 1723: "pptp", 1883: "mqtt",
    2049: "nfs", 2375: "docker", 3000: "http-alt", 3306: "mysql", 3389: "ms-wbt",
    5060: "sip", 5222: "xmpp-client", 5353: "mdns", 5432: "postgresql",
    5672: "amqp", 5900: "vnc", 6379: "redis", 8000: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 8888: "http-alt", 9000: "cslistener",
    9100: "jetdirect", 11211: "memcached", 27017: "mongodb",
}

UDP_PORTS = {
    53: "domain", 67: "bootps", 68: "bootpc", 69: "tftp", 88: "kerberos",
    123: "ntp", 137: "netbios-ns", 138: "netbios-dgm", 161: "snmp",
    162: "snmptrap", 1900: "ssdp", 3702: "ws-discovery", 443: "quic",
    4789: "vxlan", 5060: "sip", 5353: "mdns", 1900 + 0: "ssdp",
    51820: "wireguard",
}

TCP_FLAGS = (
    (0x001, "fin"),
    (0x002, "syn"),
    (0x004, "rst"),
    (0x008, "psh"),
    (0x010, "ack"),
    (0x020, "urg"),
    (0x040, "ece"),
    (0x080, "cwr"),
    (0x100, "ns"),
)


def decode_tcp_flags(value: int) -> list[str]:
    """Turn the 9-bit TCP flag field into short names like ``['syn', 'ack']``."""
    return [name for mask, name in TCP_FLAGS if value & mask]


# Dynamic/ephemeral ports. No service is registered here, so there is nothing
# to look up and no point paying for the lookup.
EPHEMERAL_FLOOR = 49152


@lru_cache(maxsize=8192)
def service_name(port: int, proto: str) -> str:
    """Best-effort service name for a port.

    Cached, and never asked of the operating system for an ephemeral port:
    ``getservbyport`` is a comparatively expensive services-database lookup on
    Windows (over a millisecond per call), and on a busy link most packets are
    client ports that have no service name at all.
    """
    table = UDP_PORTS if proto == "udp" else TCP_PORTS
    name = table.get(port)
    if name:
        return name
    if port <= 0 or port >= EPHEMERAL_FLOOR:
        return ""
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Packet record
# ---------------------------------------------------------------------------


@dataclass
class PacketInfo:
    """Everything we managed to learn about one frame."""

    index: int = 0
    ts: float = 0.0
    link_type: int = 1
    captured_len: int = 0
    wire_len: int = 0

    # Link layer
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    ethertype: Optional[int] = None

    # Network layer
    ip_version: Optional[int] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ttl: int = 0
    ip_proto: Optional[int] = None
    ip_id: int = 0
    ip_tos: int = 0
    ip_df: bool = False
    ip_offset: int = 0
    ip_total_len: int = 0
    fragmented: bool = False

    # Transport layer
    l4_proto: str = "other"
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    seq: int = 0
    ack: int = 0
    flags: list[str] = field(default_factory=list)
    window: int = 0
    udp_length: int = 0
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None

    # ARP
    arp: Optional[dict[str, Any]] = None

    # Everything else
    payload: bytes = b""
    app: Optional[dict[str, Any]] = None
    layers: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    # -- convenience -------------------------------------------------------

    @property
    def payload_len(self) -> int:
        """Application payload size in bytes."""
        return len(self.payload)

    @property
    def truncated(self) -> bool:
        """True when the capture snaplen cut the frame short."""
        return self.wire_len > self.captured_len

    @property
    def protocol(self) -> str:
        """Short label for the transport protocol: tcp / udp / icmp / arp / ip."""
        return self.l4_proto

    @property
    def service(self) -> str:
        """Service name of the destination port, if it is well known."""
        if self.l4_proto in ("tcp", "udp") and self.dst_port:
            return service_name(self.dst_port, self.l4_proto)
        return ""

    @property
    def summary(self) -> str:
        """A compact one-line description used by the stats module."""
        if self.arp:
            return f"ARP {self.arp['operation']} {self.arp['sender_ip']} -> {self.arp['target_ip']}"
        if not self.src_ip:
            return self.layers[0][0] if self.layers else "empty"
        ports = ""
        if self.l4_proto in ("tcp", "udp"):
            ports = f":{self.src_port} > :{self.dst_port}"
        elif self.l4_proto == "icmp":
            ports = f"type {self.icmp_type} code {self.icmp_code}"
        app = f"  {self.app['label']}" if self.app else ""
        return f"{self.src_ip}{ports} > {self.dst_ip}{ports}{app}"

    @property
    def flow_key(self) -> Optional[tuple]:
        """Bidirectional 5-tuple identifying a conversation, or None for non-IP."""
        if not self.src_ip or not self.dst_ip:
            return None
        return (
            self.l4_proto,
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
        )


# ---------------------------------------------------------------------------
# Layer decoders
# ---------------------------------------------------------------------------


def _mac(raw: bytes) -> str:
    """Format 6 bytes as a colon-separated MAC address.

    Uses ``bytes.hex`` rather than a generator of formatted pieces: this runs
    twice per packet, and the C implementation is several times quicker.
    """
    digits = raw[:6].hex()
    return f"{digits[0:2]}:{digits[2:4]}:{digits[4:6]}:{digits[6:8]}:{digits[8:10]}:{digits[10:12]}"


def _decode_ethernet(info: PacketInfo, data: bytes, detail: bool = True) -> int:
    """Decode an Ethernet II header. Returns the payload offset (0 if short)."""
    if len(data) < 14:
        info.notes.append("Ethernet header truncated")
        return 0

    info.dst_mac = _mac(data[0:6])
    info.src_mac = _mac(data[6:12])
    ethertype = struct.unpack("!H", data[12:14])[0]
    info.ethertype = ethertype

    offset = 14

    # 802.1Q / 802.1ad VLAN tags sit between the MAC header and the real type.
    # Each tag is 4 bytes: 2-byte TCI (priority + VLAN id) + 2-byte type.
    # TCI layout: bits 0-2 priority, bit 3 drop-eligible, bits 4-11 VLAN id.
    vlans: list[int] = []
    while ethertype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ) and len(data) >= offset + 4:
        tci, ethertype = struct.unpack("!HH", data[offset : offset + 4])
        vlans.append(tci)
        offset += 4

    if not detail:
        # Only the unwrapped ethertype matters downstream; skip the formatting
        # work for a layer tree nobody is going to print.
        info.ethertype = ethertype
        return offset

    for depth, tci in enumerate(vlans):
        info.layers.append(
            (
                "802.1Q" if depth == 0 else "802.1ad",
                {
                    "VLAN ID": str(tci & 0x0FFF),
                    "priority": str(tci >> 13),
                    "drop eligible": str(bool(tci & 0x1000)),
                },
            )
        )

    # Record the *unwrapped* ethertype: after VLAN tags this is the real
    # payload type (IPv4, IPv6, ARP), and the layer decoder dispatches on it.
    info.ethertype = ethertype

    ethertype_names = {
        ETHERTYPE_IPV4: "IPv4",
        ETHERTYPE_IPV6: "IPv6",
        ETHERTYPE_ARP: "ARP",
    }
    info.layers.append(
        (
            "Ethernet",
            {
                "Destination": info.dst_mac,
                "Source": info.src_mac,
                "Type": f"0x{ethertype:04x} ({ethertype_names.get(ethertype, 'unknown')})",
            },
        )
    )
    return offset


def _decode_arp(info: PacketInfo, data: bytes, detail: bool = True) -> int:
    """Decode an ARP request/reply. Returns 0 (ARP has no upper payload)."""
    if len(data) < 28:
        info.notes.append("ARP packet truncated")
        return 0

    htype, ptype, hlen, plen, oper = struct.unpack("!HHBBH", data[:8])
    if hlen != 6 or plen != 4 or len(data) < 28:
        # Only Ethernet/IPv4 ARP is realistic on a LAN.
        info.notes.append(f"unsupported ARP format (hw={hlen}, proto={plen})")
        return 0

    sha = _mac(data[8:14])
    spa = socket.inet_ntoa(data[14:18])
    tha = _mac(data[18:24])
    tpa = socket.inet_ntoa(data[24:28])

    operations = {1: "who-has", 2: "is-at", 3: "RARP-req", 4: "RARP-rep",
                  5: "Dyn-RARP-req", 6: "Dyn-RAR-rep", 7: "Dyn-RARP-err",
                  8: "InARP-req", 9: "InARP-rep"}
    name = operations.get(oper, f"op-{oper}")

    info.l4_proto = "arp"
    info.arp = {
        "operation": name,
        "sender_mac": sha,
        "sender_ip": spa,
        "target_mac": tha,
        "target_ip": tpa,
    }
    if detail:
        info.layers.append(
            (
                "ARP",
                {
                    "Operation": f"{oper} ({name})",
                    "Sender MAC": sha,
                    "Sender IP": spa,
                    "Target MAC": tha,
                    "Target IP": tpa,
                },
            )
        )
    return 0


def _decode_ipv4(info: PacketInfo, data: bytes, detail: bool = True) -> int:
    """Decode an IPv4 header. Returns the offset of the transport header."""
    if len(data) < 20:
        info.notes.append("IPv4 header truncated")
        return 0

    version_ihl = data[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4  # header length in bytes
    tos = data[1]
    total_len, ip_id, flags_frag, ttl, proto, _checksum = struct.unpack(
        "!HHHBBH", data[2:12]
    )
    src = socket.inet_ntoa(data[12:16])
    dst = socket.inet_ntoa(data[16:20])

    if version != 4:
        info.notes.append(f"IPv4 header has version {version}")
    if ihl < 20:
        info.notes.append("IPv4 IHL below minimum (20)")
        return 0

    fragment_offset = flags_frag & 0x1FFF
    more_fragments = bool(flags_frag & 0x2000)
    dont_fragment = bool(flags_frag & 0x4000)

    info.ip_version = 4
    info.src_ip, info.dst_ip = src, dst
    info.ttl = ttl
    info.ip_proto = proto
    info.ip_id = ip_id
    info.ip_tos = tos
    info.ip_df = dont_fragment
    info.ip_offset = fragment_offset
    info.ip_total_len = total_len
    # Anything other than offset 0 means we only see part of the datagram.
    info.fragmented = fragment_offset != 0 or more_fragments

    # For a non-first fragment the transport header is not in this packet at
    # all -- it only exists in the first fragment. Say so and let the caller
    # treat the rest of the datagram as an opaque blob.
    if info.fragmented and fragment_offset != 0:
        info.notes.append("non-first IP fragment: no transport header present")
        info.l4_proto = "ip-frag"

    if not detail:
        return ihl

    tos_names = {0x00: "default", 0x08: "low-delay", 0x10: "throughput",
                 0x18: "reliability", 0x20: "min-cost", 0x28: "max-reliability"}
    fields = {
        "Version": "4",
        "Header length": f"{ihl} bytes",
        "DSCP / TOS": f"0x{tos:02x} ({tos_names.get(tos, 'cs' + str(tos >> 3) + ',ecn' + str(tos & 1))})",
        "Total length": f"{total_len} bytes",
        "Identification": f"0x{ip_id:04x} ({ip_id})",
        "Flags": ", ".join(
            name for mask, name in
            ((0x4000, "DF"), (0x2000, "MF")) if flags_frag & mask
        ) or "none",
        "Fragment offset": str(fragment_offset),
        "TTL": str(ttl),
        "Protocol": f"{proto} ({IP_PROTO_NAMES.get(proto, 'unknown')})",
        "Source": src,
        "Destination": dst,
    }
    if ihl > 20 and len(data) >= ihl:
        fields["Options"] = _decode_ip_options(data[20:ihl])
    info.layers.append(("IPv4", fields))
    return ihl


def _decode_ip_options(raw: bytes) -> str:
    """Render the IP option TLVs as a compact string."""
    out: list[str] = []
    offset = 0
    while offset < len(raw):
        kind = raw[offset]
        if kind == 0:  # End of options
            break
        if kind == 1:  # NOP
            out.append("nop")
            offset += 1
            continue
        if offset + 1 >= len(raw):
            break
        length = raw[offset + 1]
        value = raw[offset + 2 : offset + length]
        names = {7: "RR", 68: "TS", 131: "LSR", 130: "SSR", 5: "EOL"}
        out.append(f"{names.get(kind, f'opt-{kind}')}({value.hex()})")
        if length < 2:
            break
        offset += length
    return " ".join(out) or "none"


def _decode_ipv6(info: PacketInfo, data: bytes, detail: bool = True) -> int:
    """Decode an IPv6 header. Returns the offset of the transport header."""
    if len(data) < 40:
        info.notes.append("IPv6 header truncated")
        return 0

    version_tc_flow = struct.unpack("!I", data[:4])[0]
    payload_len, next_header, hop_limit = struct.unpack("!HBB", data[4:8])
    src = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, data[24:40])

    info.ip_version = 6
    info.src_ip, info.dst_ip = src, dst
    info.ttl = hop_limit
    info.ip_proto = next_header
    info.ip_total_len = 40 + payload_len

    if detail:
        info.layers.append(
            (
                "IPv6",
                {
                    "Version": "6",
                    "Traffic class": f"0x{(version_tc_flow >> 20) & 0xFF:02x}",
                    "Flow label": f"0x{version_tc_flow & 0xFFFFF:05x}",
                    "Payload length": f"{payload_len} bytes",
                    "Next header": f"{next_header} ({IPV6_PROTO_NAMES.get(next_header, 'unknown')})",
                    "Hop limit": str(hop_limit),
                    "Source": src,
                    "Destination": dst,
                },
            )
        )

    # Walk the extension-header chain (hop-by-hop, routing, fragment, ...).
    offset = 40
    guard = 0
    while next_header not in (IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMPV6) and guard < 8:
        guard += 1
        if next_header == 44 and len(data) >= offset + 8:  # Fragment
            nxt, _res, frag_off, _m = struct.unpack("!BBHI", data[offset : offset + 8])
            info.notes.append("IPv6 fragment")
            info.fragmented = True
            if detail:
                info.layers.append(("IPv6 Fragment", {"offset": str(frag_off >> 3)}))
            next_header, offset = nxt, offset + 8
        elif next_header in (0, 43, 60) and len(data) >= offset + 2:
            nxt, ext_len = struct.unpack("!BB", data[offset : offset + 2])
            if detail:
                name = {0: "Hop-by-Hop", 43: "Routing", 60: "Destination"}.get(
                    next_header, f"ext-{next_header}"
                )
                info.layers.append((f"IPv6 {name}", {"length": f"{(ext_len + 1) * 8} bytes"}))
            next_header, offset = nxt, offset + (ext_len + 1) * 8
        else:
            break
    return offset


def _decode_tcp(info: PacketInfo, data: bytes, detail: bool = True) -> int:
    """Decode a TCP header. Returns the offset of the payload."""
    if len(data) < 20:
        info.notes.append("TCP header truncated")
        return 0

    src_port, dst_port, seq, ack, off_flags, window, _csum, _urg = struct.unpack(
        "!HHIIHHHH", data[:20]
    )
    data_offset = (off_flags >> 12) * 4
    flag_bits = off_flags & 0x1FF

    info.l4_proto = "tcp"
    info.src_port, info.dst_port = src_port, dst_port
    info.seq, info.ack = seq, ack
    info.window = window
    info.flags = decode_tcp_flags(flag_bits)
    # The NS (nonce) bit is the 9th flag: bit 8 of the offset/flags field,
    # after the 4 data-offset bits and 3 reserved bits.
    if off_flags & 0x0100:
        info.notes.append("ECN nonce bit (NS) set")
    if not detail:
        return data_offset if data_offset >= 20 else 20

    fields: dict[str, Any] = {
        "Source port": f"{src_port} ({service_name(src_port, 'tcp') or 'unknown'})",
        "Destination port": f"{dst_port} ({service_name(dst_port, 'tcp') or 'unknown'})",
        "Sequence": str(seq),
        "Acknowledgment": str(ack),
        "Header length": f"{data_offset} bytes",
        "Flags": " ".join(info.flags).upper() if info.flags else "none",
        "Window": f"{window}",
        "Checksum": _hex16(data, 16),
    }
    if flag_bits & 0x020:
        fields["Urgent pointer"] = str(struct.unpack("!H", data[18:20])[0])
    if data_offset > 20 and len(data) >= data_offset:
        fields["Options"] = _decode_tcp_options(data[20:data_offset])
    info.layers.append(("TCP", fields))

    return data_offset if data_offset >= 20 else 20


def _decode_tcp_options(raw: bytes) -> str:
    """Render TCP options as a compact string (MSS, SACK, timestamps, WScale)."""
    out: list[str] = []
    offset = 0
    while offset < len(raw):
        kind = raw[offset]
        if kind == 0:  # End of option list
            break
        if kind == 1:  # NOP
            out.append("nop")
            offset += 1
            continue
        if offset + 1 >= len(raw):
            break
        length = raw[offset + 1]
        body = raw[offset + 2 : offset + length]
        if kind == 2 and len(body) >= 2:
            out.append(f"MSS={struct.unpack('!H', body[:2])[0]}")
        elif kind == 3 and len(body) >= 1:
            out.append(f"WScale={body[0]}")
        elif kind == 4:
            # SACK-permitted: the option is only a kind/length pair, no body.
            out.append("SACKok")
        elif kind == 5 and len(body) >= 2:
            out.append(f"SACK r={struct.unpack('!H', body[:2])[0]}")
        elif kind == 8 and len(body) >= 8:
            value, echo = struct.unpack("!II", body[:8])
            out.append(f"TSval={value} TSecr={echo}")
        else:
            out.append(f"opt-{kind}")
        if length < 2:
            break
        offset += length
    return " ".join(out) or "none"


def _decode_udp(info: PacketInfo, data: bytes, detail: bool = True) -> int:
    """Decode a UDP header. UDP has no options, so payload starts at byte 8."""
    if len(data) < 8:
        info.notes.append("UDP header truncated")
        return 0

    src_port, dst_port, length, _csum = struct.unpack("!HHHH", data[:8])
    info.l4_proto = "udp"
    info.src_port, info.dst_port = src_port, dst_port
    info.udp_length = length

    if detail:
        info.layers.append(
            (
                "UDP",
                {
                    "Source port": f"{src_port} ({service_name(src_port, 'udp') or 'unknown'})",
                    "Destination port": f"{dst_port} ({service_name(dst_port, 'udp') or 'unknown'})",
                    "Length": f"{length} bytes",
                    "Checksum": _hex16(data, 6),
                },
            )
        )
    return 8


def _decode_icmp(info: PacketInfo, data: bytes, ipv6: bool = False,
                 detail: bool = True) -> int:
    """Decode an ICMP/ICMPv6 header. Returns the offset of the body."""
    if len(data) < 4:
        info.notes.append("ICMP header truncated")
        return 0

    icmp_type, code = data[0], data[1]
    info.l4_proto = "icmpv6" if ipv6 else "icmp"
    info.icmp_type, info.icmp_code = icmp_type, code
    if not detail:
        # Echo packets carry an 8-byte ICMP header then the original datagram.
        return 8 if (not ipv6 and icmp_type in (0, 8)) else 4

    if not ipv6:
        names = {
            0: "echo-reply", 3: "dest-unreachable", 4: "source-quench",
            5: "redirect", 8: "echo-request", 11: "time-exceeded",
            12: "parameter-problem", 13: "timestamp-request",
            14: "timestamp-reply",
        }
        fields: dict[str, Any] = {
            "Type": f"{icmp_type} ({names.get(icmp_type, 'unknown')})",
            "Code": str(code),
            "Checksum": _hex16(data, 2),
        }
        if icmp_type in (0, 8) and len(data) >= 8:
            ident, seq = struct.unpack("!HH", data[4:8])
            fields["Identifier"] = str(ident)
            fields["Sequence"] = str(seq)
        info.layers.append(("ICMP", fields))
        # Echo packets carry an 8-byte ICMP header then the original datagram.
        return 8 if icmp_type in (0, 8) else 4

    v6_names = {
        1: "dest-unreachable", 2: "packet-too-big", 3: "time-exceeded",
        4: "param-problem", 128: "echo-request", 129: "echo-reply",
        133: "router-solicit", 134: "router-advert", 135: "neighbor-solicit",
        136: "neighbor-advert", 137: "redirect",
    }
    info.layers.append(
        (
            "ICMPv6",
            {
                "Type": f"{icmp_type} ({v6_names.get(icmp_type, 'unknown')})",
                "Code": str(code),
                "Checksum": _hex16(data, 2),
            },
        )
    )
    return 4


def _hex16(data: bytes, offset: int) -> str:
    """Format a 16-bit checksum field as 0xabcd."""
    if len(data) < offset + 2:
        return "0x????"
    return f"0x{struct.unpack('!H', data[offset:offset + 2])[0]:04x}"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def dissect(
    data: bytes,
    link_type: int = 1,
    ts: float = 0.0,
    index: int = 0,
    wire_len: Optional[int] = None,
    detail: bool = True,
) -> PacketInfo:
    """Dissect one captured frame into a :class:`PacketInfo`.

    Args:
        data:      frame bytes as stored in the capture.
        link_type: link-layer type (a ``LINKTYPE_*`` constant).
        ts:        capture timestamp.
        index:     sequence number, for display.
        wire_len:  frame length on the wire; defaults to ``len(data)``. A larger
                   value means the capture snaplen truncated the frame.
        detail:    build the human-readable layer tree in
                   :attr:`PacketInfo.layers`. Set this to ``False`` when you
                   only need the scalar fields; it skips a large amount of
                   string formatting per packet.
    """
    info = PacketInfo(
        index=index,
        ts=ts,
        link_type=link_type,
        captured_len=len(data),
        wire_len=wire_len if wire_len is not None else len(data),
    )
    if wire_len is not None and wire_len > len(data):
        info.notes.append(f"frame truncated by snaplen ({len(data)}/{wire_len} bytes)")

    if not data:
        info.notes.append("empty frame")
        return info

    offset = 0
    ethertype: Optional[int] = None

    if link_type == 1:  # Ethernet
        offset = _decode_ethernet(info, data, detail)
        ethertype = info.ethertype
    elif link_type in (101, 228, 229):  # Raw IP
        # No link header; decide IPv4 vs IPv6 from the version nibble.
        ethertype = ETHERTYPE_IPV4 if data[0] >> 4 == 4 else ETHERTYPE_IPV6
        if detail:
            info.layers.append(("Raw IP", {"note": "no link-layer header"}))
    elif link_type in (0, 108):  # BSD loopback
        offset = 4
        if detail:
            info.layers.append(("Loopback", {"note": "4-byte family header stripped"}))
        ethertype = ETHERTYPE_IPV4 if len(data) > 4 and data[4] >> 4 == 4 else ETHERTYPE_IPV6
    elif link_type == 113:  # Linux cooked capture
        if len(data) >= 16:
            ethertype = struct.unpack("!H", data[14:16])[0]
            offset = 16
            if detail:
                info.layers.append(("Linux SLL", {"protocol": f"0x{ethertype:04x}"}))
        else:
            info.notes.append("Linux SLL header truncated")
    else:
        info.notes.append(f"unsupported link type {link_type}")
        return info

    if ethertype == ETHERTYPE_ARP:
        _decode_arp(info, data[offset:], detail)
        return info

    if ethertype == ETHERTYPE_IPV6:
        body_offset = _decode_ipv6(info, data[offset:], detail)
    elif ethertype == ETHERTYPE_IPV4 or ethertype is None:
        if ethertype is None:
            info.notes.append("no ethertype; assuming IPv4")
        body_offset = _decode_ipv4(info, data[offset:], detail)
    else:
        info.notes.append(f"unhandled ethertype 0x{ethertype:04x}")
        return info

    if not body_offset or body_offset <= 0:
        return info

    body = data[offset + body_offset :]

    if info.fragmented and info.ip_offset != 0:
        info.payload = body
        return info

    proto = info.ip_proto
    l4_offset = 0
    if proto == IPPROTO_TCP:
        l4_offset = _decode_tcp(info, body, detail)
    elif proto == IPPROTO_UDP:
        l4_offset = _decode_udp(info, body, detail)
    elif proto in (IPPROTO_ICMP, IPPROTO_ICMPV6):
        l4_offset = _decode_icmp(info, body, proto == IPPROTO_ICMPV6, detail)
    else:
        info.l4_proto = f"ip-{proto}" if proto is not None else "ip"
        info.notes.append(
            f"no decoder for IP protocol {proto} "
            f"({IP_PROTO_NAMES.get(proto, IPV6_PROTO_NAMES.get(proto, 'unknown'))})"
        )
        info.payload = body
        return info

    if not l4_offset:
        return info

    info.payload = body[l4_offset:]

    # Drop Ethernet padding: the IP total length already told us where the
    # datagram ends, so anything past that is not part of the packet.
    if not info.fragmented and info.ip_total_len:
        declared = info.ip_total_len - (body_offset + l4_offset)
        if 0 <= declared < len(info.payload):
            info.payload = info.payload[:declared]

    info.app = appproto.identify(info, detail=detail)
    if info.app and detail:
        info.layers.append((info.app["label"], info.app["fields"]))
    return info
