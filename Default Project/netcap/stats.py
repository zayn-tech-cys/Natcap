"""
Traffic statistics: protocol mix, byte counts, talkers and conversations.

A *conversation* (or flow) groups the two directions of one 5-tuple together,
which is what you normally want when asking "who was talking to whom, and how
much data moved". A unidirectional *pair* key is kept as well for the
"who spoke to whom first" view.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .dissect import PacketInfo


def human_bytes(count: float) -> str:
    """Format a byte count with a binary unit suffix."""
    if count < 1024:
        return f"{int(count)} B"
    for unit, size in (("KiB", 1024**2), ("MiB", 1024**3), ("GiB", 1024**4)):
        if count < size:
            return f"{count / (size / 1024):.1f} {unit}"
    return f"{count / 1024**4:.1f} TiB"


def human_duration(seconds: float) -> str:
    """Format a duration as ``1h02m03s`` / ``2m03s`` / ``4.2s``."""
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, secs = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h{minutes:02d}m{secs:02d}s"
    return f"{minutes}m{secs:02d}s"


@dataclass
class _Flow:
    """Accumulated counters for one bidirectional conversation."""

    proto: str
    a: str
    a_port: Optional[int]
    b: str
    b_port: Optional[int]
    packets: int = 0
    bytes: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    a_to_b: int = 0
    b_to_a: int = 0

    @property
    def endpoints(self) -> str:
        left = f"{self.a}:{self.a_port}" if self.a_port is not None else self.a
        right = f"{self.b}:{self.b_port}" if self.b_port is not None else self.b
        return f"{left} <-> {right}"

    @property
    def heavy_side(self) -> tuple[str, int]:
        """Which endpoint sent most of the bytes, and the percentage."""
        if self.a_to_b >= self.b_to_a:
            label = f"{self.a} -> {self.b}"
            return label, (self.a_to_b / self.bytes * 100 if self.bytes else 0.0)
        label = f"{self.b} -> {self.a}"
        return label, (self.b_to_a / self.bytes * 100 if self.bytes else 0.0)


@dataclass
class TrafficStats:
    """Rolling statistics over the packets seen so far."""

    packets: int = 0
    bytes: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0

    protocol_packets: dict[str, int] = field(default_factory=dict)
    protocol_bytes: dict[str, int] = field(default_factory=dict)
    app_packets: dict[str, int] = field(default_factory=dict)

    ip_sent: dict[str, int] = field(default_factory=dict)
    ip_received: dict[str, int] = field(default_factory=dict)
    ip_packets: dict[str, int] = field(default_factory=dict)
    port_packets: dict[str, int] = field(default_factory=dict)

    flows: dict[tuple, _Flow] = field(default_factory=dict)
    flags: dict[str, int] = field(default_factory=dict)

    dns_queries: list[str] = field(default_factory=list)
    http_hosts: dict[str, int] = field(default_factory=dict)
    tls_snis: dict[str, int] = field(default_factory=dict)
    icmp_types: dict[str, int] = field(default_factory=dict)
    notes: dict[str, int] = field(default_factory=dict)

    filtered_out: int = 0

    # -- ingest -----------------------------------------------------------

    def add(self, info: "PacketInfo") -> None:
        """Fold one dissected packet into the statistics."""
        self.packets += 1
        size = info.wire_len or info.captured_len
        self.bytes += size

        if not self.first_ts:
            self.first_ts = info.ts
        self.last_ts = info.ts

        proto = info.l4_proto if info.l4_proto != "ip-frag" else "ip"
        self.protocol_packets[proto] = self.protocol_packets.get(proto, 0) + 1
        self.protocol_bytes[proto] = self.protocol_bytes.get(proto, 0) + size

        if info.app:
            self.app_packets[info.app["proto"]] = self.app_packets.get(info.app["proto"], 0) + 1

        # Per-host counters. Tracking sent and received separately is much more
        # informative than a single "bytes handled" total, which would count
        # every packet once for each endpoint and make a download look like a
        # two-way transfer.
        if info.src_ip:
            self.ip_sent[info.src_ip] = self.ip_sent.get(info.src_ip, 0) + size
        if info.dst_ip:
            self.ip_received[info.dst_ip] = self.ip_received.get(info.dst_ip, 0) + size
        for ip in (info.src_ip, info.dst_ip):
            if ip:
                self.ip_packets[ip] = self.ip_packets.get(ip, 0) + 1
        # ARP carries addresses but no IP-layer size attribution, so count the
        # sender only, otherwise a chatty ARP cache shows up as traffic.
        if info.arp and info.arp.get("sender_ip"):
            sender = info.arp["sender_ip"]
            self.ip_sent.setdefault(sender, 0)
            self.ip_packets.setdefault(sender, 0)

        for port in (info.dst_port,):
            if port:
                self.port_packets[port] = self.port_packets.get(port, 0) + 1

        for flag in info.flags:
            self.flags[flag] = self.flags.get(flag, 0) + 1

        if info.l4_proto == "icmp" and info.icmp_type is not None:
            key = f"type {info.icmp_type}"
            self.icmp_types[key] = self.icmp_types.get(key, 0) + 1

        for note in info.notes:
            self.notes[note] = self.notes.get(note, 0) + 1

        self._add_flow(info, size)
        self._add_app(info)

    def _add_flow(self, info: "PacketInfo", size: int) -> None:
        """Update the bidirectional conversation table."""
        key = info.flow_key
        if key is None:
            return
        proto, src_ip, src_port, dst_ip, dst_port = key
        # Normalise direction so both halves of a conversation share one key.
        forward = (src_ip, src_port or 0) <= (dst_ip, dst_port or 0)
        flow_key = (
            proto,
            src_ip if forward else dst_ip,
            src_port if forward else dst_port,
            dst_ip if forward else src_ip,
            dst_port if forward else src_port,
        )
        flow = self.flows.get(flow_key)
        if flow is None:
            flow = _Flow(
                proto=proto,
                a=flow_key[1], a_port=flow_key[2] or None,
                b=flow_key[3], b_port=flow_key[4] or None,
                first_ts=info.ts, last_ts=info.ts,
            )
            self.flows[flow_key] = flow
        flow.packets += 1
        flow.bytes += size
        # Packets can be handed to us out of order, so track the true span.
        flow.first_ts = min(flow.first_ts, info.ts) if info.ts < flow.first_ts else flow.first_ts
        flow.last_ts = max(flow.last_ts, info.ts)
        if forward:
            flow.a_to_b += size
        else:
            flow.b_to_a += size

    def _add_app(self, info: "PacketInfo") -> None:
        """Record interesting application-layer facts."""
        if not info.app:
            return
        extra = info.app.get("extra") or {}

        if info.app["proto"] == "dns":
            question = extra.get("question")
            if question and not extra.get("is_response") and question not in self.dns_queries:
                self.dns_queries.append(question)
        elif info.app["proto"] == "http":
            host = extra.get("host")
            if host:
                self.http_hosts[host] = self.http_hosts.get(host, 0) + 1
        elif info.app["proto"] == "tls":
            for name in extra.get("sni") or []:
                self.tls_snis[name] = self.tls_snis.get(name, 0) + 1

    # -- queries ----------------------------------------------------------

    @property
    def duration(self) -> float:
        """Wall-clock span of the capture, in seconds."""
        if not self.first_ts or not self.last_ts or self.last_ts <= self.first_ts:
            return 0.0
        return self.last_ts - self.first_ts

    @property
    def rate(self) -> float:
        """Average packets per second over the capture."""
        span = self.duration
        return self.packets / span if span > 0 else 0.0

    def top(self, counter: dict, count: int = 10) -> list[tuple]:
        """The ``count`` largest (key, value) pairs from a counter dict."""
        return sorted(counter.items(), key=lambda kv: kv[1], reverse=True)[:count]

    def host_total(self, ip: str) -> int:
        """Bytes a host either sent or received."""
        return self.ip_sent.get(ip, 0) + self.ip_received.get(ip, 0)

    def top_hosts(self, count: int = 10) -> list[str]:
        """The busiest hosts, ordered by total bytes touched."""
        totals = {
            ip: self.ip_sent.get(ip, 0) + self.ip_received.get(ip, 0)
            for ip in self.ip_packets
        }
        return [ip for ip, _ in sorted(totals.items(), key=lambda kv: kv[1], reverse=True)[:count]]

    def top_flows(self, count: int = 10) -> list[_Flow]:
        """The busiest conversations by bytes."""
        return sorted(self.flows.values(), key=lambda f: f.bytes, reverse=True)[:count]
