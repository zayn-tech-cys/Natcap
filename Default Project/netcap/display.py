"""
Terminal rendering: colour, the live packet line, the layer tree, and the
end-of-capture summary report.

Colour is applied through :class:`Style`, which turns itself off when the
output is not an interactive terminal or when ``--no-color`` is passed, so
piping the output to a file gives you clean text.
"""

from __future__ import annotations

import os
import sys
import time
from typing import TYPE_CHECKING, Any, Optional, TextIO

from . import stats
from .dissect import service_name
from .pcap import link_type_name

if TYPE_CHECKING:
    from .dissect import PacketInfo
    from .stats import TrafficStats

# ANSI SGR codes
_CODES = {
    "reset": "0",
    "bold": "1",
    "dim": "2",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
    "white": "37",
    "grey": "90",
    "bred": "91",
    "bgreen": "92",
    "byellow": "93",
    "bblue": "94",
    "bmagenta": "95",
    "bcyan": "96",
}


class Style:
    """Minimal ANSI colour helper."""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled

    def __call__(self, text: str, *names: str) -> str:
        if not self.enabled or not names:
            return text
        prefix = "".join(f"\033[{_CODES[n]}m" for n in names if n in _CODES)
        return f"{prefix}{text}\033[0m" if prefix else text


def should_colorize(force: Optional[bool] = None) -> bool:
    """Decide whether to emit ANSI escapes."""
    if force is not None:
        return force
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def supports_unicode(stream: TextIO) -> bool:
    """Detect whether the output stream can render box-drawing characters."""
    encoding = (getattr(stream, "encoding", None) or "").lower()
    return "utf" in encoding


# ---------------------------------------------------------------------------
# Per-protocol colouring
# ---------------------------------------------------------------------------

PROTO_COLORS = {
    "tcp": "bcyan",
    "udp": "byellow",
    "icmp": "bmagenta",
    "icmpv6": "bmagenta",
    "arp": "yellow",
    "ip-frag": "grey",
}

APP_COLORS = {"dns": "bblue", "http": "bgreen", "tls": "bmagenta"}


def format_clock(ts: float, base: Optional[float] = None) -> str:
    """Format a timestamp as a wall clock, or as seconds since ``base``."""
    if base is None:
        clock = time.strftime("%H:%M:%S", time.localtime(ts))
        return f"{clock}.{int(ts % 1 * 1000):03d}"
    return f"{ts - base:+10.3f}"


# ---------------------------------------------------------------------------
# Live packet line
# ---------------------------------------------------------------------------


def packet_line(info: "PacketInfo", style: Style, unicode_ok: bool = True,
                base_ts: Optional[float] = None) -> str:
    """The one-line summary printed for each captured packet.

    ``000123  12:00:01.412  10.0.0.14:52418 > 93.184.216.34:443  TCP  [syn]  Len 74``
    """
    parts: list[str] = []

    index = style(f"{info.index:>6}", "grey")
    parts.append(index)

    clock = style(format_clock(info.ts, base_ts), "grey")
    parts.append(clock)

    if info.l4_proto == "arp" and info.arp:
        parts.append(style("ARP", "yellow"))
        arp = info.arp
        parts.append(f"{arp['sender_ip']} > {arp['target_ip']}")
        parts.append(style(arp["operation"], "bold"))
    else:
        proto = info.l4_proto
        color = PROTO_COLORS.get(proto, "white")
        parts.append(style(proto.upper().ljust(5), color))

        if info.src_ip:
            src = info.src_ip
            if info.src_port is not None:
                src = f"{src}:{info.src_port}"
            parts.append(src)
            parts.append(style(">", "grey"))
            dst = info.dst_ip or "?"
            if info.dst_port is not None:
                dst = f"{dst}:{info.dst_port}"
            parts.append(dst)
        else:
            parts.append(style("(no IP decoded)", "grey"))

        if info.l4_proto == "icmp" and info.icmp_type is not None:
            names = {0: "reply", 3: "unreachable", 8: "request", 11: "timeout"}
            parts.append(style(f"type={info.icmp_type} ({names.get(info.icmp_type, '?')})", "magenta"))

        if info.flags:
            parts.append(style("[" + " ".join(flag.upper() for flag in info.flags) + "]", "cyan"))

    if info.app:
        app = info.app
        parts.append(style(app["label"], APP_COLORS.get(app["proto"], "white")))
        detail = _app_detail(app)
        if detail:
            parts.append(detail)

    total = info.ip_total_len or info.wire_len
    arrow = unicode_ok and "→" or "->"
    parts.append(style(f"{arrow} {total}B", "grey"))
    if info.payload_len:
        parts.append(style(f"(+{info.payload_len}B app)", "grey"))
    if info.truncated or any("truncated" in n for n in info.notes):
        parts.append(style("[truncated]", "bred"))

    return "  ".join(parts)


def _app_detail(app: dict[str, Any]) -> str:
    """A short, single-line hint at what the application payload says."""
    extra = app.get("extra") or {}
    if app["proto"] == "dns":
        if extra.get("is_response"):
            answers = extra.get("answers") or []
            if answers:
                return answers[0].split(" -> ")[-1][:48]
            return f"rcode={extra.get('rcode', '?')}"
        return (extra.get("question") or "")[:48]
    if app["proto"] == "http":
        if extra.get("is_response"):
            return f"{extra.get('status', '?')}"
        target = (extra.get("uri") or "")[:40]
        return f"{extra.get('method', '')} {target}"
    if app["proto"] == "tls":
        sni = extra.get("sni") or []
        if sni:
            return f"SNI={sni[0]}"
        if extra.get("handshake_type") == 2:
            return "server-hello"
        if extra.get("content_type") == 23:
            return "encrypted"
    return ""


# ---------------------------------------------------------------------------
# Layer tree (verbose / --detail)
# ---------------------------------------------------------------------------


def packet_detail(info: "PacketInfo", style: Style, unicode_ok: bool = True,
                  hexdump: bool = True) -> str:
    """Full protocol tree, the way Wireshark shows it."""
    lines: list[str] = []
    arrow = unicode_ok and "▸" or ">"
    branch = unicode_ok and "└─" or "`-"

    lines.append(style(f"Frame {info.index}", "bold", "bwhite"))
    lines.append(f"  {branch} {style('Timestamp', 'bblue')}: {info.ts:.6f}")
    lines.append(
        f"  {branch} {style('Length', 'bblue')}: {info.wire_len} bytes on the wire, "
        f"{info.captured_len} bytes captured"
    )
    lines.append(f"  {branch} {style('Link type', 'bblue')}: {link_type_name(info.link_type)}")

    indent = "     "
    for depth, (name, fields) in enumerate(info.layers):
        last = depth == len(info.layers) - 1
        marker = branch if last else f"{arrow} "
        lines.append(f"{indent}{marker} {style(name, 'bgreen')}")
        for key, value in fields.items():
            if value in ("", None):
                continue
            lines.append(f"{indent}      {style(str(key) + ':', 'bcyan')} {value}")

    if info.notes:
        lines.append(f"{indent}{branch} {style('Notes', 'byellow')}")
        for note in info.notes:
            lines.append(f"{indent}      {style('-', 'byellow')} {note}")

    if info.payload and hexdump:
        lines.append(
            f"{indent}{branch} {style('Payload', 'bblue')} "
            f"({info.payload_len} bytes)"
        )
        for row in hexdump_lines(info.payload, limit=64):
            lines.append(f"{indent}      {style(row, 'grey')}")

    return "\n".join(lines)


def hexdump_lines(data: bytes, width: int = 16, limit: Optional[int] = None) -> list[str]:
    """Render bytes as a classic offset / hex / ASCII dump."""
    limit = len(data) if limit is None else min(limit, len(data))
    lines: list[str] = []
    for offset in range(0, limit, width):
        chunk = data[offset : offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:08x}  {hex_part:<{width * 3}} {ascii_part}")
    if limit < len(data):
        lines.append(f"... {len(data) - limit} more bytes")
    return lines


# ---------------------------------------------------------------------------
# Summary report
# ---------------------------------------------------------------------------


def summary_report(stat: "TrafficStats", style: Style,
                    unicode_ok: bool = True, link_type: int = 1) -> str:
    """Build the end-of-capture report."""
    lines: list[str] = []
    rule = (unicode_ok and "─" or "-") * 74

    def heading(text: str) -> None:
        lines.append("")
        lines.append(style(text.upper(), "bold", "bwhite"))
        lines.append(style(rule, "grey"))

    # -- capture overview -------------------------------------------------
    lines.append(style("CAPTURE SUMMARY", "bold", "bwhite"))
    lines.append(style(rule, "grey"))
    lines.append(f"  Link type       {link_type_name(link_type)}")
    lines.append(f"  Packets         {stat.packets:,}")
    lines.append(f"  Total bytes     {stats.human_bytes(stat.bytes)} ({stat.bytes:,})")
    if stat.duration:
        lines.append(
            f"  Duration        {stats.human_duration(stat.duration)}  "
            f"({stat.rate:,.1f} pkt/s, "
            f"{stats.human_bytes(stat.bytes / stat.duration)}/s)"
        )
    if stat.first_ts:
        lines.append(
            f"  First packet    {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.first_ts))}"
        )
    if stat.filtered_out:
        lines.append(f"  Filtered out    {stat.filtered_out:,} (did not match the filter)")

    # -- protocol mix -----------------------------------------------------
    heading("Protocol mix")
    if not stat.protocol_packets:
        lines.append("  (nothing captured)")
    else:
        total = sum(stat.protocol_packets.values()) or 1
        for proto, count in stat.top(stat.protocol_packets, count=12):
            byte_count = stat.protocol_bytes.get(proto, 0)
            share = count / total * 100
            bar = "#" * int(share / 2.5)
            color = PROTO_COLORS.get(proto, "white")
            lines.append(
                f"  {style(proto.ljust(9), color, 'bold')}"
                f"{count:>8,}  {share:>5.1f}%  "
                f"{style(bar.ljust(40), color)}  {stats.human_bytes(byte_count)}"
            )

    # -- application protocols -------------------------------------------
    if stat.app_packets:
        heading("Application protocols")
        for proto, count in stat.top(stat.app_packets, count=8):
            lines.append(f"  {proto.upper().ljust(9)}{count:>8,}")

    # -- talkers ----------------------------------------------------------
    if stat.ip_packets:
        heading("Top talkers")
        lines.append(
            f"  {style('address'.ljust(24), 'bold')}"
            f"{style('pkts'.rjust(7), 'bold')}"
            f"{style('sent'.rjust(12), 'bold')}"
            f"{style('received'.rjust(12), 'bold')}"
        )
        for ip in stat.top_hosts(count=12):
            sent = stat.ip_sent.get(ip, 0)
            received = stat.ip_received.get(ip, 0)
            lines.append(
                f"  {ip.ljust(24)}{stat.ip_packets.get(ip, 0):>7,}"
                f"  {stats.human_bytes(sent):>11}  {stats.human_bytes(received):>11}"
            )

    # -- conversations ----------------------------------------------------
    flows = stat.top_flows(count=10)
    if flows:
        heading("Top conversations (by bytes)")
        lines.append(
            f"  {style('endpoints'.ljust(46), 'bold')}"
            f"{style('pkts'.rjust(6), 'bold')}"
            f"{style('bytes'.rjust(12), 'bold')}"
            f"  most data"
        )
        for flow in flows:
            endpoints = flow.endpoints
            if len(endpoints) > 46:
                endpoints = endpoints[:43] + "..."
            direction, share = flow.heavy_side
            color = PROTO_COLORS.get(flow.proto, "white")
            lines.append(
                f"  {style(endpoints.ljust(46), color)}"
                f"{flow.packets:>6,}  {stats.human_bytes(flow.bytes):>11}"
                f"  {share:>3.0f}% {direction}"
            )

    # -- ports ------------------------------------------------------------
    if stat.port_packets:
        heading("Destination ports (by packet count)")
        for port, count in stat.top(stat.port_packets, count=10):
            name = service_name(port, "tcp")
            lines.append(f"  {str(port).ljust(8)} {name.ljust(22)}{count:>8,}")

    # -- protocol specifics ----------------------------------------------
    if stat.flags:
        heading("TCP flags")
        for flag, count in stat.top(stat.flags, count=10):
            lines.append(f"  {flag.upper().ljust(8)}{count:>8,}")

    if stat.icmp_types:
        heading("ICMP message types")
        for key, count in stat.top(stat.icmp_types, count=8):
            lines.append(f"  {key.ljust(20)}{count:>8,}")

    # -- names seen -------------------------------------------------------
    name_lines: list[str] = []
    if stat.dns_queries:
        name_lines.append(("DNS queries", stat.dns_queries))
    if stat.http_hosts:
        hosts = [f"{host} x{count}" if count > 1 else host
                 for host, count in stat.top(stat.http_hosts, count=10)]
        name_lines.append(("HTTP hosts", hosts))
    if stat.tls_snis:
        snis = [f"{name} x{count}" if count > 1 else name
                for name, count in stat.top(stat.tls_snis, count=10)]
        name_lines.append(("TLS server names (SNI)", snis))

    if name_lines:
        heading("Names observed")
        for title, names in name_lines:
            lines.append(f"  {style(title, 'bold')}")
            for name in names:
                lines.append(f"    {name}")

    # -- warnings ---------------------------------------------------------
    if stat.notes:
        heading("Dissection warnings")
        for note, count in stat.top(stat.notes, count=10):
            suffix = f" (x{count})" if count > 1 else ""
            lines.append(f"  {style('-', 'byellow')} {note}{suffix}")

    lines.append("")
    return "\n".join(lines)
