"""
Minimal reader/writer for the classic libpcap file format (``.pcap``/``.cap``).

Why not just use scapy for this? Two reasons:

1. Offline analysis then works with *no* third-party packages installed, so you
   can dissect a capture on any machine.
2. You can actually see how a capture file is put together. The whole format is
   a 24-byte global header followed by a 16-byte header per packet.

File layout::

    global header (24 bytes, little- or big-endian)
      magic      0xa1b2c3d4  microsecond timestamps
                 0xa1b2c3d4 swapped  => big-endian file
                 0xa1b23c4d  nanosecond timestamps
      version    major(2) minor(2)   -> 2.4
      thiszone   signed 4 bytes, seconds to GMT (legacy, always 0)
      sigfigs    unsigned 4 bytes  (legacy, always 0)
      snaplen    unsigned 4 bytes, max bytes stored per packet
      network    unsigned 4 bytes, link-layer type (see LINKTYPE_*)

    per-packet header (16 bytes)
      ts_sec      unsigned 4   seconds
      ts_usec     unsigned 4   microseconds (or nanoseconds, see magic)
      incl_len    unsigned 4   bytes stored in the file
      orig_len    unsigned 4   bytes on the wire (incl_len < orig_len => truncated)

    then incl_len bytes of packet data
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator

# Link-layer header types we know how to decode.
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LOOP = 108

LINKTYPE_NAMES = {
    LINKTYPE_NULL: "Null/Loopback",
    LINKTYPE_ETHERNET: "Ethernet",
    LINKTYPE_RAW: "Raw IP",
    LINKTYPE_LINUX_SLL: "Linux cooked capture",
    LINKTYPE_LOOP: "OpenBSD loopback",
    LINKTYPE_IPV4: "Raw IPv4",
    LINKTYPE_IPV6: "Raw IPv6",
}

PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D

_GLOBAL_HEADER = struct.Struct("<IHHiIII")
_PACKET_HEADER = struct.Struct("<IIII")


class PcapError(Exception):
    """Raised when a file is not a readable pcap capture."""


@dataclass
class RawPacket:
    """One captured frame plus the metadata the container gave us.

    Attributes:
        ts:        capture timestamp as a Unix epoch float.
        data:      the frame bytes exactly as stored (may be truncated).
        orig_len:  length of the frame on the wire.
        link_type: link-layer header type (one of the LINKTYPE_* constants).
    """

    ts: float
    data: bytes
    orig_len: int
    link_type: int

    @property
    def wire_len(self) -> int:
        """Bytes actually on the wire (ignoring any capture truncation)."""
        return self.orig_len or len(self.data)

    @property
    def truncated(self) -> bool:
        """True when the capture stored fewer bytes than were on the wire."""
        return self.orig_len > 0 and self.orig_len > len(self.data)


def link_type_name(link_type: int) -> str:
    """Human-readable name for a link-layer type."""
    return LINKTYPE_NAMES.get(link_type, f"Unknown ({link_type})")


class PcapReader:
    """Iterable, closable reader over a pcap file.

    Use it as a context manager so the file handle is released promptly::

        with pcap.PcapReader("traffic.pcap") as reader:
            for packet in reader:
                ...

    This matters on Windows, where an open handle makes the file undeletable.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self.link_type, self._iter = read_pcap(path)

    def __iter__(self) -> Iterator[RawPacket]:
        return self._iter

    def close(self) -> None:
        """Release the file handle. Safe to call more than once."""
        if self._iter is not None:
            self._iter.close()
            self._iter = None

    def __enter__(self) -> "PcapReader":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


def read_pcap(path: str) -> tuple[int, Iterator[RawPacket]]:
    """Open a pcap file.

    Returns:
        (link_type, packet_iterator)

    The header is read eagerly so callers can fail fast on a bad file, while
    packet payloads stream lazily. Prefer :class:`PcapReader`, which ties the
    file handle to a deterministic close.
    """
    with open(path, "rb") as handle:
        header = handle.read(_GLOBAL_HEADER.size)
        if len(header) < _GLOBAL_HEADER.size:
            raise PcapError(f"{path}: file is too short to be a pcap capture")

        # The magic tells us the byte order. A little quirk: if the file is
        # big-endian the magic reads as the byte-swapped value.
        nano = False
        for endian in ("<", ">"):
            (magic,) = struct.unpack(endian + "I", header[:4])
            if magic == PCAP_MAGIC_US:
                break
            if magic == PCAP_MAGIC_NS:
                nano = True
                break
        else:
            raise PcapError(f"{path}: not a pcap file (bad magic {header[:4]!r})")

        _, major, minor, _zone, _figs, _snaplen, network = struct.unpack(
            endian + "IHHiIII", header
        )
        if major != 2:
            raise PcapError(f"{path}: unsupported pcap version {major}.{minor}")

        scale = 1e-9 if nano else 1e-6
        fmt = endian + "IIII"
        header_size = _GLOBAL_HEADER.size

        def packets() -> Iterator[RawPacket]:
            with open(path, "rb") as body:
                # Skip the global header we already consumed; without this the
                # file's magic number is read as a packet timestamp.
                body.seek(header_size)
                while True:
                    raw = body.read(_PACKET_HEADER.size)
                    if not raw:
                        return
                    if len(raw) < _PACKET_HEADER.size:
                        return  # truncated trailing header; stop cleanly
                    ts_sec, ts_frac, incl_len, orig_len = struct.unpack(fmt, raw)
                    data = body.read(incl_len)
                    if len(data) < incl_len:
                        return
                    yield RawPacket(
                        ts=ts_sec + ts_frac * scale,
                        data=data,
                        orig_len=orig_len,
                        link_type=network,
                    )

    return network, packets()


def write_pcap(path: str, packets: list[RawPacket], link_type: int, snaplen: int = 262144) -> int:
    """Write packets to a pcap file in the classic format.

    Returns:
        The number of packets written.
    """
    with open(path, "wb") as handle:
        handle.write(_GLOBAL_HEADER.pack(PCAP_MAGIC_US, 2, 4, 0, 0, snaplen, link_type))
        for packet in packets:
            # incl_len is what we actually store; orig_len stays the wire length
            # so downstream code can tell the frame was truncated.
            handle.write(
                _PACKET_HEADER.pack(
                    int(packet.ts),
                    int(round((packet.ts - int(packet.ts)) * 1_000_000)),
                    len(packet.data),
                    packet.orig_len or len(packet.data),
                )
            )
            handle.write(packet.data)
    return len(packets)
