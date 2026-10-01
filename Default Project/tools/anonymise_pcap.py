"""
Rewrite the IP addresses in a capture file, so a real capture can be published.

Addresses are remapped to the ranges reserved for documentation by RFC 5737:

    192.0.2.0/24        TEST-NET-1
    198.51.100.0/24     TEST-NET-2
    203.0.113.0/24      TEST-NET-3
    2001:db8::/32       documentation prefix for IPv6

Each distinct address in the capture keeps its identity, so a conversation is
still visibly between the same two hosts -- only the numbers change. MAC
addresses are zeroed for the same reason.

Because the IPv4 and UDP/TCP header checksums cover the addresses, they are
recomputed afterwards. A stale checksum would make the sample teach the wrong
thing; a correct one means you can checksum-validate an anonymised capture.

Usage::

    python tools/anonymise_pcap.py examples/sample.pcap
"""

from __future__ import annotations

import os
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netcap.pcap import PcapReader, RawPacket, write_pcap  # noqa: E402

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100

# Documentation prefix for IPv6, from RFC 3849.
V6_PREFIX = "2001:db8::"


class Renamer:
    """Assigns a stable pseudonym to each address it is shown.

    Addresses are handed out in order of first appearance, walking the three
    documentation ranges. Every distinct address gets its own pseudonym, so two
    unrelated servers never collapse into the same host.
    """

    RANGES = ("192.0.2", "198.51.100", "203.0.113")

    def __init__(self) -> None:
        self.v4: dict[str, str] = {}
        self.v6: dict[str, str] = {}
        self._v4_next = 0
        self._v6_next = 1

    def _next_v4(self) -> str:
        # 254 usable host addresses per range, skipping .0 and .255.
        index = self._v4_next
        self._v4_next += 1
        base, host = self.RANGES[index // 254], index % 254 + 1
        return f"{base}.{host}"

    def v4_name(self, address: str) -> str:
        if address not in self.v4:
            self.v4[address] = self._next_v4()
        return self.v4[address]

    def v6_name(self, address: str) -> str:
        if address not in self.v6:
            self.v6[address] = f"{V6_PREFIX}{self._v6_next:x}"
            self._v6_next += 1
        return self.v6[address]

    def name(self, address: str) -> str:
        return self.v6_name(address) if ":" in address else self.v4_name(address)


# ---------------------------------------------------------------------------
# Checksums
# ---------------------------------------------------------------------------


def ones_complement_sum(data: bytes) -> int:
    """Sum 16-bit words the way the internet checksum does."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) | data[index + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return total & 0xFFFF


def internet_checksum(data: bytes) -> int:
    """The standard one's-complement checksum (RFC 1071)."""
    return (~ones_complement_sum(data)) & 0xFFFF


def fix_ipv4_checksum(header: bytes) -> bytes:
    """Recompute the IPv4 header checksum in place."""
    header = header[:10] + b"\x00\x00" + header[12:]
    value = internet_checksum(header)
    return header[:10] + struct.pack("!H", value) + header[12:]


def fix_transport_checksums(frame: bytes, ip_header_len: int, total_len: int,
                            protocol: int, addresses: tuple[bytes, bytes]) -> bytes:
    """Recompute the TCP/UDP checksum after the addresses changed.

    A pseudo-header of the addresses, protocol and length precedes the transport
    header, so the addresses have to be folded back in. The UDP checksum of 0
    means "not computed" in IPv4 and must stay 0.
    """
    transport = frame[ip_header_len:total_len]
    if len(transport) < 4:
        return frame

    if protocol == 17:  # UDP
        declared = struct.unpack("!H", transport[4:6])[0]
        if declared == 0:
            return frame  # checksum disabled by the sender
        source, destination = addresses
        pseudo = source + destination + struct.pack("!HH", 0, 17) + \
            struct.pack("!H", len(transport))
        # Zero the checksum field, fold in the pseudo-header, then write the
        # result back at transport offset 6 -- not 4, which is the length.
        body = transport[:6] + b"\x00\x00" + transport[8:]
        value = internet_checksum(pseudo + body) or 0xFFFF
        return (
            frame[:ip_header_len + 6]
            + struct.pack("!H", value)
            + frame[ip_header_len + 8:]
        )

    if protocol == 6:  # TCP
        source, destination = addresses
        pseudo = source + destination + struct.pack("!HH", 0, 6) + \
            struct.pack("!H", len(transport))
        body = transport[:16] + b"\x00\x00" + transport[18:]
        value = internet_checksum(pseudo + body)
        return frame[:ip_header_len + 16] + struct.pack("!H", value) + frame[ip_header_len + 18:]

    return frame


# ---------------------------------------------------------------------------
# Frame rewriting
# ---------------------------------------------------------------------------


def _skip_dns_name(data: bytes, offset: int) -> int:
    """Return the offset just past the DNS name starting at ``offset``.

    Compression pointers are followed rather than stepped over, because the
    length is needed to find the record that follows.
    """
    hops = 0
    while offset < len(data) and hops < 128:
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2  # the name is entirely the pointer
        offset += 1 + length
        hops += 1
    return offset


def rewrite_dns(data: bytes, renamer: Renamer) -> bytes:
    """Rewrite the addresses in A and AAAA records of a DNS message.

    Without this the sample would be quietly incoherent: it would say
    "example.com resolves to 93.x.x.x" and then show a connection to
    192.0.2.7, which teaches the reader that a name and its address disagree.
    """
    prefix = 0
    if len(data) > 2 and struct.unpack("!H", data[:2])[0] == len(data) - 2:
        prefix = 2  # DNS over TCP carries a 2-byte length prefix
    body = bytearray(data)

    if len(body) < prefix + 12:
        return bytes(body)
    # flags(2) then the four section counts. The transaction id is skipped.
    # struct.unpack needs the buffer to be exactly the format's size.
    _, qd, an, ns, ar = struct.unpack("!HHHHH", body[prefix + 2 : prefix + 12])
    offset = prefix + 12

    for _ in range(min(qd, 64)):  # questions hold no addresses
        offset = _skip_dns_name(body, offset) + 4
        if offset > len(body):
            return bytes(body)

    for _ in range(min(an + ns + ar, 512)):
        if offset + 10 > len(body):
            break
        offset = _skip_dns_name(body, offset)
        if offset + 10 > len(body):
            break
        rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", body[offset : offset + 10])
        offset += 10
        if offset + rdlength > len(body):
            break
        if rtype == 1 and rdlength == 4:            # A
            original = socket.inet_ntoa(bytes(body[offset : offset + 4]))
            body[offset : offset + 4] = socket.inet_aton(renamer.v4_name(original))
        elif rtype == 28 and rdlength == 16:        # AAAA
            original = socket.inet_ntop(socket.AF_INET6, bytes(body[offset : offset + 16]))
            body[offset : offset + 16] = socket.inet_pton(
                socket.AF_INET6, renamer.v6_name(original)
            )
        offset += rdlength

    return bytes(body)


def find_network(frame: bytes) -> tuple[int, int]:
    """Locate the network header: returns ``(offset, ethertype)``.

    Skips the Ethernet header and any 802.1Q/802.1ad VLAN tags. Returns
    ``(-1, 0)`` when the frame is not one we understand.
    """
    if len(frame) < 14:
        return -1, 0
    ethertype = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    while ethertype in (ETHERTYPE_VLAN, 0x88A8) and len(frame) >= offset + 4:
        ethertype = struct.unpack("!H", frame[offset + 2 : offset + 4])[0]
        offset += 4
    if ethertype not in (ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETHERTYPE_ARP):
        return -1, 0
    return offset, ethertype


def rewrite_frame(frame: bytes, renamer: Renamer) -> bytes:
    """Anonymise one frame in place, returning a new bytes object."""
    frame = bytearray(frame)

    # Zero the MAC addresses. They identify the local hardware, and no sample
    # capture needs them to demonstrate anything.
    if len(frame) >= 12:
        frame[0:6] = b"\x00" * 6
        frame[6:12] = b"\x00" * 6

    offset, ethertype = find_network(frame)
    if offset < 0:
        return bytes(frame)

    if ethertype == ETHERTYPE_ARP and len(frame) >= offset + 28:
        # sender/target protocol addresses live at +14 and +24
        for position in (offset + 14, offset + 24):
            original = socket.inet_ntoa(bytes(frame[position : position + 4]))
            frame[position : position + 4] = socket.inet_aton(renamer.v4_name(original))
        return bytes(frame)

    if ethertype == ETHERTYPE_IPV4:
        if len(frame) < offset + 20:
            return bytes(frame)
        version_ihl = frame[offset]
        if version_ihl >> 4 != 4:
            return bytes(frame)
        header_len = (version_ihl & 0x0F) * 4
        total_len = struct.unpack("!H", frame[offset + 2 : offset + 4])[0]
        protocol = frame[offset + 9]

        addresses = []
        for position in (offset + 12, offset + 16):
            original = socket.inet_ntoa(bytes(frame[position : position + 4]))
            replacement = socket.inet_aton(renamer.v4_name(original))
            frame[position : position + 4] = replacement
            addresses.append(replacement)

        if header_len >= 20:
            frame[offset : offset + header_len] = fix_ipv4_checksum(
                bytes(frame[offset : offset + header_len])
            )
        if total_len > header_len and total_len <= len(frame):
            datagram = bytearray(frame[offset : offset + total_len])
            # A DNS payload names addresses in its own A/AAAA records. Rewrite
            # them too, then re-derive the transport checksum, which covers the
            # DNS bytes.
            transport = bytes(datagram[header_len:])
            source_port, destination_port = struct.unpack("!HH", transport[:4])
            # Either port: a query is addressed *to* 53, a response comes
            # *from* 53. Checking only the destination misses every answer.
            dns_port = 53
            on_dns_port = source_port == dns_port or destination_port == dns_port
            if protocol == 17 and on_dns_port:
                # Skip the 8-byte UDP header: rewrite_dns wants the DNS message.
                datagram[header_len + 8:] = rewrite_dns(transport[8:], renamer)
            elif protocol == 6 and on_dns_port:
                # DNS over TCP prefixes the message with a 2-byte length.
                datagram[header_len + 2:] = rewrite_dns(transport[2:], renamer)
            frame[offset : offset + total_len] = fix_transport_checksums(
                bytes(datagram), header_len, total_len, protocol, tuple(addresses),
            )
        return bytes(frame)

    if ethertype == ETHERTYPE_IPV6:
        if len(frame) < offset + 40 or (frame[offset] >> 4) != 6:
            return bytes(frame)
        addresses = []
        for position in (offset + 8, offset + 24):
            original = socket.inet_ntop(socket.AF_INET6, bytes(frame[position : position + 16]))
            replacement = socket.inet_pton(socket.AF_INET6, renamer.v6_name(original))
            frame[position : position + 16] = replacement
            addresses.append(replacement)
        return bytes(frame)

    return bytes(frame)


def anonymise(path: str, output: str) -> tuple[int, dict[str, str]]:
    """Rewrite every frame in ``path`` into ``output``."""
    renamer = Renamer()
    packets: list[RawPacket] = []
    with PcapReader(path) as reader:
        link_type = reader.link_type
        for raw in reader:
            packets.append(
                RawPacket(
                    ts=raw.ts,
                    data=rewrite_frame(raw.data, renamer),
                    orig_len=raw.orig_len,
                    link_type=raw.link_type,
                )
            )
    write_pcap(output, packets, link_type)
    return len(packets), {**renamer.v4, **renamer.v6}


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {os.path.basename(argv[0])} <capture.pcap>", file=sys.stderr)
        print(__doc__, file=sys.stderr)
        return 2
    path = argv[1]
    if not os.path.exists(path):
        print(f"error: no such file: {path}", file=sys.stderr)
        return 2

    output = path
    count, mapping = anonymise(path, output)
    print(f"rewrote {count} packet(s) in {output}\n")
    for original, replacement in sorted(mapping.items(), key=lambda kv: kv[1]):
        print(f"  {original:>40}  ->  {replacement}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
