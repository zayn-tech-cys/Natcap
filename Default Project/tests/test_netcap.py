"""
Tests for netcap.

The dissectors are validated against packets built by scapy, so the bytes under
test are known-good by construction. Where scapy is unavailable the packet
builders fall back to hand-assembled byte strings, and the network-dependent
tests are skipped.

Run with::

    python -m unittest discover -s tests -v
    python tests/test_netcap.py
"""

from __future__ import annotations

import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netcap import appproto, filter as filter_mod, pcap
from netcap.dissect import dissect
from netcap.filter import compile_filter
from netcap.stats import TrafficStats, human_bytes, human_duration

try:
    from scapy.all import (  # type: ignore
        DNS, DNSQR, Ether, ICMP, IP, Raw, TCP, UDP,
    )
    HAVE_SCAPY = True
except ImportError:  # pragma: no cover
    HAVE_SCAPY = False

MAC_A = "00:11:22:33:44:55"
MAC_B = "66:77:88:99:aa:bb"


def build(packet) -> bytes:
    """Ethernet bytes for a scapy packet."""
    return bytes(packet)


def dissect_packet(packet, index: int = 1):
    """Build with scapy, then dissect with netcap."""
    return dissect(build(packet), pcap.LINKTYPE_ETHERNET, 1700000000.0, index)


# ---------------------------------------------------------------------------
# Hand-built packets, so the core tests run with no third-party packages
# ---------------------------------------------------------------------------


def ethernet(dst: bytes, src: bytes, ethertype: int, payload: bytes) -> bytes:
    return dst + src + struct.pack("!H", ethertype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64,
         ident: int = 0x1234, flags: int = 0x4000, frag_offset: int = 0) -> bytes:
    import socket

    total_length = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0x00, total_length, ident,
        flags | frag_offset, ttl, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    return header + payload


def tcp(sport: int, dport: int, seq: int, ack: int, flags: int,
        payload: bytes = b"", options: bytes = b"") -> bytes:
    data_offset = (20 + len(options)) // 4
    header = struct.pack(
        "!HHIIHHHH", sport, dport, seq, ack,
        (data_offset << 12) | flags, 8192, 0, 0,
    )
    return header + options + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def arp_packet(operation: int, sender_mac: str, sender_ip: str,
               target_mac: str, target_ip: str) -> bytes:
    import socket

    def mac(text: str) -> bytes:
        return bytes(int(part, 16) for part in text.split(":"))

    return (
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, operation)
        + mac(sender_mac) + socket.inet_aton(sender_ip)
        + mac(target_mac) + socket.inet_aton(target_ip)
    )


def dns_query(name: str, qtype: int = 1, txid: int = 0xBEEF) -> bytes:
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(label)]) + label.encode() for label in name.split(".")
    ) + b"\x00"
    return header + qname + struct.pack("!HH", qtype, 1)


def dns_response(name: str, address: str, txid: int = 0xBEEF) -> bytes:
    """A response that uses a compression pointer back to the question name."""
    import socket

    header = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0)
    qname = b"".join(
        bytes([len(label)]) + label.encode() for label in name.split(".")
    ) + b"\x00"
    question = qname + struct.pack("!HH", 1, 1)
    # The answer's owner name is a pointer to offset 12 (the question's QNAME).
    answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 300, 4) + socket.inet_aton(address)
    return header + question + answer


# ---------------------------------------------------------------------------
# Link and network layer
# ---------------------------------------------------------------------------


class TestLinkLayer(unittest.TestCase):
    def test_ethernet_ipv4_tcp(self):
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1234, 80, 100, 200, 0x018)),
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        # ethernet() takes (dst, src, ...); the frame above sends to MAC_A.
        self.assertEqual(info.dst_mac, MAC_A)
        self.assertEqual(info.src_mac, MAC_B)
        self.assertEqual(info.src_ip, "10.0.0.1")
        self.assertEqual(info.dst_ip, "10.0.0.2")
        self.assertEqual(info.l4_proto, "tcp")
        self.assertEqual(info.src_port, 1234)
        self.assertEqual(info.dst_port, 80)
        self.assertEqual(info.ip_version, 4)
        self.assertEqual(info.ttl, 64)
        self.assertTrue(info.ip_df)
        self.assertEqual([name for name, _ in info.layers], ["Ethernet", "IPv4", "TCP"])

    def test_raw_ip_link_type(self):
        # No Ethernet header at all: the version nibble must be enough.
        frame = ipv4("192.168.1.5", "8.8.8.8", 17, udp(5353, 5353, b"\x00" * 8))
        info = dissect(frame, pcap.LINKTYPE_RAW, 1.0, 1)
        self.assertIsNone(info.src_mac)
        self.assertEqual(info.src_ip, "192.168.1.5")
        self.assertEqual(info.l4_proto, "udp")
        self.assertEqual(info.src_port, 5353)

    def test_vlan_tag(self):
        inner = ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 2, 3, 4, 0x002))
        # Tag control information: priority 3 in bits 0-2, VLAN 100 in bits 4-11.
        tci = (3 << 13) | 100
        tagged = struct.pack("!HH", tci, 0x0800)
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"),
            0x8100, tagged + inner,
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        self.assertEqual(info.src_ip, "10.0.0.1")
        self.assertEqual(info.l4_proto, "tcp")
        self.assertEqual(info.ethertype, 0x0800)
        self.assertIn("802.1Q", [name for name, _ in info.layers])
        vlan = dict(info.layers)["802.1Q"]
        self.assertEqual(vlan["VLAN ID"], "100")
        self.assertEqual(vlan["priority"], "3")

    def test_ethernet_padding_is_not_payload(self):
        # A 60-byte IP datagram inside a 64-byte minimum Ethernet frame.
        body = tcp(1, 2, 3, 4, 0x018, b"hello")
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"),
            0x0800, ipv4("10.0.0.1", "10.0.0.2", 6, body) + b"\x00" * 6,
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        self.assertEqual(info.payload, b"hello")

    def test_truncated_frame_is_flagged(self):
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 2, 3, 4, 0x018, b"abcdefgh")),
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1, wire_len=1514)
        self.assertTrue(info.truncated)
        self.assertTrue(any("truncated" in n for n in info.notes))


class TestDetailFlag(unittest.TestCase):
    """detail=False skips the layer tree; it must not change any real result."""

    def frames(self):
        yield ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1234, 443, 10, 20, 0x018,
                                                b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n")),
        )
        yield ethernet(
            bytes(6), bytes.fromhex("001122334455"), 0x0806,
            arp_packet(1, MAC_A, "10.0.0.1", "00:00:00:00:00:00", "10.0.0.2"),
        )
        yield ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.1", "10.0.0.2", 17, udp(5000, 53, dns_query("example.com"))),
        )
        yield ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.1", "10.0.0.2", 1, b"\x08\x00\x12\x34\x00\x01\x00\x01" + b"ping"),
        )
        tci = (3 << 13) | 100
        yield ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x8100,
            struct.pack("!HH", tci, 0x0800)
            + ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 2, 3, 4, 0x002)),
        )
        yield ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 443, 1, 2, 0x018,
                                                build_tls_client_hello())),
        )

    SCALARS = (
        "src_mac", "dst_mac", "ethertype", "ip_version", "src_ip", "dst_ip",
        "ttl", "ip_proto", "ip_id", "ip_df", "ip_offset", "ip_total_len",
        "fragmented", "l4_proto", "src_port", "dst_port", "seq", "ack",
        "flags", "window", "udp_length", "icmp_type", "icmp_code", "arp",
        "payload", "notes", "captured_len", "wire_len",
    )

    def test_scalars_are_identical(self):
        for index, frame in enumerate(self.frames(), start=1):
            with self.subTest(frame=index):
                full = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, index, detail=True)
                lean = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, index, detail=False)
                for name in self.SCALARS:
                    self.assertEqual(
                        getattr(full, name), getattr(lean, name),
                        f"{name} differs between detail=True and detail=False",
                    )

    def test_application_facts_survive(self):
        """The host name and DNS question are used by the summary, not just -v."""
        http_frame = next(iter(self.frames()))
        lean = dissect(http_frame, pcap.LINKTYPE_ETHERNET, 1.0, 1, detail=False)
        self.assertEqual(lean.app["proto"], "http")
        self.assertEqual(lean.app["extra"]["host"], "a.example")

        tls_frame = list(self.frames())[-1]
        lean = dissect(tls_frame, pcap.LINKTYPE_ETHERNET, 1.0, 1, detail=False)
        self.assertEqual(lean.app["proto"], "tls")
        self.assertEqual(lean.app["extra"]["sni"], ["secure.example.com"])

    def test_layer_tree_is_omitted(self):
        lean = dissect(next(iter(self.frames())), pcap.LINKTYPE_ETHERNET, 1.0, 1,
                       detail=False)
        self.assertEqual(lean.layers, [])
        full = dissect(next(iter(self.frames())), pcap.LINKTYPE_ETHERNET, 1.0, 1,
                       detail=True)
        self.assertTrue(full.layers)

    def test_display_still_works_without_a_layer_tree(self):
        from netcap import display

        style = display.Style(enabled=False)
        lean = dissect(next(iter(self.frames())), pcap.LINKTYPE_ETHERNET, 1.0, 1,
                       detail=False)
        line = display.packet_line(lean, style, True)
        self.assertIn("10.0.0.1", line)
        self.assertIn("GET", line)


class TestArp(unittest.TestCase):
    def test_arp_request(self):
        frame = ethernet(
            bytes(6), bytes.fromhex("001122334455"), 0x0806,
            arp_packet(1, MAC_A, "10.0.0.1", "00:00:00:00:00:00", "10.0.0.2"),
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        self.assertEqual(info.l4_proto, "arp")
        self.assertEqual(info.arp["operation"], "who-has")
        self.assertEqual(info.arp["sender_ip"], "10.0.0.1")
        self.assertEqual(info.arp["target_ip"], "10.0.0.2")
        self.assertEqual(info.payload, b"")
        self.assertIn("ARP", info.summary)

    def test_arp_reply(self):
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0806,
            arp_packet(2, MAC_B, "10.0.0.2", MAC_A, "10.0.0.1"),
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        self.assertEqual(info.arp["operation"], "is-at")
        self.assertEqual(info.arp["sender_mac"], MAC_B)


class TestIPv4Flags(unittest.TestCase):
    def test_non_first_fragment_has_no_transport_header(self):
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.1", "10.0.0.2", 6, b"\xaa" * 16, flags=0x0000, frag_offset=185),
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        self.assertEqual(info.l4_proto, "ip-frag")
        self.assertTrue(info.fragmented)
        self.assertTrue(any("non-first" in n for n in info.notes))
        self.assertEqual(info.payload, b"\xaa" * 16)

    def test_dont_and_more_fragments(self):
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 2, 3, 4, 0x018), flags=0x2000),
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        self.assertTrue(info.fragmented)
        self.assertFalse(info.ip_df)
        self.assertEqual(dict(info.layers)["IPv4"]["Flags"], "MF")


class TestIPv6(unittest.TestCase):
    def test_ipv6_udp(self):
        import socket

        udp_header = udp(54678, 53, b"\xaa" * 8)
        header = (
            struct.pack("!IHBB", 6 << 28, len(udp_header), 17, 64)
            + socket.inet_pton(socket.AF_INET6, "2001:db8::1")
            + socket.inet_pton(socket.AF_INET6, "2001:db8::2")
        )
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"),
            0x86DD, header + udp_header,
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        self.assertEqual(info.ip_version, 6)
        self.assertEqual(info.src_ip, "2001:db8::1")
        self.assertEqual(info.dst_ip, "2001:db8::2")
        self.assertEqual(info.l4_proto, "udp")
        self.assertEqual(info.ttl, 64)  # hop limit
        self.assertEqual(info.dst_port, 53)


class TestTCPOptions(unittest.TestCase):
    def test_mss_sack_timestamp_wscale(self):
        # Real option kinds: 2=MSS, 4=SACK-permitted, 3=window scale,
        # 8=timestamp, 1=NOP. The block must total a multiple of 4 bytes,
        # because the data-offset field counts in 32-bit words.
        options = (
            b"\x02\x04\x05\xb4"            # MSS 1460
            + b"\x04\x02\x01\x01"          # SACK permitted, NOP-padded
            + b"\x03\x03\x07\x01"          # window scale 7, NOP-padded
            + b"\x08\x0a" + struct.pack("!II", 3829314, 10993544)  # timestamp
            + b"\x01\x01"                  # pad to a 4-byte boundary
        )
        self.assertEqual(len(options) % 4, 0)
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1234, 443, 1, 2, 0x018, options=options)),
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        rendered = dict(info.layers)["TCP"]["Options"]
        self.assertIn("MSS=1460", rendered)
        self.assertIn("WScale=7", rendered)
        self.assertIn("SACKok", rendered)
        self.assertIn("TSval=3829314", rendered)
        self.assertIn("TSecr=10993544", rendered)
        self.assertNotIn("opt-", rendered)  # nothing should be unrecognised
        self.assertEqual(info.payload, b"")

    def test_flag_names(self):
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 2, 3, 4, 0x002 | 0x010)),
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        self.assertEqual(sorted(info.flags), ["ack", "syn"])

    def test_rst_does_not_claim_to_be_the_ns_bit(self):
        """0x004 is RST; the NS bit is 0x100. Easy to confuse, so pin it down."""
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 2, 3, 4, 0x004 | 0x010)),
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        self.assertEqual(sorted(info.flags), ["ack", "rst"])
        self.assertFalse(any("nonce" in note for note in info.notes),
                         f"RST was misreported as the NS bit: {info.notes}")

    def test_ns_bit_is_recognised(self):
        # NS lives in the offset/flags field at bit 8, not in the low 8 bits.
        body = tcp(1, 2, 3, 4, 0x010)  # ACK only
        body = body[:12] + b"\x51" + body[13:]  # data offset 5, NS bit set
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.1", "10.0.0.2", 6, body),
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        self.assertIn("ns", info.flags)
        self.assertTrue(any("nonce" in note for note in info.notes))


# ---------------------------------------------------------------------------
# Application layer
# ---------------------------------------------------------------------------


class TestDNS(unittest.TestCase):
    def test_query(self):
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.1", "10.0.0.2", 17, udp(53124, 53, dns_query("example.com"))),
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        self.assertIsNotNone(info.app)
        self.assertEqual(info.app["proto"], "dns")
        extra = info.app["extra"]
        self.assertFalse(extra["is_response"])
        self.assertEqual(extra["question"], "example.com")
        self.assertEqual(info.app["fields"]["Transaction ID"], "0xbeef")
        self.assertIn("recursion desired", info.app["fields"].get("RD", ""))

    def test_response_with_compression_pointer(self):
        payload = dns_response("example.com", "93.184.216.34")
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.2", "10.0.0.1", 17, udp(53, 53124, payload)),
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        self.assertEqual(info.app["proto"], "dns")
        extra = info.app["extra"]
        self.assertTrue(extra["is_response"])
        answers = extra["answers"]
        self.assertEqual(len(answers), 1)
        # The answer's owner name is a pointer, so it must resolve back.
        self.assertIn("example.com", answers[0])
        self.assertIn("93.184.216.34", answers[0])

    def test_malformed_dns_does_not_crash(self):
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.1", "10.0.0.2", 17, udp(1000, 53, b"\xff" * 20)),
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        # Either no decode, or a decode that did not raise. Must not blow up.
        self.assertTrue(info.app is None or info.app["proto"] == "dns")

    def test_pointer_loop_terminates(self):
        # A compression pointer aimed at itself must not spin forever.
        payload = struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0) + b"\xc0\x0c" + b"\x00" * 20
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.2", "10.0.0.1", 17, udp(53, 1000, payload)),
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        self.assertIsNotNone(info)


class TestHTTP(unittest.TestCase):
    def test_get_request(self):
        request = (
            b"GET /index.html?q=1 HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"User-Agent: netcap-test/1.0\r\n"
            b"Accept: */*\r\n"
            b"\r\n"
        )
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.1", "10.0.0.2", 6, tcp(50000, 80, 1, 1, 0x018, request)),
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        self.assertEqual(info.app["proto"], "http")
        extra = info.app["extra"]
        self.assertEqual(extra["method"], "GET")
        self.assertEqual(extra["uri"], "/index.html?q=1")
        self.assertEqual(extra["host"], "example.com")
        self.assertEqual(extra["user_agent"], "netcap-test/1.0")

    def test_response_status(self):
        response = (
            b"HTTP/1.1 404 Not Found\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: 5\r\n"
            b"\r\n"
            b"nope!"
        )
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.2", "10.0.0.1", 6, tcp(80, 50000, 1, 1, 0x018, response)),
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        self.assertEqual(info.app["proto"], "http")
        self.assertEqual(info.app["extra"]["status"], "404")
        self.assertEqual(info.app["extra"]["body_len"], 5)
        self.assertEqual(info.payload, response)

    def test_post_with_body(self):
        body = b'{"a":1}'
        request = (
            b"POST /api HTTP/1.1\r\nHost: api.example.com\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 7\r\n\r\n" + body
        )
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 8080, 1, 1, 0x018, request)),
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        self.assertEqual(info.app["extra"]["method"], "POST")
        self.assertEqual(info.app["extra"]["content_type"], "application/json")

    def test_cookie_value_is_not_printed(self):
        request = (
            b"GET / HTTP/1.1\r\nHost: example.com\r\n"
            b"Cookie: session=supersecretvalue\r\n\r\n"
        )
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 80, 1, 1, 0x018, request)),
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        self.assertTrue(info.app["extra"].get("has_credentials"))
        # The secret must not survive anywhere in the rendered fields.
        self.assertNotIn("supersecretvalue", str(info.app["fields"]))

    def test_authorization_value_is_not_printed(self):
        request = (
            b"GET / HTTP/1.1\r\nHost: api.example.com\r\n"
            b"Authorization: Bearer tok_live_abcdef123456\r\n\r\n"
        )
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 80, 1, 1, 0x018, request)),
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        self.assertNotIn("tok_live_abcdef123456", str(info.app["fields"]))

    def test_ordinary_headers_are_still_shown(self):
        request = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\n\r\n"
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 80, 1, 1, 0x018, request)),
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        self.assertIn("Accept: text/html", info.app["fields"]["Headers"])

    def test_non_http_on_http_port_is_ignored(self):
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 80, 1, 1, 0x018, b"\x16\x03\x01")),
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        self.assertIsNone(info.app)


def build_tls_client_hello(sni: str = "secure.example.com",
                           alpn_protocol: str = "http/1.1") -> bytes:
    """A TLS 1.2 ClientHello record carrying an SNI and an ALPN extension.

    Built by hand from RFC 8446 section 4.1.2 so the test does not depend on a
    particular scapy version's TLS layer.
    """
    # server_name extension: list length, name type 0 (host_name), name
    name = sni.encode()
    server_name_list = b"\x00" + struct.pack("!H", len(name)) + name
    sni_body = struct.pack("!H", len(server_name_list)) + server_name_list

    # ALPN extension: protocol name list, each entry length-prefixed
    proto = alpn_protocol.encode()
    protocol_list = bytes([len(proto)]) + proto
    alpn_body = struct.pack("!H", len(protocol_list)) + protocol_list

    extensions = (
        struct.pack("!HH", 0, len(sni_body)) + sni_body
        + struct.pack("!HH", 16, len(alpn_body)) + alpn_body
    )

    body = (
        struct.pack("!H", 0x0303)                    # legacy_version TLS 1.2
        + b"\x00" * 32                               # random
        + b"\x00"                                    # legacy_session_id length
        + struct.pack("!H", 4) + b"\x13\x01\xc0\x2f"  # cipher suites
        + b"\x01\x00"                                # compression methods
        + struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


class TestTLS(unittest.TestCase):
    def test_client_hello_sni_and_alpn(self):
        payload = build_tls_client_hello()
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.1", "10.0.0.2", 6, tcp(51000, 443, 1, 1, 0x018, payload)),
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        self.assertEqual(info.app["proto"], "tls")
        extra = info.app["extra"]
        self.assertEqual(extra["sni"], ["secure.example.com"])
        self.assertEqual(extra["alpn"], ["http/1.1"])
        fields = info.app["fields"]
        self.assertIn("secure.example.com", fields["Server name (SNI)"])
        self.assertEqual(fields["Client version"], "TLS 1.2")
        self.assertIn("server_name", fields["Extensions"])

    def test_application_data_is_opaque(self):
        # TLS 1.3 record with encrypted content: we must not pretend to decode.
        payload = b"\x17\x03\x03" + struct.pack("!H", 32) + b"\xab" * 32
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.2", "10.0.0.1", 6, tcp(443, 51000, 1, 1, 0x018, payload)),
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        self.assertEqual(info.app["proto"], "tls")
        self.assertNotIn("sni", info.app["extra"])
        self.assertIn("encrypted", info.app["fields"]["Note"])

    def test_tls_detected_before_http(self):
        # A ClientHello begins with 0x16, which is not an HTTP method, but the
        # ordering in identify() must not let HTTP claim it.
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 443, 1, 1, 0x018,
                                                build_tls_client_hello())),
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        self.assertEqual(info.app["proto"], "tls")


# ---------------------------------------------------------------------------
# pcap container
# ---------------------------------------------------------------------------


class TestPcapFile(unittest.TestCase):
    def make_packets(self, count: int = 3):
        return [
            pcap.RawPacket(
                ts=1700000000.5 + i * 0.25,
                data=bytes([i]) * (40 + i),
                orig_len=40 + i,
                link_type=pcap.LINKTYPE_ETHERNET,
            )
            for i in range(count)
        ]

    def test_round_trip(self):
        original = self.make_packets()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "round-trip.pcap")
            written = pcap.write_pcap(path, original, pcap.LINKTYPE_ETHERNET)
            self.assertEqual(written, len(original))

            with pcap.PcapReader(path) as reader:
                self.assertEqual(reader.link_type, pcap.LINKTYPE_ETHERNET)
                got = list(reader)
            self.assertEqual(len(got), len(original))
            for before, after in zip(original, got):
                self.assertEqual(after.data, before.data)
                self.assertEqual(after.orig_len, before.orig_len)
                self.assertAlmostEqual(after.ts, before.ts, places=5)

    def test_reader_releases_the_file_when_closed_early(self):
        """Breaking out early must not leave the file locked (Windows)."""
        original = self.make_packets(count=20)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "early-close.pcap")
            pcap.write_pcap(path, original, pcap.LINKTYPE_ETHERNET)
            reader = pcap.PcapReader(path)
            next(iter(reader))  # read one, then abandon the rest
            reader.close()
            # TemporaryDirectory cleanup would raise PermissionError on
            # Windows if a handle were still open.
            with open(path, "rb") as handle:
                self.assertTrue(handle.read(4))

    def test_truncation_survives_the_round_trip(self):
        original = [pcap.RawPacket(ts=1.0, data=b"\x01" * 20, orig_len=1514,
                                   link_type=1)]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "trunc.pcap")
            pcap.write_pcap(path, original, 1)
            with pcap.PcapReader(path) as reader:
                packet = next(iter(reader))
            self.assertTrue(packet.truncated)
            self.assertEqual(len(packet.data), 20)
            self.assertEqual(packet.orig_len, 1514)

    def test_rejects_non_pcap_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "not-a-capture.pcap")
            with open(path, "wb") as handle:
                handle.write(b"this is definitely not a pcap file at all")
            with self.assertRaises(pcap.PcapError):
                pcap.read_pcap(path)

    def test_scapy_can_read_our_pcap(self):
        """The file we write must be readable by the tool people will use next."""
        if not HAVE_SCAPY:
            self.skipTest("scapy not installed")
        from scapy.utils import rdpcap  # type: ignore

        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1234, 80, 1, 2, 0x018)),
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "for-scapy.pcap")
            pcap.write_pcap(path, [pcap.RawPacket(ts=1.0, data=frame, orig_len=len(frame),
                                                 link_type=1)], 1)
            read_back = rdpcap(path)
            self.assertEqual(len(read_back), 1)
            packet = read_back[0]
            self.assertEqual(packet[IP].src, "10.0.0.1")
            self.assertEqual(packet[TCP].dport, 80)

    def test_scapy_packet_dissects_consistently(self):
        """Our dissector should agree with scapy on a scapy-built packet."""
        if not HAVE_SCAPY:
            self.skipTest("scapy not installed")
        packet = (
            Ether(src=MAC_A, dst=MAC_B)
            / IP(src="192.168.1.10", dst="1.1.1.1", ttl=55, id=4242)
            / TCP(sport=1234, dport=443, flags="SA", seq=100, ack=200, window=8192)
        )
        info = dissect_packet(packet)
        self.assertEqual(info.src_ip, "192.168.1.10")
        self.assertEqual(info.dst_ip, "1.1.1.1")
        self.assertEqual(info.ttl, 55)
        self.assertEqual(info.ip_id, 4242)
        self.assertEqual(info.src_port, 1234)
        self.assertEqual(info.dst_port, 443)
        self.assertEqual(sorted(info.flags), ["ack", "syn"])
        self.assertEqual(info.window, 8192)

    def test_scapy_dns_dissects(self):
        if not HAVE_SCAPY:
            self.skipTest("scapy not installed")
        packet = (
            Ether(src=MAC_A, dst=MAC_B)
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=40000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="www.example.org", qtype="A"))
        )
        info = dissect_packet(packet)
        self.assertEqual(info.app["proto"], "dns")
        self.assertEqual(info.app["extra"]["question"], "www.example.org")

    def test_scapy_icmp_dissects(self):
        if not HAVE_SCAPY:
            self.skipTest("scapy not installed")
        packet = (
            Ether(src=MAC_A, dst=MAC_B)
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / ICMP(type=8, code=0, id=1, seq=1)
            / Raw(b"ping-payload")
        )
        info = dissect_packet(packet)
        self.assertEqual(info.l4_proto, "icmp")
        self.assertEqual(info.icmp_type, 8)
        self.assertEqual(info.icmp_code, 0)


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------


class TestFilter(unittest.TestCase):
    def make(self, **kwargs):
        """Build a dissected packet with sensible defaults for filter tests."""
        defaults = dict(
            data=None, link_type=pcap.LINKTYPE_ETHERNET, ts=1.0, index=1,
        )
        defaults.update(kwargs)
        return dissect(**defaults)

    def tcp_packet(self, src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=80):
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4(src, dst, 6, tcp(sport, dport, 1, 2, 0x018, b"data")),
        )
        return dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)

    def udp_packet(self, src="10.0.0.1", dst="10.0.0.2", sport=5000, dport=53):
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4(src, dst, 17, udp(sport, dport, dns_query("example.com"))),
        )
        return dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)

    def arp_packet_info(self):
        frame = ethernet(
            bytes(6), bytes.fromhex("001122334455"), 0x0806,
            arp_packet(1, MAC_A, "10.0.0.1", "00:00:00:00:00:00", "10.0.0.2"),
        )
        return dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1)

    def test_empty_filter_matches_everything(self):
        predicate = compile_filter("")
        self.assertTrue(predicate(self.tcp_packet()))

    def test_protocol(self):
        tcp_only = compile_filter("tcp")
        self.assertTrue(tcp_only(self.tcp_packet()))
        self.assertFalse(tcp_only(self.udp_packet()))

    def test_port_either_direction(self):
        predicate = compile_filter("port 80")
        self.assertTrue(predicate(self.tcp_packet(sport=1234, dport=80)))
        self.assertTrue(predicate(self.tcp_packet(sport=80, dport=1234)))
        self.assertFalse(predicate(self.tcp_packet(sport=1, dport=2)))

    def test_direction(self):
        outgoing = compile_filter("dst port 443")
        self.assertTrue(outgoing(self.tcp_packet(dport=443)))
        self.assertFalse(outgoing(self.tcp_packet(sport=443, dport=1)))
        incoming = compile_filter("src port 443")
        self.assertTrue(incoming(self.tcp_packet(sport=443, dport=1)))
        self.assertFalse(incoming(self.tcp_packet(dport=443)))

    def test_host(self):
        predicate = compile_filter("host 10.0.0.2")
        self.assertTrue(predicate(self.tcp_packet(dst="10.0.0.2")))
        self.assertTrue(predicate(self.tcp_packet(src="10.0.0.2")))
        self.assertFalse(predicate(self.tcp_packet(src="10.0.0.1", dst="10.0.0.3")))

    def test_net(self):
        predicate = compile_filter("net 10.0.0.0/8")
        self.assertTrue(predicate(self.tcp_packet()))
        self.assertFalse(predicate(self.tcp_packet(src="192.168.1.1", dst="192.168.1.2")))

    def test_and_or_not(self):
        expression = "tcp and port 443 and not host 10.0.0.9"
        predicate = compile_filter(expression)
        self.assertTrue(predicate(self.tcp_packet(dport=443)))
        self.assertFalse(predicate(self.tcp_packet(dport=443, dst="10.0.0.9")))

        predicate = compile_filter("udp or arp")
        self.assertTrue(predicate(self.udp_packet()))
        self.assertTrue(predicate(self.arp_packet_info()))
        self.assertFalse(predicate(self.tcp_packet()))

    def test_parentheses(self):
        predicate = compile_filter("(tcp or udp) and host 10.0.0.2")
        self.assertTrue(predicate(self.tcp_packet(dst="10.0.0.2")))
        self.assertTrue(predicate(self.udp_packet(dst="10.0.0.2")))
        self.assertFalse(predicate(self.udp_packet(dst="10.0.0.5")))

    def test_proto_keyword(self):
        predicate = compile_filter("proto tcp")
        self.assertTrue(predicate(self.tcp_packet()))
        self.assertFalse(predicate(self.udp_packet()))

    def test_ip_and_ip6(self):
        predicate = compile_filter("ip")
        self.assertTrue(predicate(self.tcp_packet()))
        self.assertTrue(predicate(self.arp_packet_info()) is False)  # ARP has no IP layer

    def test_implicit_and(self):
        """tcpdump reads "tcp port 80" as "tcp and port 80"."""
        for expression in ("tcp port 80", "port 80 tcp"):
            with self.subTest(expression=expression):
                predicate = compile_filter(expression)
                self.assertTrue(predicate(self.tcp_packet(dport=80)))
                self.assertFalse(predicate(self.udp_packet()))
                self.assertFalse(predicate(self.tcp_packet(dport=443)))

    def test_implicit_and_with_direction(self):
        # "host X" matches either direction, so this accepts the host as
        # source or destination as long as the destination port is 80.
        predicate = compile_filter("host 10.0.0.2 dst port 80")
        self.assertTrue(predicate(self.tcp_packet(dst="10.0.0.2", dport=80)))
        self.assertTrue(predicate(self.tcp_packet(src="10.0.0.2", dport=80)))
        self.assertFalse(predicate(self.tcp_packet(src="10.0.0.2", dport=443)))
        self.assertFalse(predicate(self.tcp_packet(src="10.0.0.9", dst="10.0.0.8", dport=80)))

    def test_group_after_or(self):
        predicate = compile_filter("udp port 53 or (tcp port 80)")
        self.assertTrue(predicate(self.udp_packet(dport=53)))
        self.assertTrue(predicate(self.tcp_packet(dport=80)))
        self.assertFalse(predicate(self.tcp_packet(dport=443)))

    def test_implicit_and_does_not_swallow_or(self):
        predicate = compile_filter("tcp port 80 or udp port 53")
        self.assertTrue(predicate(self.tcp_packet(dport=80)))
        self.assertTrue(predicate(self.udp_packet(dport=53)))
        self.assertFalse(predicate(self.tcp_packet(dport=443)))

    def test_bad_expression_raises(self):
        for bad in ("tcp and", "port", "host", "((((", "proto nonsense"):
            with self.subTest(bad=bad):
                with self.assertRaises(filter_mod.FilterError):
                    compile_filter(bad)


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


class TestStats(unittest.TestCase):
    def frame_tcp(self, src, dst, sport, dport, size=100, payload=b"x" * 100):
        body = tcp(sport, dport, 1, 2, 0x018, payload)
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4(src, dst, 6, body),
        )
        return dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1, wire_len=size)

    def test_totals_and_protocol_mix(self):
        stat = TrafficStats()
        stat.add(self.frame_tcp("10.0.0.1", "10.0.0.2", 1000, 80))
        stat.add(self.frame_tcp("10.0.0.2", "10.0.0.1", 80, 1000))
        self.assertEqual(stat.packets, 2)
        self.assertEqual(stat.protocol_packets["tcp"], 2)
        self.assertEqual(stat.bytes, 200)

    def test_sent_and_received_are_separate(self):
        stat = TrafficStats()
        stat.add(self.frame_tcp("10.0.0.1", "10.0.0.2", 1000, 80, size=1000))
        stat.add(self.frame_tcp("10.0.0.2", "10.0.0.1", 80, 1000, size=1000))
        self.assertEqual(stat.ip_sent["10.0.0.1"], 1000)
        self.assertEqual(stat.ip_received["10.0.0.1"], 1000)
        self.assertEqual(stat.ip_sent["10.0.0.2"], 1000)
        self.assertEqual(stat.ip_received["10.0.0.2"], 1000)

    def test_flows_group_both_directions(self):
        stat = TrafficStats()
        for _ in range(3):
            stat.add(self.frame_tcp("10.0.0.1", "10.0.0.2", 1000, 80))
        for _ in range(2):
            stat.add(self.frame_tcp("10.0.0.2", "10.0.0.1", 80, 1000))
        self.assertEqual(len(stat.flows), 1)
        flow = next(iter(stat.flows.values()))
        self.assertEqual(flow.packets, 5)
        self.assertEqual(flow.a_to_b, 300)
        self.assertEqual(flow.b_to_a, 200)

    def test_distinct_conversations_stay_separate(self):
        stat = TrafficStats()
        stat.add(self.frame_tcp("10.0.0.1", "10.0.0.2", 1000, 80))
        stat.add(self.frame_tcp("10.0.0.1", "10.0.0.3", 1000, 80))
        self.assertEqual(len(stat.flows), 2)

    def test_dns_queries_are_collected_without_duplicates(self):
        stat = TrafficStats()
        for _ in range(3):
            frame = ethernet(
                bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
                ipv4("10.0.0.1", "10.0.0.2", 17, udp(5000, 53, dns_query("example.com"))),
            )
            stat.add(dissect(frame, pcap.LINKTYPE_ETHERNET, 1.0, 1))
        self.assertEqual(stat.dns_queries, ["example.com"])
        self.assertEqual(stat.app_packets["dns"], 3)

    def test_hostile_payloads_do_not_raise(self):
        """Fuzz-ish: random bytes must never make the dissector raise."""
        import random

        stat = TrafficStats()
        rng = random.Random(1234)
        for index in range(400):
            length = rng.randrange(0, 200)
            data = bytes(rng.randrange(256) for _ in range(length))
            for link_type in (1, 0, 101, 113, 108):
                info = dissect(data, link_type, 1.0, index)
                stat.add(info)
        self.assertEqual(stat.packets, 400 * 5)


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


class TestAnonymiser(unittest.TestCase):
    """The published sample must be safe to share and still teach correctly."""

    @classmethod
    def setUpClass(cls):
        cls.tools = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"
        )
        if not os.path.isdir(cls.tools):
            raise unittest.SkipTest("tools/ not present")
        sys.path.insert(0, cls.tools)
        try:
            import anonymise_pcap  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise unittest.SkipTest(f"anonymise_pcap not importable: {exc}")
        cls.mod = anonymise_pcap

    @staticmethod
    def ones_complement_sum(data: bytes) -> int:
        if len(data) % 2:
            data += b"\x00"
        total = 0
        for index in range(0, len(data), 2):
            total += (data[index] << 8) | data[index + 1]
            total = (total & 0xFFFF) + (total >> 16)
        return total & 0xFFFF

    def frames(self, protocol=6):
        payload = b"payload" * 4
        if protocol == 6:
            body = tcp(1234, 80, 1, 2, 0x018, payload)
        else:
            body = udp(1234, 53, payload)
        return ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.1.2.3", "93.184.216.34", protocol, body),
        )

    def test_addresses_are_replaced(self):
        renamer = self.mod.Renamer()
        out = self.mod.rewrite_frame(self.frames(), renamer)
        info = dissect(out, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        self.assertNotEqual(info.src_ip, "10.1.2.3")
        self.assertNotEqual(info.dst_ip, "93.184.216.34")
        for address in (info.src_ip, info.dst_ip):
            self.assertIn(address.split(".")[0], ("192", "198", "203"))

    def test_distinct_addresses_get_distinct_names(self):
        """A small fixed pool used to collapse two servers onto one address."""
        renamer = self.mod.Renamer()
        names = {renamer.v4_name(f"10.0.0.{n}") for n in range(1, 40)}
        self.assertEqual(len(names), 39, "pseudonyms collided")

    def test_same_address_maps_consistently(self):
        renamer = self.mod.Renamer()
        first = self.mod.rewrite_frame(self.frames(), renamer)
        second = self.mod.rewrite_frame(self.frames(), renamer)
        self.assertEqual(
            dissect(first, pcap.LINKTYPE_ETHERNET, 1.0, 1).src_ip,
            dissect(second, pcap.LINKTYPE_ETHERNET, 1.0, 1).src_ip,
        )

    def test_mac_addresses_are_zeroed(self):
        renamer = self.mod.Renamer()
        out = self.mod.rewrite_frame(self.frames(), renamer)
        info = dissect(out, pcap.LINKTYPE_ETHERNET, 1.0, 1)
        self.assertEqual(info.src_mac, "00:00:00:00:00:00")
        self.assertEqual(info.dst_mac, "00:00:00:00:00:00")

    def test_ipv4_checksum_is_valid(self):
        for protocol in (6, 17):
            with self.subTest(protocol=protocol):
                renamer = self.mod.Renamer()
                out = self.mod.rewrite_frame(self.frames(protocol), renamer)
                header = out[14:34]
                self.assertEqual(
                    self.ones_complement_sum(header), 0xFFFF,
                    "IPv4 header checksum does not validate after rewriting",
                )

    def test_transport_checksum_is_valid(self):
        for protocol in (6, 17):
            with self.subTest(protocol=protocol):
                renamer = self.mod.Renamer()
                out = self.mod.rewrite_frame(self.frames(protocol), renamer)
                total = struct.unpack("!H", out[16:18])[0]
                segment = out[14:14 + total]
                transport = segment[20:]
                pseudo = (
                    segment[12:16] + segment[16:20]
                    + struct.pack("!HH", 0, protocol)
                    + struct.pack("!H", len(transport))
                )
                self.assertEqual(
                    self.ones_complement_sum(pseudo + transport), 0xFFFF,
                    f"protocol {protocol} checksum does not validate",
                )

    def test_udp_length_field_is_not_clobbered(self):
        """A past bug wrote the checksum over the UDP length field."""
        renamer = self.mod.Renamer()
        out = self.mod.rewrite_frame(self.frames(17), renamer)
        total = struct.unpack("!H", out[16:18])[0]
        transport = out[14 + 20 : 14 + total]
        self.assertEqual(struct.unpack("!H", transport[4:6])[0], len(transport))

    def test_dns_a_records_are_rewritten(self):
        """Otherwise the sample would claim a name resolves to a stale address."""
        renamer = self.mod.Renamer()
        message = dns_response("example.com", "93.184.216.34")
        out = self.mod.rewrite_dns(message, renamer)
        decoded = appproto.decode_dns(out)
        self.assertIn("example.com", decoded["extra"]["answers"][0])
        self.assertNotIn("93.184.216.34", decoded["extra"]["answers"][0])

    def test_published_sample_is_fully_anonymised(self):
        """End-to-end check on the file that actually ships in the repo."""
        import ipaddress

        sample = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "examples", "sample.pcap",
        )
        if not os.path.exists(sample):
            self.skipTest("examples/sample.pcap not present")
        documentation = [
            ipaddress.ip_network(c) for c in
            ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
        ]
        checked = 0
        with pcap.PcapReader(sample) as reader:
            for raw in reader:
                info = dissect(raw.data, reader.link_type, raw.ts, detail=False)
                checked += 1
                for address in (info.src_ip, info.dst_ip):
                    if not address:
                        continue
                    self.assertTrue(
                        any(ipaddress.ip_address(address) in net for net in documentation),
                        f"{address} is not a documentation range",
                    )
                if info.src_mac:
                    self.assertEqual(info.src_mac, "00:00:00:00:00:00")
        self.assertGreater(checked, 0, "sample capture is empty")


class TestFormatting(unittest.TestCase):
    def test_human_bytes(self):
        self.assertEqual(human_bytes(0), "0 B")
        self.assertEqual(human_bytes(512), "512 B")
        self.assertEqual(human_bytes(1024), "1.0 KiB")
        self.assertEqual(human_bytes(1536), "1.5 KiB")
        self.assertEqual(human_bytes(1024 ** 2), "1.0 MiB")

    def test_human_duration(self):
        self.assertEqual(human_duration(0.25), "250ms")
        self.assertEqual(human_duration(4.2), "4.2s")
        self.assertEqual(human_duration(75), "1m15s")
        self.assertEqual(human_duration(3725), "1h02m05s")

    def test_hexdump_shape(self):
        from netcap.display import hexdump_lines

        lines = hexdump_lines(bytes(range(32)), width=16)
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith("00000000  00 01 02"))
        self.assertIn("................", lines[0])

    def test_display_never_crashes(self):
        from netcap import display

        style = display.Style(enabled=False)
        stat = TrafficStats()
        frame = ethernet(
            bytes.fromhex("001122334455"), bytes.fromhex("66778899aabb"), 0x0800,
            ipv4("10.0.0.1", "10.0.0.2", 17, udp(5000, 53, dns_query("example.com"))),
        )
        info = dissect(frame, pcap.LINKTYPE_ETHERNET, 1700000000.0, 1)
        stat.add(info)
        self.assertTrue(display.packet_line(info, style, True))
        self.assertTrue(display.packet_detail(info, style, True))
        self.assertIn("PROTOCOL MIX", display.summary_report(stat, style, True, 1))

    def test_style_disabled_emits_no_escapes(self):
        from netcap.display import Style

        self.assertEqual(Style(enabled=False)("x", "red", "bold"), "x")
        self.assertIn("\033[", Style(enabled=True)("x", "red"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
