"""
Application-layer decoders: DNS, HTTP and TLS.

The dissector has already peeled off the link, network and transport headers
and handed us the payload. This module looks at the ports to guess which
application protocol that payload belongs to, then decodes it.

Each decoder returns ``None`` when the bytes do not look like the protocol, so
a mis-guess is harmless.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:  # avoid a circular import at runtime
    from .dissect import PacketInfo

# Ports where we should try a given decoder.
DNS_PORTS = {53, 5353, 5355, 123}
HTTP_PORTS = {80, 8080, 8000, 8888, 8081, 5000, 3128, 8009, 9090, 80}
TLS_PORTS = {443, 993, 995, 465, 636, 853, 989, 990, 992, 5061, 8443, 9443}

DNS_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 35: "NAPTR", 41: "OPT", 43: "DS", 48: "DNSKEY",
    52: "TLSA", 64: "SVCB", 65: "HTTPS", 251: "IXFR", 252: "AXFR", 255: "ANY",
}

DNS_CLASSES = {1: "IN", 3: "CH", 4: "HS", 255: "ANY"}

DNS_RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP",
    5: "REFUSED", 9: "NOTAUTH", 10: "NOTZONE",
}

DNS_OPCODES = {0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE"}

# HTTP request methods we are likely to see, longest-first so prefix matching
# does not mistake a short method for a longer one.
HTTP_METHODS = [
    "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE", "CONNECT",
    "PATCH", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK",
    "UNLOCK", "REPORT", "SEARCH", "RPC_IN_DATA", "RPC_OUT_DATA",
]

TLS_HANDSHAKE_TYPES = {
    0: "hello-request", 1: "client-hello", 2: "server-hello",
    4: "new-session-ticket", 8: "encrypted-extensions", 11: "certificate",
    12: "server-key-exchange", 13: "certificate-request",
    14: "server-hello-done", 15: "certificate-verify", 16: "client-key-exchange",
    20: "finished", 24: "key-update",
}

TLS_VERSIONS = {
    0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2",
    0x0304: "TLS 1.3", 0x0305: "TLS 1.3 (draft)",
}

TLS_EXTENSIONS = {
    0: "server_name", 5: "status_request", 10: "supported_groups",
    11: "ec_point_formats", 13: "signature_algorithms", 16: "ALPN",
    17: "status_request_v2", 18: "signed_certificate_timestamp",
    21: "padding", 22: "encrypt_then_mac", 23: "extended_master_secret",
    28: "record_size_limit", 35: "session_ticket", 41: "pre_shared_key",
    42: "early_data", 43: "supported_versions", 44: "cookie",
    45: "psk_key_exchange_modes", 49: "post_handshake_auth",
    50: "signature_algorithms_cert", 51: "key_share", 65281: "renegotiation_info",
}

ALPN_PROTOCOLS = {
    b"\x08http/1.1": "http/1.1", b"\x08h2": "h2", b"\x08http/1.0": "http/1.0",
    b"\x06spdy/3": "spdy/3", b"\x08http/1.1h2": "http/1.1+h2",
}


def identify(info: "PacketInfo", detail: bool = True) -> Optional[dict[str, Any]]:
    """Pick and run an application decoder for this packet's payload.

    Args:
        info:   a dissected packet, with the transport headers already parsed.
        detail: build the human-readable ``fields`` mapping used by the verbose
                layer tree. The compact ``extra`` facts (the DNS question, the
                TLS server name, the HTTP host) are always collected, because
                the one-line display and the statistics both use them.

    Returns:
        ``{"proto": "dns", "label": "DNS", "fields": {...}, "extra": ...}`` or
        None when there is nothing decodable to show.
    """
    if info.l4_proto not in ("tcp", "udp") or not info.payload:
        return None

    ports = {info.src_port, info.dst_port}
    payload = info.payload

    if info.l4_proto == "udp" and ports & DNS_PORTS:
        decoded = decode_dns(payload, detail)
        if decoded:
            return decoded

    if info.l4_proto == "udp":
        return None  # no other UDP decoder yet

    if info.l4_proto == "tcp":
        # TLS first: 0x16/0x17 record bytes would never parse as HTTP.
        if ports & TLS_PORTS or payload[:1] in (b"\x16", b"\x17", b"\x14", b"\x15"):
            decoded = decode_tls(payload, detail)
            if decoded:
                return decoded
        if ports & HTTP_PORTS or payload[:1] in (b"G", b"P", b"H", b"D", b"O", b"C"):
            decoded = decode_http(payload, detail)
            if decoded:
                return decoded
    return None


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


def _read_name(data: bytes, offset: int, depth: int = 0) -> tuple[Optional[str], int]:
    """Read a DNS name, following compression pointers.

    Returns:
        (name, offset just past the name in the *current* record). Pointers are
        followed with a depth limit to stop a malicious/crafted capture from
    sending us into a loop.
    """
    labels: list[str] = []
    jumped = False
    end = offset
    # A name is at most 255 bytes on the wire.
    hops = 0
    while offset < len(data) and hops < 128:
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            if offset + 1 >= len(data):
                return None, end
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
                jumped = True
            offset = pointer
            hops += 1
            continue
        offset += 1
        if offset + length > len(data):
            return None, end
        labels.append(data[offset : offset + length].decode("latin-1"))
        offset += length
        if not jumped:
            end = offset
    else:
        return None, end

    name = ".".join(labels) if labels else "."
    return name, end


def _read_rdata(data: bytes, rtype: int, start: int, length: int) -> str:
    """Render a record's rdata as a short string."""
    import socket as _socket

    chunk = data[start : start + length]
    try:
        if rtype == 1 and length == 4:
            return _socket.inet_ntoa(chunk)
        if rtype == 28 and length == 16:
            return _socket.inet_ntop(_socket.AF_INET6, chunk)
        if rtype in (2, 5, 12):
            return _read_name(data, start)[0] or "?"
        if rtype == 15 and length >= 2:
            return f"pref={struct.unpack('!H', chunk[:2])[0]} {chunk[2:].decode('latin-1', 'replace')}"
        if rtype == 16 and length >= 1:
            # TXT strings are length-prefixed, possibly several of them.
            parts, pos = [], 0
            while pos < len(chunk):
                size = chunk[pos]
                parts.append(chunk[pos + 1 : pos + 1 + size].decode("latin-1", "replace"))
                pos += 1 + size
            return " ".join(parts)[:60]
    except (OSError, struct.error):
        return "?"
    return chunk[:32].hex() + ("..." if length > 32 else "")


def decode_dns(data: bytes, detail: bool = True) -> Optional[dict[str, Any]]:
    """Decode a DNS message (over UDP or TCP, with the 2-byte TCP length prefix)."""
    # RFC 1035 section 4.2.2: over TCP, messages are prefixed with a 16-bit length.
    if len(data) > 2 and struct.unpack("!H", data[:2])[0] == len(data) - 2:
        data = data[2:]
    if len(data) < 12:
        return None

    msg_id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    opcode = (flags >> 11) & 0xF
    rcode = flags & 0xF
    is_response = bool(flags & 0x8000)
    authoritative = bool(flags & 0x0400)
    truncated = bool(flags & 0x0200)
    recursion_desired = bool(flags & 0x0100)
    recursion_available = bool(flags & 0x0080)

    fields: dict[str, Any] = {
        "Transaction ID": f"0x{msg_id:04x}",
        "Flags": f"0x{flags:04x} ({'response' if is_response else 'query'}, "
                 f"opcode={DNS_OPCODES.get(opcode, opcode)}, "
                 f"rcode={DNS_RCODES.get(rcode, rcode)})",
        "Questions": str(qd),
        "Answer RRs": str(an),
        "Authority RRs": str(ns),
        "Additional RRs": str(ar),
    }
    if recursion_desired:
        fields["RD"] = "recursion desired"
    if recursion_available:
        fields["RA"] = "recursion available"
    if authoritative:
        fields["AA"] = "authoritative"
    if truncated:
        fields["TC"] = "truncated"

    extra: dict[str, Any] = {"is_response": is_response, "id": msg_id}
    if not detail:
        # The one-line display and the statistics only need the question and
        # the answer values, so skip building the pretty field mapping.
        fields = {}

    offset = 12
    questions: list[str] = []
    for _ in range(min(qd, 16)):  # cap so a bogus count cannot loop forever
        name, offset = _read_name(data, offset)
        if name is None or offset + 4 > len(data):
            break
        qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        questions.append(
            f"{name} {DNS_TYPES.get(qtype, str(qtype))} "
            f"{DNS_CLASSES.get(qclass, str(qclass))}"
        )
    if questions:
        fields["Query"] = "; ".join(questions[:4])
        extra["question"] = questions[0].rsplit(" ", 2)[0] if questions else ""

    answers: list[str] = []
    for _ in range(min(an, 16)):
        if offset + 10 > len(data):
            break
        name, offset = _read_name(data, offset)
        rtype, rclass, _ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            break
        answers.append(
            f"{name} {DNS_TYPES.get(rtype, rtype)} -> "
            f"{_read_rdata(data, rtype, offset, rdlength)}"
        )
        offset += rdlength
    if answers:
        fields["Answer"] = "; ".join(answers[:4])
        extra["answers"] = answers

    extra["questions"] = questions
    return {"proto": "dns", "label": "DNS", "fields": fields, "extra": extra}


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


# Headers whose values are credentials or session identifiers. We record that
# they are present but never render the value, because captures get shared in
# bug reports and pasted into chat.
SENSITIVE_HEADERS = {
    "cookie", "set-cookie", "authorization", "proxy-authorization",
    "x-api-key", "x-auth-token", "x-csrf-token", "x-amz-security-token",
}


def _read_headers(data: bytes) -> list[tuple[str, str]]:
    """Parse the ``name: value`` block of an HTTP message."""
    try:
        text = data.decode("latin-1")
    except UnicodeDecodeError:
        return []
    head = text.split("\r\n\r\n", 1)[0].split("\n\n", 1)[0]
    headers: list[tuple[str, str]] = []
    for line in head.replace("\r\n", "\n").split("\n")[1:]:
        if not line.strip():
            continue
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        headers.append((name.strip(), value.strip()))
        if len(headers) >= 40:  # enough for any realistic request
            break
    return headers


def _redact(name: str, value: str) -> str:
    """Hide the value of a credential-bearing header."""
    if name.lower() in SENSITIVE_HEADERS:
        return "<hidden>"
    return value


def decode_http(data: bytes, detail: bool = True) -> Optional[dict[str, Any]]:
    """Decode an HTTP/1.x request line or status line plus headers."""
    head_end = data.find(b"\r\n\r\n")
    sep = 4
    if head_end == -1:
        head_end = data.find(b"\n\n")
        sep = 2
    if head_end == -1:
        return None

    try:
        start_line = data[:head_end].split(b"\n", 1)[0].decode("latin-1").strip()
    except (UnicodeDecodeError, IndexError):
        return None
    if not start_line:
        return None

    upper = start_line.upper()
    extra: dict[str, Any] = {}
    fields: dict[str, Any] = {}

    if upper.startswith("HTTP/"):
        parts = start_line.split(None, 2)
        if len(parts) < 2:
            return None
        extra["is_response"] = True
        extra["status"] = parts[1]
        fields["Response"] = start_line
    else:
        method = upper.split(" ")[0]
        if method not in HTTP_METHODS:
            return None
        parts = start_line.split(None, 2)
        if len(parts) < 2:
            return None
        target = parts[1]
        extra["is_response"] = False
        extra["method"] = method
        extra["uri"] = target
        fields["Request"] = start_line
        # Absolute-form request targets carry the full URL.
        if target.startswith("http://") or target.startswith("https://"):
            host = target.split("//", 1)[1].split("/", 1)[0]
            extra["host"] = host
            fields["Host (absolute URI)"] = host

    headers = _read_headers(data[: head_end + sep])
    lowered = {name.lower(): value for name, value in headers}
    if headers and detail:
        # Rendered with sensitive values masked, because this text is what
        # ends up in a shared capture report.
        fields["Headers"] = ", ".join(
            f"{name}: {_redact(name, value)}" for name, value in headers[:6]
        )

    if "host" in lowered:
        extra["host"] = lowered["host"]
        fields.setdefault("Host", lowered["host"])
    if "user-agent" in lowered:
        extra["user_agent"] = lowered["user-agent"]
        fields.setdefault("User-Agent", lowered["user-agent"])
    if "content-type" in lowered:
        extra["content_type"] = lowered["content-type"]
        fields.setdefault("Content-Type", lowered["content-type"])
    if "content-length" in lowered:
        extra["content_length"] = lowered["content-length"]
    if "cookie" in lowered or "authorization" in lowered:
        # Never print the value; just note that it is present.
        extra["has_credentials"] = True
        for sensitive in SENSITIVE_HEADERS & set(lowered):
            fields.setdefault(sensitive, "<present, value hidden>")

    body = data[head_end + sep :]
    extra["body_len"] = len(body)
    if body and detail:
        fields["Body"] = _preview_body(lowered.get("content-type", ""), body)
    return {"proto": "http", "label": "HTTP", "fields": fields, "extra": extra}


def _preview_body(content_type: str, body: bytes) -> str:
    """Show a short, safe preview of an HTTP body."""
    if "json" in content_type or body[:1] in (b"{", b"["):
        return body[:120].decode("utf-8", "replace")
    if "text" in content_type or content_type == "":
        return body[:120].decode("utf-8", "replace")
    return f"<{len(body)} bytes of {content_type or 'binary data'}>"


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------


def decode_tls(data: bytes, detail: bool = True) -> Optional[dict[str, Any]]:
    """Decode a TLS record and, for a ClientHello, its SNI and ALPN."""
    if len(data) < 5:
        return None

    content_type = data[0]
    record_version = struct.unpack("!H", data[1:3])[0]
    record_length = struct.unpack("!H", data[3:5])[0]

    record_types = {
        20: "change-cipher-spec", 21: "alert", 22: "handshake",
        23: "application-data", 24: "heartbeat",
    }
    if content_type not in record_types:
        return None

    fields: dict[str, Any] = {}
    if detail:
        fields = {
            "Content type": f"{content_type} ({record_types[content_type]})",
            "Version": TLS_VERSIONS.get(record_version, f"0x{record_version:04x}"),
            "Length": f"{record_length} bytes",
        }
    extra: dict[str, Any] = {"content_type": content_type}

    # Only a plaintext handshake record is worth digging into. Once the
    # connection is encrypted the payload is opaque by design.
    if content_type != 22:
        if detail:
            if content_type == 23:
                fields["Note"] = "encrypted application data"
            if content_type == 21 and len(data) >= 7:
                fields["Alert"] = _tls_alert(data[5], data[6])
        return {"proto": "tls", "label": "TLS", "fields": fields, "extra": extra}

    body = data[5 : 5 + record_length]
    if not body:
        return {"proto": "tls", "label": "TLS", "fields": fields, "extra": extra}

    msg_type = body[0]
    msg_length = int.from_bytes(body[1:4], "big")
    handshake = body[4 : 4 + msg_length]
    extra["handshake_type"] = msg_type

    if not detail:
        # Still walk a ClientHello for the SNI: the hostname is worth knowing
        # even without the verbose layer tree.
        if msg_type == 1 and len(handshake) >= 34:
            _decode_client_hello(handshake, fields, extra, minimal=True)
        return {"proto": "tls", "label": "TLS", "fields": fields, "extra": extra}

    fields["Handshake type"] = f"{msg_type} ({TLS_HANDSHAKE_TYPES.get(msg_type, 'unknown')})"
    fields["Handshake length"] = f"{msg_length} bytes"

    if msg_type == 1 and len(handshake) >= 34:
        _decode_client_hello(handshake, fields, extra)
    elif msg_type == 2 and len(handshake) >= 34:
        _decode_server_hello(handshake, fields, extra)
    elif msg_type == 22:
        if len(handshake) >= 8:
            cert_type = struct.unpack("!H", handshake[4:6])[0]
            certs_len = struct.unpack("!I", handshake[6:10])[0] if len(handshake) >= 10 else 0
            names = {0: "X.509", 1: "X.509 Attr Cert", 2: "Raw Public Key"}
            fields["Certificate type"] = names.get(cert_type, str(cert_type))
            fields["Certificates"] = f"{certs_len} bytes total"

    return {"proto": "tls", "label": "TLS", "fields": fields, "extra": extra}


def _decode_client_hello(handshake: bytes, fields: dict, extra: dict,
                         minimal: bool = False) -> None:
    """Pull SNI, ALPN and version out of a ClientHello body.

    When ``minimal`` is set only the SNI is collected, which is the one fact
    worth having without building the full field mapping.
    """
    if len(handshake) < 34:
        return
    if not minimal:
        version = struct.unpack("!H", handshake[0:2])[0]
        fields["Client version"] = TLS_VERSIONS.get(version, f"0x{version:04x}")

    offset = 2 + 32  # skip version + 32-byte random
    if offset >= len(handshake):
        return
    offset += 1 + handshake[offset]  # session id
    if offset + 2 > len(handshake):
        return
    cipher_len = struct.unpack("!H", handshake[offset : offset + 2])[0]
    offset += 2 + cipher_len
    if offset + 1 > len(handshake):
        return
    offset += 1 + handshake[offset]  # compression methods
    if offset + 2 > len(handshake):
        return
    ext_total = struct.unpack("!H", handshake[offset : offset + 2])[0]
    offset += 2
    end = min(len(handshake), offset + ext_total)

    sni: list[str] = []
    alpn: list[str] = []
    supported: list[str] = []
    while offset + 4 <= end:
        ext_type, ext_len = struct.unpack("!HH", handshake[offset : offset + 4])
        body = handshake[offset + 4 : offset + 4 + ext_len]
        offset += 4 + ext_len

        if ext_type == 0 and len(body) >= 5:  # server_name
            pos = 2  # server_name_list length
            while pos + 3 <= len(body):
                name_type = body[pos]
                name_len = struct.unpack("!H", body[pos + 1 : pos + 3])[0]
                pos += 3
                if pos + name_len > len(body):
                    break
                if name_type == 0:
                    sni.append(body[pos : pos + name_len].decode("latin-1", "replace"))
                pos += name_len
        elif minimal:
            continue  # only the SNI is wanted in this mode
        elif ext_type == 16 and len(body) >= 2:  # ALPN
            pos = 2
            while pos < len(body):
                size = body[pos]
                alpn.append(ALPN_PROTOCOLS.get(
                    body[pos + 1 : pos + 1 + size],
                    body[pos + 1 : pos + 1 + size].decode("latin-1", "replace"),
                ))
                pos += 1 + size
        elif ext_type == 43 and len(body) >= 1:  # supported_versions
            size = body[0]
            for i in range(1, 1 + size, 2):
                if i + 2 <= len(body):
                    v = struct.unpack("!H", body[i : i + 2])[0]
                    supported.append(TLS_VERSIONS.get(v, f"0x{v:04x}"))

    if sni:
        extra["sni"] = sni
        fields["Server name (SNI)"] = ", ".join(sni)
    if minimal:
        return
    if alpn:
        fields["ALPN"] = ", ".join(alpn)
        extra["alpn"] = alpn
    if supported:
        fields["Supported versions"] = ", ".join(supported)
    ext_names = [
        TLS_EXTENSIONS.get(t, str(t))
        for t in _iter_ext_types(handshake)
    ]
    if ext_names:
        fields["Extensions"] = ", ".join(ext_names[:10])


def _iter_ext_types(handshake: bytes):
    """Yield the extension type numbers from a ClientHello body."""
    if len(handshake) < 35:
        return
    offset = 2 + 32
    offset += 1 + handshake[offset]
    if offset + 2 > len(handshake):
        return
    offset += 2 + struct.unpack("!H", handshake[offset : offset + 2])[0]
    if offset + 1 > len(handshake):
        return
    offset += 1 + handshake[offset]
    if offset + 2 > len(handshake):
        return
    ext_total = struct.unpack("!H", handshake[offset : offset + 2])[0]
    offset += 2
    end = min(len(handshake), offset + ext_total)
    while offset + 4 <= end:
        ext_type, ext_len = struct.unpack("!HH", handshake[offset : offset + 4])
        yield ext_type
        offset += 4 + ext_len


def _decode_server_hello(handshake: bytes, fields: dict, extra: dict) -> None:
    """Pull the negotiated version out of a ServerHello body."""
    if len(handshake) < 35:
        return
    version = struct.unpack("!H", handshake[0:2])[0]
    fields["Server version"] = TLS_VERSIONS.get(version, f"0x{version:04x}")
    cipher = struct.unpack("!H", handshake[34:36])[0] if len(handshake) >= 36 else None
    if cipher:
        fields["Cipher suite"] = f"0x{cipher:04x}"


def _tls_alert(level: int, description: int) -> str:
    levels = {1: "warning", 2: "fatal"}
    descriptions = {
        0: "close_notify", 40: "handshake_failure", 42: "bad_certificate",
        47: "illegal_parameter", 48: "unknown_ca", 50: "decode_error",
        51: "decrypt_error", 70: "protocol_version", 71: "insufficient_security",
        80: "internal_error", 112: "unrecognized_name",
    }
    return f"{levels.get(level, level)} / {descriptions.get(description, description)}"
