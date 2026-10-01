"""
A small filter language, deliberately similar to tcpdump's BPF syntax.

Supported primitives::

    tcp  udp  icmp  arp  ip  ip6          protocol / ethertype
    host 10.0.0.1                        IPv4 address
    host example.com                     (resolved to an address)
    net 192.168.1.0/24                    network
    port 443  src port 443  dst port 443 transport port
    proto tcp                            synonym for "tcp"

Combined with ``and`` / ``or`` / ``not`` and parentheses::

    "tcp and port 443 and not host 10.0.0.5"
    "(udp or icmp) and host 192.168.1.1"

Why not just hand the string to libpcap? Two reasons: filtering in the driver
is faster, but it only works where a BPF engine is available (on Windows that
means Npcap installed), and a pure-Python evaluator works everywhere. When
scapy *can* use BPF it does, and this module is the fallback.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import TYPE_CHECKING, Any, Callable, Optional

if TYPE_CHECKING:
    from .dissect import PacketInfo

PROTO_KEYWORDS = {"tcp", "udp", "icmp", "arp", "ip", "ip6", "icmp6"}

# Token kinds that can begin a primitive. Two of these in a row are joined by
# an implicit "and", so "tcp port 80" and "host 1.2.3.4 port 80" both work.
PRIMITIVE_STARTERS = {
    "proto", "bare_proto", "port", "host", "net", "word", "direction", "lparen",
}


class FilterError(ValueError):
    """Raised when a filter expression cannot be parsed."""


class _Token:
    __slots__ = ("kind", "value")

    def __init__(self, kind: str, value: Any = None) -> None:
        self.kind = kind
        self.value = value

    def __repr__(self) -> str:
        return f"<{self.kind}:{self.value!r}>"


def tokenize(text: str) -> list[_Token]:
    """Split a filter expression into tokens."""
    tokens: list[_Token] = []
    for word in text.replace("(", " ( ").replace(")", " ) ").split():
        lower = word.lower()
        if word == "(":
            tokens.append(_Token("lparen"))
        elif word == ")":
            tokens.append(_Token("rparen"))
        elif lower in ("and", "&&"):
            tokens.append(_Token("and"))
        elif lower in ("or", "||"):
            tokens.append(_Token("or"))
        elif lower in ("not", "!"):
            tokens.append(_Token("not"))
        elif lower in PROTO_KEYWORDS:
            tokens.append(_Token("proto", lower))
        elif lower == "proto":
            tokens.append(_Token("bare_proto"))
        elif lower.rstrip("s") in ("port", "host", "net"):
            tokens.append(_Token(lower.rstrip("s")))
        elif lower.isdigit():
            tokens.append(_Token("number", int(lower)))
        elif lower in ("src", "dst", "source", "destination"):
            tokens.append(_Token("direction", "src" if lower[0] == "s" else "dst"))
        else:
            # Anything else: a hostname, a CIDR block, or a protocol name that
            # follows the bare "proto" keyword.
            tokens.append(_Token("word", lower))
    return tokens


class _Parser:
    """Recursive-descent parser producing a predicate function."""

    def __init__(self, tokens: list[_Token]) -> None:
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> Optional[_Token]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def next(self) -> _Token:
        token = self.peek()
        if token is None:
            raise FilterError("unexpected end of filter expression")
        self.pos += 1
        return token

    # expr := term (("or") term)*
    def parse(self) -> Callable[["PacketInfo"], bool]:
        if not self.tokens:
            return lambda _pkt: True
        predicate = self.parse_term()
        while (token := self.peek()) and token.kind == "or":
            self.next()
            right = self.parse_term()
            left = predicate
            predicate = lambda pkt, a=left, b=right: a(pkt) or b(pkt)
        # A ')' here belongs to the enclosing group, not to this expression,
        # so leave it for parse_factor's caller to consume.
        trailing = self.peek()
        if trailing is not None and trailing.kind != "rparen":
            raise FilterError(f"unexpected token {trailing!r}")
        return predicate

    # term := factor (("and")? factor)*      -- "and" may be left implicit
    def parse_term(self) -> Callable[["PacketInfo"], bool]:
        predicate = self.parse_factor()
        while True:
            token = self.peek()
            if token is None or token.kind in ("or", "rparen"):
                break
            if token.kind == "and":
                self.next()
            elif token.kind in PRIMITIVE_STARTERS:
                # tcpdump reads "tcp port 80" as "tcp and port 80". Do the same.
                pass
            else:
                break
            right = self.parse_factor()
            left = predicate
            predicate = lambda pkt, a=left, b=right: a(pkt) and b(pkt)
        return predicate

    # factor := "not" factor | "(" expr ")" | primitive
    def parse_factor(self) -> Callable[["PacketInfo"], bool]:
        token = self.peek()
        if token is None:
            raise FilterError("unexpected end of filter expression")
        if token.kind == "not":
            self.next()
            inner = self.parse_factor()
            return lambda pkt: not inner(pkt)
        if token.kind == "lparen":
            self.next()
            inner = self.parse()
            if (closing := self.peek()) is None or closing.kind != "rparen":
                raise FilterError("missing closing parenthesis")
            self.next()
            return inner
        return self.parse_primitive()

    def parse_primitive(self) -> Callable[["PacketInfo"], bool]:
        direction: Optional[str] = None
        if (token := self.peek()) and token.kind == "direction":
            self.next()
            direction = token.value
        if self.peek() is None:
            raise FilterError("incomplete filter expression")

        token = self.next()

        if token.kind == "proto":
            proto = token.value
            if proto == "ip":
                return lambda pkt: pkt.ip_version == 4
            if proto in ("ip6", "icmp6"):
                return lambda pkt: pkt.ip_version == 6
            if proto == "arp":
                return lambda pkt: pkt.l4_proto == "arp"
            if proto == "icmp":
                return lambda pkt: pkt.l4_proto in ("icmp", "icmpv6")
            return lambda pkt, p=proto: pkt.l4_proto == p

        if token.kind == "bare_proto":
            name = self.next().value
            name = str(name).lower()
            if name not in ("tcp", "udp", "icmp", "arp", "ipv6"):
                raise FilterError(f"unknown protocol {name!r}")
            return lambda pkt, p=name: pkt.l4_proto == p

        if token.kind == "word" and token.value in PROTO_KEYWORDS:
            return lambda pkt, p=token.value: (
                p in PROTO_KEYWORDS and _matches_proto(pkt, p)
            )

        if token.kind == "port":
            value = self._expect_number("port")
            if direction == "src":
                return lambda pkt, p=value: pkt.src_port == p
            if direction == "dst":
                return lambda pkt, p=value: pkt.dst_port == p
            return lambda pkt, p=value: p in (pkt.src_port, pkt.dst_port)

        if token.kind == "host":
            addr = _resolve(self._expect_value("host"))
            scope = 32 if ":" not in addr else 128
            network = ipaddress.ip_network(f"{addr}/{scope}", strict=False)
            literal = str(network.network_address)
            if direction == "src":
                return lambda pkt, a=literal: pkt.src_ip == a
            if direction == "dst":
                return lambda pkt, a=literal: pkt.dst_ip == a
            return lambda pkt, a=literal: pkt.src_ip == a or pkt.dst_ip == a

        if token.kind == "net":
            value = self._expect_value("net")
            if "/" not in value:
                value = f"{value}/24"
            network = ipaddress.ip_network(value, strict=False)

            def in_net(pkt: "PacketInfo", n=network) -> bool:
                for candidate in ((pkt.src_ip,) if direction == "src"
                                  else (pkt.dst_ip,) if direction == "dst"
                                  else (pkt.src_ip, pkt.dst_ip)):
                    if not candidate:
                        continue
                    try:
                        if ipaddress.ip_address(candidate) in n:
                            return True
                    except ValueError:
                        continue
                return False

            return in_net

        raise FilterError(f"cannot parse filter near {token.value!r}")

    def _expect_number(self, what: str) -> int:
        token = self.next()
        if token.kind != "number":
            raise FilterError(f"expected a number after {what}, got {token.value!r}")
        return token.value

    def _expect_value(self, what: str) -> str:
        token = self.next()
        if token.kind not in ("word", "number"):
            raise FilterError(f"expected a value after {what}, got {token.value!r}")
        return str(token.value)


def _matches_proto(pkt: "PacketInfo", name: str) -> bool:
    """Match a protocol keyword, mapping the family aliases as well."""
    if name == "tcp":
        return pkt.l4_proto == "tcp"
    if name == "udp":
        return pkt.l4_proto == "udp"
    if name == "icmp":
        return pkt.l4_proto in ("icmp", "icmpv6")
    if name == "arp":
        return pkt.l4_proto == "arp"
    if name == "ip":
        return pkt.ip_version == 4
    if name in ("ip6", "ipv6"):
        return pkt.ip_version == 6
    if name == "icmp6":
        return pkt.l4_proto == "icmpv6"
    return False


def _resolve(value: str) -> str:
    """Turn a host name or literal address into a literal address."""
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    try:
        return socket.gethostbyname(value)
    except OSError as exc:
        raise FilterError(f"cannot resolve host {value!r}: {exc}") from exc


def compile_filter(expression: str) -> Callable[["PacketInfo"], bool]:
    """Compile a filter expression into a predicate.

    An empty expression matches everything.
    """
    if not expression or not expression.strip():
        return lambda _pkt: True
    return _Parser(tokenize(expression)).parse()
