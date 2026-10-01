"""
Live capture backends.

Two ways to get packets off the wire, in order of preference:

1. **scapy** (needs ``pip install scapy``). Asks the OS to put the interface
   into promiscuous mode and hands us whole frames including the Ethernet
   header. If a BPF filter is requested and a BPF engine is available (libpcap
   on Unix, Npcap on Windows) the filtering happens in the kernel, which is far
   cheaper than looking at every packet in Python.

2. **raw sockets** (standard library only). Opens ``SOCK_RAW``/``IPPROTO_RAW``
   and receives one IP packet at a time. Two important limits: you only get the
   IP header and payload, *not* the Ethernet header, so MAC addresses are
   missing; and raw sockets need Administrator/root privileges.

Both backends yield :class:`~netcap.pcap.RawPacket` objects so the analysis
layer is identical either way.
"""

from __future__ import annotations

import ctypes
import importlib
import os
import queue
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Iterator, Optional

from .pcap import LINKTYPE_ETHERNET, LINKTYPE_RAW, RawPacket

# IP socket constants that are not exposed on every platform.
try:
    IP_HDRINCL = socket.IP_HDRINCL  # Windows
except AttributeError:  # pragma: no cover - platform dependent
    IP_HDRINCL = 3
try:
    IPPROTO_RAW = socket.IPPROTO_RAW
except AttributeError:  # pragma: no cover
    IPPROTO_RAW = 255


class CaptureError(RuntimeError):
    """Raised when a capture cannot be started."""


@dataclass
class CaptureReport:
    """Counters a backend fills in while capturing.

    ``dropped`` matters: dissecting and printing packets in Python is much
    slower than a link can deliver them, so a bounded queue means some packets
    are discarded rather than being buffered without limit. Reporting that
    honestly is better than pretending the capture was complete.
    """

    seen: int = 0
    dropped: int = 0

    @property
    def lost(self) -> float:
        """Fraction of packets that could not be kept."""
        return self.dropped / self.seen if self.seen else 0.0


@dataclass
class CaptureOptions:
    """Everything a backend needs to know about what to capture."""

    iface: Optional[str] = None
    count: int = 0                 # 0 means "until interrupted"
    timeout: Optional[float] = None  # seconds; None means block forever
    bpf: Optional[str] = None      # filter handed to the kernel, if possible
    python_filter: Optional[Callable[[RawPacket], bool]] = None
    snaplen: int = 262144
    promiscuous: bool = True
    # Set by the caller to end a capture early (the "press q" handler).
    should_stop: Optional[threading.Event] = None
    on_packet: Optional[Callable[[RawPacket], bool]] = None  # return False to stop
    # How many captured packets may wait to be processed. Bounded on purpose:
    # an unbounded queue turns a fast link into unbounded memory use and a
    # capture that appears to hang while it drains a backlog.
    queue_size: int = 20000
    report: CaptureReport = field(default_factory=CaptureReport)


def is_admin() -> bool:
    """Whether the process can open raw sockets on this platform."""
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return os.geteuid() == 0


def default_route_ip() -> Optional[str]:
    """The local IP of the interface that owns the default route.

    Connecting a UDP socket "sends" nothing -- it just asks the routing table
    which source address would be used -- so this needs no privileges and
    generates no traffic.
    """
    for family, probe in (
        (socket.AF_INET, "8.8.8.8"),
        (socket.AF_INET6, "2001:4860:4860::8888"),
    ):
        try:
            sock = socket.socket(family, socket.SOCK_DGRAM)
        except OSError:
            continue
        try:
            sock.settimeout(0.3)
            sock.connect((probe, 53))
            return sock.getsockname()[0]
        except OSError:
            continue
        finally:
            sock.close()
    return None


# Descriptions of adapters that cannot carry interesting traffic. These are
# Microsoft's virtual miniports and debug drivers, not real links.
_JUNK = ("wan miniport", "kernel debugger", "ip-https", "teredo", "6to4")


@dataclass
class InterfaceInfo:
    """One capture-capable interface."""

    device: str          # the name the capture API needs (an NPF path on Windows)
    name: str            # the friendly name shown to the user
    description: str
    mac: str = ""
    ips: tuple[str, ...] = ()
    is_default: bool = False   # holds the machine's default route

    @property
    def is_loopback(self) -> bool:
        return self.mac in ("", "00:00:00:00:00:00")


def _interface_ips(iface) -> tuple[str, ...]:
    """Flatten scapy's ``{version: [address, ...]}`` address mapping.

    Newer scapy returns a dict keyed by IP version; older builds return a flat
    sequence. Handle both so this does not silently report "no address".
    """
    raw = getattr(iface, "ips", None)
    if not raw:
        return ()
    if isinstance(raw, dict):
        values: list[str] = []
        for version in (4, 6):
            values.extend(str(a) for a in (raw.get(version) or ()))
        return tuple(values)
    return tuple(str(a) for a in raw)


def list_interfaces() -> list[InterfaceInfo]:
    """Enumerate capture interfaces, most useful first.

    Prefers scapy (which knows the Windows NPF device names behind the friendly
    names) and degrades to :func:`socket.if_nameindex` when it is not installed.
    """
    try:
        from scapy.all import conf  # type: ignore
    except Exception:
        return [
            InterfaceInfo(device=name, name=name, description=f"interface #{index}")
            for index, name in socket.if_nameindex()
        ]

    found: list[InterfaceInfo] = []
    route_ip = default_route_ip()
    for device, iface in getattr(conf, "ifaces", {}).items():
        description = getattr(iface, "description", "") or ""
        name = getattr(iface, "name", None) or device
        if any(junk in description.lower() for junk in _JUNK):
            continue
        ips = _interface_ips(iface)
        found.append(
            InterfaceInfo(
                device=device,
                name=name,
                description=description,
                mac=getattr(iface, "mac", "") or "",
                ips=ips,
                is_default=bool(route_ip) and route_ip in ips,
            )
        )

    # Default route first, then anything with an address, then the rest.
    found.sort(key=lambda i: (not i.is_default, not bool(i.ips), i.is_loopback, i.name.lower()))
    return found


def resolve_interface(name: str) -> str:
    """Map a user-supplied interface name to the name the capture API needs.

    On Windows you can pass either the friendly name ("Wi-Fi") or the NPF
    device path; on Unix the two are the same thing.
    """
    for info in list_interfaces():
        if name in (info.name, info.device):
            return info.device
    # Not in our list: hand it through unchanged and let the backend complain
    # with its own (usually better) error message.
    return name


def default_interface() -> str:
    """A sensible interface to capture on: the one with the default route."""
    interfaces = list_interfaces()
    for info in interfaces:
        if info.is_default:
            return info.device
    for info in interfaces:
        if info.ips:
            return info.device
    return interfaces[0].device if interfaces else ""


def have_scapy() -> bool:
    """Whether scapy can be imported."""
    try:
        importlib.import_module("scapy.all")
        return True
    except Exception:
        return False


def have_bpf() -> bool:
    """Whether a kernel BPF filter engine is available.

    On Windows this means Npcap; without it scapy raises when you pass a
    ``filter=`` to :func:`sniff`.
    """
    if sys.platform.startswith("win"):
        # Npcap/WinPcap ships libpcap.dll; look for it where it is installed.
        for folder in (r"C:\Windows\System32\Npcap", r"C:\Windows\System32\WinPcap"):
            if os.path.exists(os.path.join(folder, "wpcap.dll")):
                return True
        try:  # the DLL may be on PATH instead
            ctypes.WinDLL("wpcap")  # type: ignore[attr-defined]
            return True
        except OSError:
            return False
    try:
        from scapy.arch import get_pcap  # type: ignore

        return get_pcap() is not None
    except Exception:
        return False


# ---------------------------------------------------------------------------
# scapy backend
# ---------------------------------------------------------------------------


def sniff_scapy(options: CaptureOptions) -> Iterator[RawPacket]:
    """Capture using scapy.

    Falls back to Python-side filtering if a BPF engine is not available, and
    warns on stderr so the user knows the filter is costing more CPU.
    """
    try:
        from scapy.all import conf, sniff  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise CaptureError(
            "scapy is not installed. Run 'pip install scapy', or use --backend socket."
        ) from exc

    # On Windows, scapy can go through Npcap instead of a raw socket. Npcap
    # allows promiscuous mode (and capture at all) without Administrator, so
    # prefer it whenever the driver is present.
    if have_bpf():
        try:
            conf.use_pcap = True
        except Exception:
            pass

    kwargs: dict = {
        "iface": options.iface or None,
        "store": False,
        "timeout": options.timeout,
    }
    if options.promiscuous:
        kwargs["promisc"] = True

    kernel_filter = None
    if options.bpf:
        if have_bpf():
            kernel_filter = options.bpf
        else:
            print(
                "warning: no BPF engine found (install Npcap on Windows); "
                "applying the filter in Python instead, which is slower.",
                file=sys.stderr,
            )

    # scapy's sniff() has no way to be told "stop from another thread", so it
    # runs on a worker thread and pushes into a bounded queue. The consumer
    # below is a plain generator, so the caller's break/return works normally.
    outbox: "queue.Queue[object]" = queue.Queue(maxsize=max(1, options.queue_size))
    report = options.report
    emitted = [0]

    def emit(raw: RawPacket) -> None:
        """Queue a packet, dropping it if the consumer is not keeping up."""
        try:
            outbox.put_nowait(raw)
        except queue.Full:
            report.dropped += 1
            return
        emitted[0] += 1

    def on_packet(packet) -> None:
        """Convert a scapy packet into a RawPacket and hand it on."""
        try:
            data = bytes(packet)
        except Exception as exc:  # a malformed frame scapy cannot rebuild
            report.dropped += 1
            outbox.put_nowait(CaptureError(f"could not serialise a packet: {exc}"))
            return
        report.seen += 1
        link_type = LINKTYPE_ETHERNET
        # With a cooked/"any" capture on Linux there is no Ethernet header.
        if packet.__class__.__name__ in ("CookedLinux", "CookedWindows"):
            link_type = 113
        raw = RawPacket(
            ts=float(packet.time),
            data=data,
            orig_len=len(data),
            link_type=link_type,
        )
        if options.python_filter and not options.python_filter(raw):
            return
        emit(raw)

    def stop_filter(_packet) -> bool:
        """Called by scapy for every packet; return True to end the capture."""
        if options.should_stop is not None and options.should_stop.is_set():
            return True
        return bool(options.count) and emitted[0] >= options.count

    if kernel_filter:
        kwargs["filter"] = kernel_filter

    def worker() -> None:
        try:
            # prn= is the documented way to get a per-packet callback. Passing
            # a positional would bind to whichever parameter comes first.
            sniff(prn=on_packet, stop_filter=stop_filter, **kwargs)
        except BaseException as exc:  # surface backend failures to the consumer
            report.dropped += 1
            try:
                outbox.put_nowait(exc)
            except queue.Full:
                pass
        finally:
            # Wait for room so the sentinel is never lost, but do not hang
            # forever on a full queue: the consumer is draining it, so this
            # resolves promptly and bounds the backlog we have to work through.
            while True:
                try:
                    outbox.put(None, timeout=5.0)
                    return
                except queue.Full:
                    pass

    threading.Thread(target=worker, daemon=True).start()

    while True:
        item = outbox.get()
        if item is None:
            return
        if isinstance(item, BaseException):
            raise item
        yield item  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Raw socket backend
# ---------------------------------------------------------------------------


def sniff_raw_socket(options: CaptureOptions) -> Iterator[RawPacket]:
    """Capture using a standard-library raw socket.

    This is the "socket" approach from the brief. Notes:

    * ``SOCK_RAW`` with ``IPPROTO_RAW`` receives *incoming* IP packets for us
      and lets us send raw IP packets too. We only receive here.
    * Windows and macOS deliver the IP header at the start of each datagram.
      Linux with a raw socket also includes the IP header; to get the Ethernet
      header you would need ``AF_PACKET``, which is Linux-only and needs root.
    * ``IP_HDRINCL`` is set so the socket can also send packets with a header we
      built, and a receive timeout lets the loop notice Ctrl-C promptly.
    * No BPF here: every IP packet on the machine reaches this process, so the
      filter has to be applied in Python.
    """
    if not is_admin():
        raise CaptureError(
            "raw socket capture needs Administrator (Windows) or root (Linux/macOS) "
            "privileges. Re-run from an elevated terminal, or use "
            "'--backend scapy' if you have Npcap installed."
        )

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPPROTO_RAW)
    try:
        try:
            sock.setsockopt(socket.IPPROTO_IP, IP_HDRINCL, 1)
        except OSError:
            pass  # receive-only use does not need it on every platform
        sock.settimeout(0.5)

        count = 0
        deadline = time.monotonic() + options.timeout if options.timeout else None
        while True:
            if options.should_stop is not None and options.should_stop.is_set():
                return
            if options.count and count >= options.count:
                return
            if deadline and time.monotonic() >= deadline:
                return
            try:
                data, _addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as exc:
                # Winsock reports a benign condition this way when the buffer
                # is emptied by another reader; keep going rather than abort.
                if getattr(exc, "errno", None) in (10022, 10054, 10040):
                    continue
                raise CaptureError(f"raw socket receive failed: {exc}") from exc

            raw = RawPacket(
                ts=time.time(),
                data=data,
                orig_len=len(data),
                link_type=LINKTYPE_RAW,
            )
            if options.python_filter and not options.python_filter(raw):
                continue
            count += 1
            if options.on_packet and not options.on_packet(raw):
                return
            yield raw
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def sniff(options: CaptureOptions, backend: str = "auto") -> Iterator[RawPacket]:
    """Capture packets, choosing the best available backend.

    Args:
        options: what and how much to capture.
        backend: ``"scapy"``, ``"socket"``, or ``"auto"``.
    """
    backend = backend.lower()
    if backend == "auto":
        if have_scapy():
            backend = "scapy"
        elif is_admin():
            backend = "socket"
        else:
            raise CaptureError(
                "no capture backend available: install scapy "
                "(pip install scapy) and run as Administrator"
            )

    if backend == "socket":
        yield from sniff_raw_socket(options)
    elif backend == "scapy":
        yield from sniff_scapy(options)
    else:
        raise CaptureError(f"unknown backend {backend!r} (use scapy, socket or auto)")
