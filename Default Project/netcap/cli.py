"""
Command line interface.

    netcap                          live capture, default interface
    netcap -i "Wi-Fi" -c 50         first 50 packets from a named interface
    netcap -f "tcp port 443"        only HTTPS traffic
    netcap -a capture.pcap          dissect a capture file, no privileges needed
    netcap -a capture.pcap -v       ... showing the full protocol tree
    netcap -o out.pcap -c 200       capture 200 packets and save them
    netcap -L                       list capture interfaces
"""

from __future__ import annotations

import argparse
import sys
import threading
import time
from typing import Optional

from . import __version__, capture, display, filter as filter_mod, pcap
from .dissect import dissect
from .stats import TrafficStats, human_bytes

BANNER = "netcap {version} - network traffic capture and analysis"


# ---------------------------------------------------------------------------
# Interactive key handling
# ---------------------------------------------------------------------------


class KeyWatcher:
    """Watch for a keypress so you can stop a live capture without a mouse.

    On Windows this polls the console with ``msvcrt``; on Unix it puts the
    terminal in cbreak mode for the duration. If stdin is not a terminal
    (redirected input, or running under a scheduler) the watcher disables
    itself, because changing terminal modes there would be wrong.
    """

    def __init__(self, on_stop, enabled: bool = True) -> None:
        self.on_stop = on_stop
        self.enabled = enabled and sys.stdin is not None and sys.stdin.isatty()
        self._thread: Optional[threading.Thread] = None
        self._done = threading.Event()
        self._saved = None

    def start(self) -> None:
        if not self.enabled:
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        try:
            self._poll()
        finally:
            self._done.set()

    def _poll(self) -> None:
        if sys.platform.startswith("win"):
            self._poll_windows()
        else:
            self._poll_unix()

    def _poll_windows(self) -> None:
        import msvcrt

        while not self._done.is_set():
            # kbhit() reports whether a keypress is already buffered, so this
            # never blocks and never eats a keystroke meant for the shell.
            if msvcrt.kbhit():
                char = msvcrt.getwch()
                if char in ("q", "Q", "\x03"):
                    self.on_stop()
                    return
            time.sleep(0.1)

    def _poll_unix(self) -> None:
        import termios
        import tty

        fd = sys.stdin.fileno()
        try:
            self._saved = termios.tcgetattr(fd)
        except (termios.error, ValueError):
            self.enabled = False
            return
        try:
            # cbreak delivers each key immediately without waiting for Enter,
            # and leaves the tty usable if we are killed mid-capture.
            tty.setcbreak(fd)
            while not self._done.is_set():
                char = sys.stdin.read(1)
                if not char or char in ("q", "Q", "\x03", "\x04"):
                    self.on_stop()
                    return
        except (OSError, ValueError):
            return
        finally:
            if self._saved is not None:
                try:
                    termios.tcsetattr(fd, termios.TCSADRAIN, self._saved)
                except termios.error:
                    pass

    def stop(self) -> None:
        """Stop watching and restore the terminal, if we changed it."""
        self._done.set()
        if self._thread is not None:
            # The Unix poller blocks in read(1), so a timed join is the best
            # we can do; the thread is a daemon and exits with the process.
            self._thread.join(timeout=0.5)
            self._thread = None


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netcap",
        description="Capture network traffic, dissect the packets, and report on the data.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
filter examples
  "tcp"                      TCP only
  "udp or icmp"              UDP and ICMP
  "port 53"                  DNS (either direction)
  "src port 443"             outgoing HTTPS
  "host 192.168.1.1"         traffic to or from one host
  "tcp and port 443 and not host 10.0.0.5"

examples
  netcap -c 40                          watch 40 packets
  netcap -f "udp port 53" -c 20         follow DNS lookups
  netcap -a traffic.pcap -v             dissect a file, full protocol tree
  netcap -o session.pcap -c 500         capture and save
""",
    )

    what = parser.add_argument_group("what to capture")
    what.add_argument("-i", "--interface", metavar="NAME",
                      help="interface to capture on (default: the default-route adapter)")
    what.add_argument("-a", "--analyze", metavar="FILE",
                      help="dissect a saved .pcap file instead of capturing live")
    what.add_argument("-f", "--filter", metavar="EXPR",
                      help="filter expression, e.g. 'tcp and port 443'")
    what.add_argument("-c", "--count", type=int, default=0, metavar="N",
                      help="stop after N packets (0 = until interrupted)")
    what.add_argument("--timeout", type=float, default=None, metavar="SEC",
                      help="stop after SEC seconds")
    what.add_argument("-s", "--snaplen", type=int, default=262144, metavar="BYTES",
                      help="bytes to store per packet (default: all of it)")
    what.add_argument("--no-promisc", action="store_true",
                      help="do not put the interface into promiscuous mode")

    how = parser.add_argument_group("how to capture")
    how.add_argument("--backend", choices=("auto", "scapy", "socket"), default="auto",
                     help="capture backend (default: auto)")
    how.add_argument("-L", "--list-interfaces", action="store_true",
                     help="list available capture interfaces and exit")

    out = parser.add_argument_group("output")
    out.add_argument("-o", "--output", metavar="FILE",
                     help="write the captured packets to a .pcap file")
    out.add_argument("-v", "--verbose", action="store_true",
                     help="print the full protocol tree for every packet")
    out.add_argument("-q", "--quiet", action="store_true",
                     help="print no packet lines, only the summary")
    out.add_argument("--no-hex", action="store_true",
                     help="omit the payload hex dump from --verbose output")
    out.add_argument("--no-summary", action="store_true",
                     help="skip the end-of-capture report")
    out.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    out.add_argument("--ascii", action="store_true",
                     help="use plain ASCII instead of box-drawing characters")
    out.add_argument("--version", action="version", version=f"netcap {__version__}")

    return parser


# ---------------------------------------------------------------------------
# Capture / analysis loop
# ---------------------------------------------------------------------------


def run_offline(path: str, args: argparse.Namespace, style: display.Style,
                unicode_ok: bool) -> int:
    """Dissect every packet in a pcap file."""
    try:
        # PcapReader owns the file handle, so use it as a context manager:
        # stopping early must not leave the file open.
        reader = pcap.PcapReader(path)
    except FileNotFoundError:
        print(f"error: no such file: {path}", file=sys.stderr)
        return 2
    except pcap.PcapError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: cannot read {path}: {exc}", file=sys.stderr)
        return 2

    link_type = reader.link_type
    print(f"{BANNER.format(version=__version__)}")
    print(f"analysing {path} ({pcap.link_type_name(link_type)})")
    if args.filter:
        print(f"filter: {args.filter}")
    if sys.stdin.isatty():
        print("press q to stop early")
    print(flush=True)

    stat = TrafficStats()
    predicate = _build_predicate(args)
    saved: list[pcap.RawPacket] = []
    stop = threading.Event()
    watcher = KeyWatcher(stop.set, enabled=sys.stdin.isatty())
    watcher.start()

    seen = 0
    with reader:
        for index, raw in enumerate(_limit(reader, args), start=1):
            if stop.is_set():
                break
            # Count every packet in the file, not just the ones we dissect, so
            # -c means "the first N packets of the file".
            seen += 1
            if args.count and seen > args.count:
                break
            info = dissect(raw.data, link_type, raw.ts, seen, raw.orig_len,
                           detail=args.verbose)
            if predicate and not predicate(info):
                stat.filtered_out += 1
                continue

            if args.output:
                saved.append(raw)
            stat.add(info)
            if not args.quiet:
                _print_packet(info, args, style, unicode_ok, index == 1)

    watcher.stop()
    print()
    print(f"processed {stat.packets + stat.filtered_out:,} of {seen:,} packet(s) in {path}",
          flush=True)

    if args.output and saved:
        written = pcap.write_pcap(args.output, saved, link_type, args.snaplen)
        print(f"wrote {written:,} packet(s) to {args.output}")
    elif args.output:
        print(f"nothing matched the filter, so {args.output} was not written")

    if not args.no_summary:
        print(display.summary_report(stat, style, unicode_ok, link_type))
    return 0


def _limit(packets, args: argparse.Namespace):
    """Yield packets, applying the snaplen truncation if one was requested."""
    for raw in packets:
        if args.snaplen and len(raw.data) > args.snaplen:
            raw = pcap.RawPacket(
                ts=raw.ts, data=raw.data[: args.snaplen],
                orig_len=raw.orig_len, link_type=raw.link_type,
            )
        yield raw


def run_live(args: argparse.Namespace, style: display.Style, unicode_ok: bool) -> int:
    """Capture from a live interface."""
    friendly = args.interface
    iface = capture.resolve_interface(friendly) if friendly else capture.default_interface()
    if not iface:
        print("error: could not determine a capture interface; pass -i NAME",
              file=sys.stderr)
        return 2

    interfaces = capture.list_interfaces()
    label = friendly or next(
        (i.name for i in interfaces if i.device == iface), iface
    )

    print(f"{BANNER.format(version=__version__)}")
    backend = args.backend
    if backend == "auto":
        backend = "scapy" if capture.have_scapy() else "socket"
    print(f"interface: {label}   backend: {backend}")
    if backend == "socket" and not capture.is_admin():
        print("error: the socket backend needs an elevated terminal. "
              "Re-run as Administrator, or use --backend scapy with Npcap installed.",
              file=sys.stderr)
        return 1
    if not args.filter:
        print("no filter: capturing everything (q or Ctrl-C to stop)")
    else:
        print(f"filter: {args.filter}")
    if capture.is_admin():
        print("privileges: elevated")
    else:
        print("privileges: standard user (using Npcap via scapy)")

    # A BPF engine only exists in some setups; only hand the filter to the
    # kernel when it does, and fall back to the Python evaluator otherwise.
    kernel_filter = None
    predicate = None
    if args.filter:
        if backend == "scapy" and capture.have_bpf():
            kernel_filter = args.filter
        else:
            predicate = _build_predicate(args)
    if args.quiet:
        print("quiet mode: only the summary will be printed")
    print("press q to stop\n", flush=True)

    # "stop" is shared between the key watcher and the capture backend, so
    # pressing q ends the capture from either side.
    stop = threading.Event()
    watcher = KeyWatcher(stop.set, enabled=sys.stdin.isatty())
    watcher.start()

    options = capture.CaptureOptions(
        iface=iface,
        count=args.count,
        timeout=args.timeout,
        bpf=kernel_filter,
        python_filter=None,
        snaplen=args.snaplen,
        promiscuous=not args.no_promisc,
        should_stop=stop,
    )

    stat = TrafficStats()
    saved: list[pcap.RawPacket] = []
    link_type = pcap.LINKTYPE_ETHERNET
    started = time.time()

    try:
        stream = capture.sniff(options, backend=backend)
        for index, raw in enumerate(stream, start=1):
            if stop.is_set():
                break
            if args.snaplen and len(raw.data) > args.snaplen:
                raw = pcap.RawPacket(
                    ts=raw.ts, data=raw.data[: args.snaplen],
                    orig_len=raw.orig_len, link_type=raw.link_type,
                )
            link_type = raw.link_type
            info = dissect(raw.data, link_type, raw.ts, index, raw.orig_len,
                           detail=args.verbose)
            if predicate and not predicate(info):
                stat.filtered_out += 1
                continue

            if args.output:
                saved.append(raw)
            stat.add(info)
            if not args.quiet:
                _print_packet(info, args, style, unicode_ok, index == 1)
    except KeyboardInterrupt:
        print("\ninterrupted")
    except capture.CaptureError as exc:
        watcher.stop()
        print(f"\nerror: {exc}", file=sys.stderr)
        return 1
    finally:
        watcher.stop()

    elapsed = time.time() - started
    print()
    if stat.packets:
        print(
            f"captured {stat.packets:,} packet(s), "
            f"{human_bytes(stat.bytes)} in {elapsed:.1f}s"
        )
    else:
        print("no packets captured")
        if args.filter and kernel_filter is None:
            print("hint: the filter may not match any traffic on this interface")

    # A bounded queue drops packets when Python cannot keep up with the link.
    # Say so, rather than letting a partial capture look complete.
    report = options.report
    if report.dropped:
        print(
            f"warning: dropped {report.dropped:,} of {report.seen:,} packet(s) "
            f"({report.lost:.1%}) because processing could not keep up. "
            f"Use --quiet to analyse without printing every packet."
        )

    if args.output and saved:
        written = pcap.write_pcap(args.output, saved, link_type, args.snaplen)
        print(f"wrote {written:,} packet(s) to {args.output}")
    elif args.output:
        print(f"nothing was captured, so {args.output} was not written")

    if not args.no_summary:
        print(display.summary_report(stat, style, unicode_ok, link_type))
    return 0


def _print_packet(info, args, style, unicode_ok, first: bool) -> None:
    """Print one packet, either as a line or as a full protocol tree."""
    if args.verbose:
        if not first:
            print()
        print(display.packet_detail(info, style, unicode_ok, hexdump=not args.no_hex))
    else:
        print(display.packet_line(info, style, unicode_ok))


def _build_predicate(args: argparse.Namespace):
    """Compile the filter expression into a predicate over PacketInfo."""
    if not args.filter:
        return None
    try:
        return filter_mod.compile_filter(args.filter)
    except filter_mod.FilterError as exc:
        raise SystemExit(f"error: bad filter expression: {exc}")


def list_interfaces() -> int:
    """Print the available capture interfaces."""
    print("capture interfaces (the first one is used by default):\n")
    for index, info in enumerate(capture.list_interfaces()):
        marker = " *" if info.is_default else "  "
        addresses = ", ".join(info.ips) or "no address"
        loop = " (loopback)" if info.is_loopback else ""
        print(f"{marker} {info.name}{loop}")
        print(f"     {info.description}")
        print(f"     {addresses}   mac {info.mac or 'unknown'}")
        if index == 0:
            print()
    print("* default route")
    print()
    print(f"scapy installed:   {'yes' if capture.have_scapy() else 'no'}")
    print(f"BPF engine:        {'yes' if capture.have_bpf() else 'no (Npcap not found)'}")
    if capture.is_admin():
        print("raw socket access: yes (elevated)")
    else:
        print("raw socket access: no (raw sockets need Administrator/root)")
        if capture.have_bpf():
            print("                  scapy + Npcap will be used instead, which is fine")
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    style = display.Style(enabled=display.should_colorize(
        False if args.no_color else None))
    unicode_ok = display.supports_unicode(sys.stdout) and not args.ascii

    if args.list_interfaces:
        return list_interfaces()

    try:
        if args.analyze:
            return run_offline(args.analyze, args, style, unicode_ok)
        return run_live(args, style, unicode_ok)
    except KeyboardInterrupt:
        print("\ninterrupted")
        return 130
    except BrokenPipeError:
        # Piping into head(1) and friends; exit quietly.
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
