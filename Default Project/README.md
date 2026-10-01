# netcap

A network traffic capture and analysis tool written in Python.

It captures packets off a live interface, dissects them layer by layer, decodes
the application protocols inside them, and reports on who talked to whom and
how much data moved.

```
     1  19:49:46.808  TCP    104.17.253.239:443  >  192.168.100.35:63684  [ACK]  -> 1445B (+1405B app)
     2  19:49:46.808  TCP    192.168.100.35:63684  >  104.17.253.239:443  [ACK]  -> 76B
     3  19:49:46.809  DNS    192.168.100.35:53124 >  192.168.100.1:53     example.com
```

---

## Install

```powershell
python -m pip install -r requirements.txt
```

Or, if `python` is not on `PATH` on Windows, use the bundled launcher:

```bat
netcap.cmd -L
```

That installs **scapy**, which is only needed for *live* capture. Everything
else -- the dissectors, the filter language, the statistics, the pcap reader
and writer -- uses nothing but the standard library, so you can analyse a
capture file on a machine with no packages at all.

### Privileges and drivers

| What | What you need |
| --- | --- |
| Live capture, scapy backend | [Npcap](https://npcap.com/) on Windows. No Administrator needed. |
| Live capture, socket backend | Administrator (Windows) or root (Linux/macOS). No extra driver. |
| Analysing a `.pcap` file | Nothing. Works offline, unprivileged. |

Npcap is the usual choice on Windows because it allows promiscuous mode
without elevating. Check what is available:

```powershell
python -m netcap -L
```

```
capture interfaces (the first one is used by default):

 * Wi-Fi
     Intel(R) Wi-Fi 6 AX201 160MHz
     192.168.100.35, fe80::70d0:5768:5181:9c39   mac dc:21:5c:8f:6c:ea
...
scapy installed:   yes
BPF engine:        yes
raw socket access: no (raw sockets need Administrator/root)
                  scapy + Npcap will be used instead, which is fine
```

## Use

```powershell
# Watch the first 40 packets on the default interface
python -m netcap -c 40

# Follow DNS lookups only
python -m netcap -f "udp port 53"

# Everything leaving to the internet on port 443
python -m netcap -f "tcp and dst port 443"

# Capture 500 packets and save them for later
python -m netcap -o session.pcap -c 500

# Dissect a capture file, showing the full protocol tree
python -m netcap -a session.pcap -v

# Collect statistics without printing per-packet lines
python -m netcap -f "tcp or udp" -q --timeout 30
```

Press **q** to stop a live capture. Ctrl-C works too.

### On Windows

`python` is frequently not usable on Windows out of the box: the `python.exe`
that ships with the OS is a Microsoft Store stub that does nothing when run.
`netcap.cmd` works around that by locating a real interpreter:

```bat
netcap.cmd -L
netcap.cmd -a examples\sample.pcap -v
netcap.cmd -c 40 -f "tcp port 443"
```

Every argument is passed straight through, so anything below works with it too.
If you would rather fix `PATH`, add the interpreter's `Scripts` directory as
well, so `netcap` and `scapy` are on the command line:

```
C:\Users\<you>\AppData\Local\Programs\Python\Python312\
C:\Users\<you>\AppData\Local\Programs\Python\Python312\Scripts\
```

### Try it without capturing anything

`examples/sample.pcap` is a real 127-packet capture containing plain HTTP
requests, DNS lookups and a TLS handshake, so you can explore every feature
without needing capture privileges or generating traffic:

```powershell
python -m netcap -a examples/sample.pcap
python -m netcap -a examples/sample.pcap -v -f "src port 53"
python -m netcap -a examples/sample.pcap -f "tcp port 80"
```

### Options

| Flag | Meaning |
| --- | --- |
| `-i, --interface NAME` | Interface to capture on (default: the one with the default route) |
| `-a, --analyze FILE` | Dissect a saved `.pcap` instead of capturing |
| `-f, --filter EXPR` | Filter expression (see below) |
| `-c, --count N` | Stop after N packets |
| `--timeout SEC` | Stop after SEC seconds |
| `-s, --snaplen BYTES` | Bytes stored per packet (default: all) |
| `--no-promisc` | Don't put the interface in promiscuous mode |
| `--backend {auto,scapy,socket}` | Capture backend |
| `-L, --list-interfaces` | List interfaces and capabilities, then exit |
| `-o, --output FILE` | Write captured packets to a `.pcap` file |
| `-v, --verbose` | Full protocol tree per packet, with payload hex dump |
| `-q, --quiet` | No per-packet lines, just the summary |
| `--no-hex` | Omit the hex dump from verbose output |
| `--no-summary` | Skip the end-of-capture report |
| `--no-color` | Disable ANSI colour |
| `--ascii` | Plain ASCII instead of box-drawing characters |

## The filter language

Modelled on tcpdump's syntax, but implemented in Python so it works without a
BPF engine.

```
tcp  udp  icmp  arp  ip  ip6          protocol
host 10.0.0.1                        IPv4 address
net 192.168.1.0/24                   network
port 443                             transport port, either direction
src port 443   dst port 443          one direction
proto tcp                           synonym for "tcp"
```

Combine with `and`, `or`, `not` and parentheses. As in tcpdump, `and` may be
left implicit between two primitives:

```
"tcp and port 443 and not host 10.0.0.5"
"(udp or icmp) and host 192.168.1.1"
"tcp port 80"                 # same as "tcp and port 80"
"port 53 or (tcp port 80)"
```

When an NPF/libpcap BPF engine is available the expression is handed to the
kernel, so filtering costs almost nothing. Without one, netcap prints a warning
and evaluates the filter in Python instead -- same results, more CPU.

## What gets decoded

**Link** -- Ethernet II, 802.1Q/802.1ad VLAN tags, Linux cooked capture, BSD
loopback, raw IP.

**Network** -- IPv4 (including options, TTL, DSCP, the DF/MF flags and fragment
offsets), IPv6 (including the extension header chain), ARP.

**Transport** -- TCP (flags, sequence and acknowledgement numbers, window, and
options such as MSS, SACK, window scale and timestamps), UDP, ICMP and ICMPv6.

**Application** -- DNS (queries and responses, with compression-pointer
following), HTTP/1.x (method, target, status, headers, body preview) and TLS
(record type, version, ClientHello SNI and ALPN, alerts).

Credentials are never printed. `Cookie`, `Authorization`, `Set-Cookie` and
similar headers are shown as present with the value masked, because captures
get pasted into issue trackers.

## The summary report

At the end of a capture you get protocol mix, top talkers split into sent and
received bytes, the busiest conversations, destination ports, TCP flag counts,
ICMP types, the hostnames seen, and any dissection warnings.

```
PROTOCOL MIX
--------------------------------------------------------------------------
  tcp            25  100.0%  ########################################  24.9 KiB
  udp             4    0.8%  #                                     312 B

APPLICATION PROTOCOLS
--------------------------------------------------------------------------
  DNS             4

TOP TALKERS
--------------------------------------------------------------------------
  address                    pkts        sent     received
  192.168.100.35               29    24.1 KiB       312 B
  104.17.253.239               25       308 B    24.9 KiB

TOP CONVERSATIONS (BY BYTES)
--------------------------------------------------------------------------
  endpoints                                          pkts       bytes  most data
  104.17.253.239:443 <-> 192.168.100.35:63684           25    24.9 KiB   97% 104.17.253.239 -> 192.168.100.35
```

## How it fits together

Each file does one job, and only `capture.py` needs a third-party package.

| File | Responsibility | Needs scapy? |
| --- | --- | --- |
| `netcap/pcap.py` | The libpcap container format: read, write, link types | no |
| `netcap/dissect.py` | Byte-level dissection of every header layer | no |
| `netcap/appproto.py` | DNS, HTTP and TLS decoders | no |
| `netcap/filter.py` | The filter expression parser and evaluator | no |
| `netcap/stats.py` | Flows, conversations, protocol counters | no |
| `netcap/display.py` | Colour, packet lines, layer tree, report | no |
| `netcap/capture.py` | Live capture: scapy and raw-socket backends | yes, for live |
| `netcap/cli.py` | Argument parsing and the capture loop | no |

The analysis layer takes raw bytes, so it is identical whether a packet came
from a live socket or a file, and it is readable end to end.

### Two details that matter for keeping up with a link

**The layer tree is built only when you ask for it.** `dissect()` takes a
`detail` flag. With `detail=False` (the default for a normal capture) it skips
building the formatted field mappings that only `-v` prints, and skips the
service-name lookups for every port. There is a test asserting that both paths
produce identical scalars, identical application facts, and identical
statistics, so this is purely an optimisation.

**The capture queue is bounded.** Python cannot dissect packets as fast as a
busy link delivers them, so the backend hands packets to the analysis thread
through a fixed-size queue and counts anything it has to drop. If that happens
netcap says so at the end rather than letting a partial capture look complete;
`--quiet` is usually the answer.

Together these took packet dissection from about 2.9 ms to 12 us per packet on
the development machine -- a 238x difference, and the difference between
following a link and falling hopelessly behind it.

### Both capture backends

`--backend scapy` puts the interface into promiscuous mode and delivers whole
frames including the Ethernet header, and can push the filter down into the
kernel. On Windows, netcap enables Npcap when it is present so this works
without Administrator.

`--backend socket` opens a `SOCK_RAW` / `IPPROTO_RAW` socket using only the
standard library. It needs Administrator or root, and it has two limits worth
knowing: you receive the IP header and payload but **not** the Ethernet header,
so MAC addresses are missing; and there is no BPF, so every IP packet on the
machine is delivered and filtered in Python.

## Reading a packet in detail

```
Frame 1
  `- Timestamp: 1790520586.808956
  `- Length: 1459 bytes on the wire, 1459 bytes captured
  `- Link type: Ethernet
     >  Ethernet
           Destination: dc:21:5c:8f:6c:ea
           Source: 90:25:f2:ec:d6:79
           Type: 0x0800 (IPv4)
     >  IPv4
           Version: 4
           Header length: 20 bytes
           DSCP / TOS: 0x00 (default)
           Total length: 1445 bytes
           Identification: 0x98e5 (39141)
           Flags: DF
           Fragment offset: 0
           TTL: 56
           Protocol: 6 (TCP)
           Source: 104.17.253.239
           Destination: 192.168.100.35
     `- TCP
           Source port: 443 (https)
           Destination port: 63684
           Sequence: 3821663626
           Acknowledgment: 2385221933
           Header length: 20 bytes
           Flags: ACK
           Window: 18
           Checksum: 0x0feb
     `- Payload (1405 bytes)
           00000000  f2 9f d5 12 1f 0d 46 1d be a3 a0 a2 42 ad bf 1b  ......F.....B...
```

`TTL: 56` and `Window: 18` are the interesting numbers here: TTL has already
been decremented a fair way, which means the packets crossed several hops.

## Using it as a library

```python
from netcap.pcap import PcapReader
from netcap.dissect import dissect

with PcapReader("session.pcap") as reader:
    for raw in reader:
        info = dissect(raw.data, reader.link_type, raw.ts)
        if info.l4_proto == "tcp" and info.dst_port == 443:
            print(info.src_ip, info.flags, info.payload_len)
            if info.app:
                print("  ", info.app["label"], info.app["fields"])
```

Compiling a filter and reusing it:

```python
from netcap.filter import compile_filter

https_only = compile_filter("tcp and port 443")
if https_only(info):
    ...
```

## Tests

```powershell
python -m unittest discover -s tests -v
```

66 tests. The packet dissectors are checked against packets built by scapy, so
the bytes under test are correct by construction, plus hand-built frames for
the cases scapy will not generate. There is a fuzz-ish test that feeds 2000
random byte strings at every supported link type, because a dissector that
crashes on malformed input is worse than no dissector at all.

## Legal note

Packet capture on a network you do not own or have permission to monitor is
illegal in most jurisdictions. Use this on your own machine, your own network,
or where you have written authorisation.

## Publishing a capture you made yourself

Captures contain other people's infrastructure, so do not commit one straight off
the wire. `tools/anonymise_pcap.py` rewrites a capture so it is safe to share:

```bat
python tools\anonymise_pcap.py my-capture.pcap
```

It replaces every IPv4 address with a pseudonym from the ranges reserved for
documentation (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`),
maps IPv6 into `2001:db8::/32`, and zeroes the MAC addresses. Each distinct
address keeps its own pseudonym, so a conversation still looks like a
conversation between two hosts.

Two details it takes care of, both of which would otherwise leave you shipping
something misleading:

- **Checksums are recomputed.** The IPv4 header checksum and the TCP/UDP
  checksums all cover the addresses, so they are recalculated afterwards. A
  published sample with stale checksums teaches the wrong thing.
- **DNS answers are rewritten too.** Otherwise the capture would say "this name
  resolves to that address" while showing a connection to a different one.

The rewrite is in place on `examples/sample.pcap` already, which is why every
address in it is a documentation address.

## Learn more

- [RFC 791](https://www.rfc-editor.org/rfc/rfc791) -- Internet Protocol
- [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293) -- TCP
- [RFC 768](https://www.rfc-editor.org/rfc/rfc768) -- UDP
- [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) -- DNS
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) -- TLS 1.3
- [The Wireshark Display Filter Reference](https://www.wireshark.org/docs/wsug_html_chunked/DisplayFilters.html)
