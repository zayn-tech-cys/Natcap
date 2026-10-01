"""
netcap - a small network traffic capture and analysis toolkit.

Layering (deliberately separated so each piece can be read on its own):

    pcap.py      pcap file container format (read/write)  - zero dependencies
    dissect.py   byte-level protocol dissection           - zero dependencies
    appproto.py  application-layer decoders (DNS/HTTP/TLS) - zero dependencies
    filter.py    simple filter expressions                 - zero dependencies
    stats.py     flows, conversations, protocol counters   - zero dependencies
    display.py   terminal rendering                       - zero dependencies
    capture.py   live capture backends (scapy / raw socket)
    cli.py       command line interface

Only `capture.py` needs a third-party package (scapy, for live capture with a
BPF filter and promiscuous mode). Everything else works on raw bytes, which is
what makes the analysis readable and dependency-free.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
