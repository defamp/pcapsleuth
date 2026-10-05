"""Read a .pcap / .pcapng file and dissect each frame into a :class:`Packet`.

Uses dpkt for both the capture container and the L2-L4 decoding. Anything that
can't be parsed is skipped rather than aborting the whole analysis.
"""

from __future__ import annotations

import socket
from typing import Iterator

import dpkt

from .models import Packet


class PcapError(Exception):
    pass


def _open_reader(fh):
    magic = fh.read(4)
    fh.seek(0)
    # pcapng section header block magic.
    if magic == b"\x0a\x0d\x0d\x0a":
        return dpkt.pcapng.Reader(fh)
    return dpkt.pcap.Reader(fh)


def _ip_str(raw: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET if len(raw) == 4 else socket.AF_INET6, raw)
    except (ValueError, OSError):
        return ""


def _dissect(ts: float, buf: bytes, linktype: int) -> Packet:
    pkt = Packet(ts=ts, length=len(buf))
    try:
        if linktype == dpkt.pcap.DLT_EN10MB:
            eth = dpkt.ethernet.Ethernet(buf)
            l3 = eth.data
            if isinstance(eth.data, dpkt.arp.ARP):
                pkt.proto = "arp"
                return pkt
        elif linktype in (dpkt.pcap.DLT_RAW, 12, 14):
            l3 = dpkt.ip.IP(buf)
        elif linktype == dpkt.pcap.DLT_LINUX_SLL:
            l3 = dpkt.sll.SLL(buf).data
        else:
            l3 = dpkt.ethernet.Ethernet(buf).data
    except (dpkt.UnpackError, Exception):  # noqa: BLE001 - tolerate malformed frames
        pkt.proto = "other"
        return pkt

    if isinstance(l3, dpkt.ip.IP):
        pkt.src, pkt.dst = _ip_str(l3.src), _ip_str(l3.dst)
    elif isinstance(l3, dpkt.ip6.IP6):
        pkt.src, pkt.dst = _ip_str(l3.src), _ip_str(l3.dst)
    else:
        pkt.proto = "other"
        return pkt

    l4 = getattr(l3, "data", b"")
    if isinstance(l4, dpkt.tcp.TCP):
        pkt.proto, pkt.sport, pkt.dport, pkt.flags, pkt.payload = "tcp", l4.sport, l4.dport, l4.flags, bytes(l4.data)
    elif isinstance(l4, dpkt.udp.UDP):
        pkt.proto, pkt.sport, pkt.dport, pkt.payload = "udp", l4.sport, l4.dport, bytes(l4.data)
    elif isinstance(l4, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)):
        pkt.proto = "icmp"
    else:
        pkt.proto = "other"
    return pkt


def read(path: str) -> Iterator[Packet]:
    """Yield dissected packets from a capture file."""
    try:
        fh = open(path, "rb")
    except OSError as exc:
        raise PcapError(str(exc)) from exc
    with fh:
        try:
            reader = _open_reader(fh)
            linktype = reader.datalink()
        except Exception as exc:  # noqa: BLE001
            raise PcapError("not a valid pcap/pcapng file: %s" % exc) from exc
        for ts, buf in reader:
            yield _dissect(ts, buf, linktype)
