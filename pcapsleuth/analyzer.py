"""Aggregate dissected packets into a :class:`Report`, then run detections."""

from __future__ import annotations

from typing import Dict, List, Tuple

import dpkt

from . import detections
from .models import DnsQuery, Flow, HttpReq, Report
from .reader import read
from .utils import dedupe, is_private

DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR",
             15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}


def _parse_sni(payload: bytes) -> str:
    """Pull the server_name from a TLS ClientHello, tolerantly."""
    try:
        if not payload or payload[0] != 0x16:  # not a handshake record
            return ""
        # record(5) | handshake header(4) | version(2) | random(32) ...
        p = payload[5:]
        if not p or p[0] != 0x01:  # not ClientHello
            return ""
        i = 4 + 2 + 32
        sid_len = p[i]; i += 1 + sid_len
        cs_len = int.from_bytes(p[i:i + 2], "big"); i += 2 + cs_len
        comp_len = p[i]; i += 1 + comp_len
        ext_total = int.from_bytes(p[i:i + 2], "big"); i += 2
        end = i + ext_total
        while i + 4 <= end:
            etype = int.from_bytes(p[i:i + 2], "big")
            elen = int.from_bytes(p[i + 2:i + 4], "big")
            body = p[i + 4:i + 4 + elen]
            i += 4 + elen
            if etype == 0x00 and len(body) >= 5:  # server_name
                name_len = int.from_bytes(body[3:5], "big")
                return body[5:5 + name_len].decode("idna", "replace")
    except (IndexError, ValueError, UnicodeError):
        return ""
    return ""


def analyze(path: str) -> Report:
    rep = Report(path=path)
    flows: Dict[Tuple, Flow] = {}
    host_bytes: Dict[str, int] = {}
    host_pkts: Dict[str, int] = {}
    proto_counts: Dict[str, int] = {}
    app_counts: Dict[str, int] = {}
    syn_events: List[Tuple[float, str, str, int]] = []   # (ts, src, dst, dport)

    for pkt in read(path):
        rep.packets += 1
        rep.bytes += pkt.length
        if rep.start_ts == 0 or pkt.ts < rep.start_ts:
            rep.start_ts = pkt.ts
        rep.end_ts = max(rep.end_ts, pkt.ts)
        proto_counts[pkt.proto] = proto_counts.get(pkt.proto, 0) + 1

        if pkt.src:
            host_bytes[pkt.src] = host_bytes.get(pkt.src, 0) + pkt.length
            host_pkts[pkt.src] = host_pkts.get(pkt.src, 0) + 1
        if pkt.dst:
            host_bytes[pkt.dst] = host_bytes.get(pkt.dst, 0) + pkt.length
            host_pkts[pkt.dst] = host_pkts.get(pkt.dst, 0) + 1

        if pkt.proto in ("tcp", "udp"):
            key = (pkt.src, pkt.dst, pkt.sport, pkt.dport, pkt.proto)
            fl = flows.get(key)
            if fl is None:
                fl = flows[key] = Flow(pkt.src, pkt.dst, pkt.sport, pkt.dport, pkt.proto, first_ts=pkt.ts)
            fl.packets += 1
            fl.bytes += pkt.length
            fl.last_ts = pkt.ts

        if pkt.proto == "tcp":
            syn = bool(pkt.flags & dpkt.tcp.TH_SYN)
            ack = bool(pkt.flags & dpkt.tcp.TH_ACK)
            if syn and not ack:
                flows[key].syn += 1
                syn_events.append((pkt.ts, pkt.src, pkt.dst, pkt.dport))
            if syn and ack:
                flows[key].synack += 1
            if pkt.flags & dpkt.tcp.TH_RST:
                flows[key].rst += 1

        # Application-layer parsing.
        if pkt.proto == "udp" and (pkt.dport == 53 or pkt.sport == 53):
            app_counts["dns"] = app_counts.get("dns", 0) + 1
            try:
                dns = dpkt.dns.DNS(pkt.payload)
                for q in dns.qd:
                    name = q.name if isinstance(q.name, str) else q.name.decode("utf-8", "replace")
                    rep.dns.append(DnsQuery(pkt.ts, pkt.src, name, DNS_TYPES.get(q.type, str(q.type))))
            except Exception:  # noqa: BLE001
                pass
        elif pkt.proto == "tcp" and (pkt.dport == 80 or pkt.sport == 80) and pkt.payload[:4] in (
            b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"OPTI", b"PATC"):
            app_counts["http"] = app_counts.get("http", 0) + 1
            try:
                r = dpkt.http.Request(pkt.payload)
                h = {k.lower(): v for k, v in r.headers.items()}
                rep.http.append(HttpReq(
                    ts=pkt.ts, src=pkt.src, dst=pkt.dst, method=r.method,
                    host=h.get("host", ""), uri=r.uri,
                    user_agent=h.get("user-agent", ""), auth=h.get("authorization", ""),
                ))
            except Exception:  # noqa: BLE001
                pass
        elif pkt.proto == "tcp" and (pkt.dport == 443 or pkt.sport == 443) and pkt.payload[:1] == b"\x16":
            app_counts["tls"] = app_counts.get("tls", 0) + 1
            sni = _parse_sni(pkt.payload)
            if sni:
                rep.tls_sni.append(sni)

    rep.proto_counts = proto_counts
    rep.app_counts = app_counts
    rep.tls_sni = dedupe(rep.tls_sni)
    rep.flows = sorted(flows.values(), key=lambda f: f.bytes, reverse=True)
    rep.talkers = sorted(
        [(ip, host_bytes[ip], host_pkts[ip]) for ip in host_bytes],
        key=lambda t: t[1], reverse=True,
    )[:15]

    _extract_iocs(rep)
    rep.findings = detections.run(rep, flows.values(), syn_events)
    rep.verdict = detections.verdict(rep.findings)
    return rep


def _extract_iocs(rep: Report) -> None:
    domains = [d.qname for d in rep.dns] + list(rep.tls_sni) + [h.host for h in rep.http if h.host]
    ips = [t[0] for t in rep.talkers if t[0] and not is_private(t[0])]
    urls = ["http://" + h.host + h.uri for h in rep.http if h.host]
    rep.iocs = {
        "domains": dedupe(domains),
        "external_ips": dedupe(ips),
        "urls": dedupe(urls),
    }
