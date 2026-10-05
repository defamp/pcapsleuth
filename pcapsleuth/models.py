"""Normalised data model produced by the analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Shared verdict ladder (same scale across the toolkit).
VERDICTS = ["CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
FAILING_VERDICTS = {"HIGH", "CRITICAL"}


@dataclass
class Packet:
    """A dissected L3/L4 packet (only the fields the analyzer needs)."""

    ts: float
    src: str = ""
    dst: str = ""
    proto: str = ""          # tcp / udp / icmp / arp / other
    sport: int = 0
    dport: int = 0
    length: int = 0
    flags: int = 0           # TCP flags
    payload: bytes = b""


@dataclass
class Flow:
    src: str
    dst: str
    sport: int
    dport: int
    proto: str
    packets: int = 0
    bytes: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    syn: int = 0
    synack: int = 0
    rst: int = 0

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)


@dataclass
class DnsQuery:
    ts: float
    src: str
    qname: str
    qtype: str


@dataclass
class HttpReq:
    ts: float
    src: str
    dst: str
    method: str
    host: str
    uri: str
    user_agent: str = ""
    auth: str = ""           # raw Authorization header value if present


@dataclass
class Finding:
    severity: str            # critical / high / medium / low / info
    id: str
    title: str
    detail: str
    ttps: List[str] = field(default_factory=list)


@dataclass
class Report:
    path: str = ""
    packets: int = 0
    bytes: int = 0
    start_ts: float = 0.0
    end_ts: float = 0.0
    proto_counts: Dict[str, int] = field(default_factory=dict)
    app_counts: Dict[str, int] = field(default_factory=dict)
    talkers: List[Tuple[str, int, int]] = field(default_factory=list)   # (ip, bytes, packets)
    flows: List[Flow] = field(default_factory=list)
    dns: List[DnsQuery] = field(default_factory=list)
    http: List[HttpReq] = field(default_factory=list)
    tls_sni: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    iocs: Dict[str, List[str]] = field(default_factory=dict)
    verdict: str = "CLEAN"

    @property
    def duration(self) -> float:
        return max(0.0, self.end_ts - self.start_ts)

    def to_dict(self) -> Dict:
        return {
            "file": self.path,
            "packets": self.packets,
            "bytes": self.bytes,
            "duration_sec": round(self.duration, 2),
            "verdict": self.verdict,
            "protocols": self.proto_counts,
            "app_protocols": self.app_counts,
            "top_talkers": [{"ip": ip, "bytes": b, "packets": p} for ip, b, p in self.talkers],
            "findings": [
                {"severity": f.severity, "id": f.id, "title": f.title, "detail": f.detail, "ttps": f.ttps}
                for f in self.findings
            ],
            "iocs": self.iocs,
            "dns_queries": [{"qname": d.qname, "qtype": d.qtype, "src": d.src} for d in self.dns],
            "http_requests": [
                {"method": h.method, "host": h.host, "uri": h.uri, "src": h.src} for h in self.http
            ],
            "tls_sni": self.tls_sni,
        }
