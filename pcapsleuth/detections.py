"""Detection rules over the aggregated capture.

Each rule returns zero or more Findings with a MITRE ATT&CK mapping. Thresholds
are module constants so they're easy to tune and to assert against in tests.
"""

from __future__ import annotations

import base64
import statistics
from collections import defaultdict
from typing import Dict, Iterable, List, Tuple

from .models import Finding, Report
from .utils import is_private, shannon_entropy

# --- tunables -------------------------------------------------------------- #
SCAN_PORT_THRESHOLD = 15        # distinct dst ports from one src -> vertical scan
SCAN_HOST_THRESHOLD = 15        # distinct dst hosts on one port -> horizontal scan
BEACON_MIN_CONNS = 5            # connections needed to call something a beacon
BEACON_MAX_CV = 0.25           # interval coefficient-of-variation below this = regular
DNS_TUNNEL_MIN_QUERIES = 20     # queries to one parent domain
DNS_LONG_LABEL = 40             # subdomain label length that looks encoded
DNS_HIGH_ENTROPY = 3.5          # bits/char suggesting encoded data
EXFIL_BYTES = 5 * 1024 * 1024   # outbound bytes to one external host -> possible exfil

BAD_PORTS = {
    4444: "Metasploit / Meterpreter default",
    5555: "Android ADB / common backdoor",
    6666: "IRC botnet",
    6667: "IRC (C2)",
    1337: "'leet' backdoor",
    31337: "Back Orifice / 'elite' backdoor",
    12345: "NetBus backdoor",
    9001: "Tor ORPort / C2",
    4445: "known RAT",
}

_SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _parent_domain(name: str) -> str:
    labels = name.rstrip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else name


def detect_port_scan(syn_events) -> List[Finding]:
    by_src_ports: Dict[str, set] = defaultdict(set)
    by_src_hosts: Dict[Tuple[str, int], set] = defaultdict(set)
    for ts, src, dst, dport in syn_events:
        by_src_ports[src].add(dport)
        by_src_hosts[(src, dport)].add(dst)
    out: List[Finding] = []
    for src, ports in by_src_ports.items():
        if len(ports) >= SCAN_PORT_THRESHOLD:
            out.append(Finding("high", "port-scan-vertical",
                "Vertical port scan from %s" % src,
                "%s sent SYN to %d distinct ports — consistent with a port scan." % (src, len(ports)),
                ["T1046", "T1595.001"]))
    for (src, dport), hosts in by_src_hosts.items():
        if len(hosts) >= SCAN_HOST_THRESHOLD:
            out.append(Finding("high", "port-scan-horizontal",
                "Horizontal scan on port %d from %s" % (dport, src),
                "%s probed port %d across %d hosts — network sweep." % (src, dport, len(hosts)),
                ["T1046", "T1595.001"]))
    return out


def detect_beaconing(syn_events) -> List[Finding]:
    groups: Dict[Tuple[str, str, int], List[float]] = defaultdict(list)
    for ts, src, dst, dport in syn_events:
        groups[(src, dst, dport)].append(ts)
    out: List[Finding] = []
    for (src, dst, dport), times in groups.items():
        if len(times) < BEACON_MIN_CONNS:
            continue
        times.sort()
        gaps = [b - a for a, b in zip(times, times[1:])]
        mean = statistics.mean(gaps)
        if mean <= 0:
            continue
        cv = statistics.pstdev(gaps) / mean
        if cv <= BEACON_MAX_CV:
            out.append(Finding("high", "beaconing",
                "Periodic beaconing %s → %s:%d" % (src, dst, dport),
                "%d connections every ~%.0fs (jitter %.0f%%) — classic C2 beacon pattern." % (
                    len(times), mean, cv * 100),
                ["T1071", "T1571"]))
    return out


def detect_dns_tunneling(dns) -> List[Finding]:
    by_parent: Dict[str, List] = defaultdict(list)
    for q in dns:
        by_parent[_parent_domain(q.qname)].append(q)
    out: List[Finding] = []
    for parent, qs in by_parent.items():
        labels = [q.qname.split(".")[0] for q in qs]
        long_labels = [l for l in labels if len(l) >= DNS_LONG_LABEL]
        entropies = [shannon_entropy(l) for l in labels if l]
        avg_ent = statistics.mean(entropies) if entropies else 0
        txtish = sum(1 for q in qs if q.qtype in ("TXT", "NULL"))
        suspicious = (len(qs) >= DNS_TUNNEL_MIN_QUERIES and (long_labels or avg_ent >= DNS_HIGH_ENTROPY)) \
            or len(long_labels) >= 5 or (txtish >= 10)
        if suspicious:
            out.append(Finding("high", "dns-tunneling",
                "Possible DNS tunneling via %s" % parent,
                "%d queries (avg label entropy %.1f, %d long labels, %d TXT/NULL) — data may be exfiltrated over DNS." % (
                    len(qs), avg_ent, len(long_labels), txtish),
                ["T1071.004", "T1048.003"]))
    return out


def detect_cleartext_and_creds(rep: Report, flows) -> List[Finding]:
    out: List[Finding] = []
    for h in rep.http:
        if h.auth.lower().startswith("basic "):
            user = ""
            try:
                user = base64.b64decode(h.auth.split(None, 1)[1]).decode("utf-8", "replace").split(":", 1)[0]
            except Exception:  # noqa: BLE001
                pass
            out.append(Finding("high", "http-basic-creds",
                "Cleartext HTTP Basic credentials",
                "Authorization: Basic to %s%s exposes credentials%s over plaintext HTTP." % (
                    h.host, h.uri, " (user '%s')" % user if user else ""),
                ["T1552.001", "T1040"]))
    seen_proto = set()
    for f in flows:
        # Require an actual session (>= 3 packets) so a single scan SYN to
        # port 21/23 isn't mistaken for real FTP/Telnet traffic.
        if f.packets < 3:
            continue
        if f.proto == "tcp" and (f.dport == 23 or f.sport == 23) and "telnet" not in seen_proto:
            seen_proto.add("telnet")
            out.append(Finding("medium", "cleartext-telnet", "Telnet traffic (cleartext)",
                "Telnet transmits everything, including credentials, in the clear.", ["T1040"]))
        if f.proto == "tcp" and (f.dport == 21 or f.sport == 21) and "ftp" not in seen_proto:
            seen_proto.add("ftp")
            out.append(Finding("medium", "cleartext-ftp", "FTP traffic (cleartext)",
                "FTP control channel sends credentials and commands in plaintext.", ["T1040"]))
    return out


def detect_bad_ports(flows) -> List[Finding]:
    out: List[Finding] = []
    seen = set()
    for f in flows:
        port = f.dport if f.dport in BAD_PORTS else (f.sport if f.sport in BAD_PORTS else None)
        if port and port not in seen and (not is_private(f.dst) or not is_private(f.src)):
            seen.add(port)
            out.append(Finding("high", "suspicious-port-%d" % port,
                "Traffic on suspicious port %d" % port,
                "%s:%d ↔ %s — %s." % (f.src, port, f.dst, BAD_PORTS[port]),
                ["T1571"]))
    return out


def detect_exfil(flows) -> List[Finding]:
    by_pair: Dict[Tuple[str, str], int] = defaultdict(int)
    for f in flows:
        if f.src and f.dst and is_private(f.src) and not is_private(f.dst):
            by_pair[(f.src, f.dst)] += f.bytes
    out: List[Finding] = []
    for (src, dst), total in by_pair.items():
        if total >= EXFIL_BYTES:
            out.append(Finding("medium", "large-egress",
                "Large outbound transfer %s → %s" % (src, dst),
                "%.1f MB sent to an external host — review for data exfiltration." % (total / 1024 / 1024),
                ["T1041", "T1048"]))
    return out


def run(rep: Report, flows: Iterable, syn_events) -> List[Finding]:
    flows = list(flows)
    f: List[Finding] = []
    f += detect_port_scan(syn_events)
    f += detect_beaconing(syn_events)
    f += detect_dns_tunneling(rep.dns)
    f += detect_cleartext_and_creds(rep, flows)
    f += detect_bad_ports(flows)
    f += detect_exfil(flows)
    f.sort(key=lambda x: _SEV.get(x.severity, 0), reverse=True)
    return f


def verdict(findings: List[Finding]) -> str:
    if not findings:
        return "CLEAN"
    top = max(_SEV.get(x.severity, 0) for x in findings)
    return {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "CLEAN"}[top]
