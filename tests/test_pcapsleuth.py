"""Tests for pcapsleuth. Run with: pytest"""

import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from pcapsleuth.analyzer import analyze
from pcapsleuth.detections import verdict
from pcapsleuth.models import Finding
from pcapsleuth.reader import PcapError
from pcapsleuth.report import render_html, render_json, render_markdown
from pcapsleuth.utils import is_private, shannon_entropy

SAMPLE = os.path.join(ROOT, "samples", "sample.pcap")


@pytest.fixture(scope="module")
def rep():
    return analyze(SAMPLE)


def ids(rep):
    return {f.id for f in rep.findings}


# --- parsing / aggregation -------------------------------------------------- #
def test_reads_sample(rep):
    assert rep.packets > 0
    assert rep.proto_counts.get("tcp", 0) > 0
    assert rep.proto_counts.get("udp", 0) > 0


def test_app_protocols(rep):
    assert rep.app_counts.get("dns", 0) > 0
    assert rep.app_counts.get("http", 0) >= 1


def test_top_talkers(rep):
    ips = [t[0] for t in rep.talkers]
    assert "10.0.0.5" in ips


# --- detections ------------------------------------------------------------- #
def test_detects_port_scan(rep):
    assert "port-scan-vertical" in ids(rep)


def test_detects_beaconing(rep):
    assert "beaconing" in ids(rep)
    f = next(f for f in rep.findings if f.id == "beaconing")
    assert "T1071" in f.ttps


def test_detects_dns_tunneling(rep):
    assert "dns-tunneling" in ids(rep)
    f = next(f for f in rep.findings if f.id == "dns-tunneling")
    assert "T1071.004" in f.ttps


def test_detects_cleartext_creds(rep):
    assert "http-basic-creds" in ids(rep)
    f = next(f for f in rep.findings if f.id == "http-basic-creds")
    assert "admin" in f.detail  # decoded username surfaced


def test_detects_bad_port(rep):
    assert "suspicious-port-4444" in ids(rep)


def test_no_false_telnet_ftp_from_scan(rep):
    # The port scan touches 21/23 but with a single SYN each — must NOT be
    # reported as real FTP/Telnet sessions.
    assert "cleartext-ftp" not in ids(rep)
    assert "cleartext-telnet" not in ids(rep)


def test_verdict_high(rep):
    assert rep.verdict == "HIGH"


def test_findings_sorted(rep):
    from pcapsleuth.detections import _SEV
    sev = [_SEV[f.severity] for f in rep.findings]
    assert sev == sorted(sev, reverse=True)


def test_iocs_extracted(rep):
    assert any("evil-exfil.com" in d for d in rep.iocs["domains"])
    assert rep.iocs["external_ips"]


# --- helpers ---------------------------------------------------------------- #
def test_is_private():
    assert is_private("10.0.0.5")
    assert is_private("192.168.1.1")
    assert not is_private("8.8.8.8")


def test_entropy_ordering():
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("a9Xk2Lp7")


def test_verdict_empty():
    assert verdict([]) == "CLEAN"
    assert verdict([Finding("critical", "x", "t", "d")]) == "CRITICAL"


# --- error handling --------------------------------------------------------- #
def test_not_a_pcap(tmp_path):
    p = tmp_path / "bad.pcap"
    p.write_bytes(b"this is not a pcap file at all")
    with pytest.raises(PcapError):
        list_rep = analyze(str(p))


# --- reporters -------------------------------------------------------------- #
def test_json_report(rep):
    data = json.loads(render_json(rep))
    assert data["verdict"] == "HIGH"
    assert data["findings"]


def test_markdown_report(rep):
    md = render_markdown(rep)
    assert "PCAP Triage" in md
    assert "dns-tunneling" in md or "DNS tunneling" in md


def test_html_report(rep):
    out = render_html(rep)
    assert out.startswith("<!doctype html>")
    assert "HIGH" in out
