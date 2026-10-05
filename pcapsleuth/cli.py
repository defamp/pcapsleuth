"""Command-line entry point for pcapsleuth."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .analyzer import analyze
from .models import FAILING_VERDICTS
from .reader import PcapError
from .report import render_html, render_json, render_markdown, render_terminal


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pcapsleuth",
        description="Analyze a .pcap/.pcapng capture: flows, DNS/HTTP/TLS, IOCs and "
        "detections (port scan, C2 beaconing, DNS tunneling, cleartext creds), mapped to MITRE ATT&CK.",
    )
    p.add_argument("pcap", help="path to a .pcap or .pcapng file")
    p.add_argument("-f", "--format", choices=["term", "md", "html", "json"], default="term")
    p.add_argument("-o", "--output", help="write to a file instead of stdout")
    p.add_argument("--top", type=int, default=10, metavar="N", help="rows to show in tables (default 10)")
    p.add_argument("--iocs-only", action="store_true", help="with -f json, emit just IOCs")
    p.add_argument("--no-fail", action="store_true", help="always exit 0")
    p.add_argument("-V", "--version", action="version", version=f"pcapsleuth {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rep = analyze(args.pcap)
    except FileNotFoundError:
        print(f"error: file not found: {args.pcap}", file=sys.stderr)
        return 2
    except PcapError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "term" and not args.output:
        render_terminal(rep, args.top)
    else:
        text = {
            "md": render_markdown,
            "html": render_html,
            "json": lambda r: render_json(r, iocs_only=args.iocs_only),
        }.get(args.format, render_markdown)(rep)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(text)
            print(f"wrote {args.format} report to {args.output}", file=sys.stderr)
        else:
            print(text)

    if not args.no_fail and rep.verdict in FAILING_VERDICTS:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
