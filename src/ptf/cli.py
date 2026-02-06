from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ptf.parser import summarize


def _render_table(title: str, rows: list[tuple[str, int]]) -> str:
    if not rows:
        return f"{title}: none"
    lines = [f"{title}:"]
    width = max(len(str(row[0])) for row in rows)
    for label, count in rows:
        lines.append(f"  {label:<{width}}  {count}")
    return "\n".join(lines)


def _render_status(rows: list[tuple[int, int]]) -> str:
    lines = ["Status codes:"]
    for code, count in rows:
        lines.append(f"  {code}: {count}")
    return "\n".join(lines)


def analyze(path: Path, top: int, as_json: bool) -> int:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        print(f"File not found: {path}", file=sys.stderr)
        return 2

    summary = summarize(lines, top=top)

    if as_json:
        payload = {
            "total": summary.total,
            "top_paths": summary.top_paths,
            "top_ips": summary.top_ips,
            "top_agents": summary.top_agents,
            "status_counts": summary.status_counts,
            "suspicious_hits": summary.suspicious_hits,
        }
        print(json.dumps(payload, indent=2))
        return 0

    print(f"Total parsed requests: {summary.total}")
    print(_render_table("Top paths", summary.top_paths))
    print(_render_table("Top IPs", summary.top_ips))
    print(_render_table("Top user agents", summary.top_agents))
    print(_render_status(summary.status_counts))
    if summary.suspicious_hits:
        print("Suspicious hits:")
        for reason, path_hit, agent in summary.suspicious_hits:
            print(f"  {reason} | {path_hit} | {agent}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Pantheon traffic forensics")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Analyze an access log")
    analyze_parser.add_argument("logfile", type=Path, help="Path to access log")
    analyze_parser.add_argument("--top", type=int, default=10, help="Top N results")
    analyze_parser.add_argument("--json", action="store_true", help="JSON output")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "analyze":
        return analyze(args.logfile, args.top, args.json)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
