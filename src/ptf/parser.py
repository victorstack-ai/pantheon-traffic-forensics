from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Iterable

# Nginx combined log regex
NGINX_LOG_RE = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)] "
    r'"(?P<method>\S+) (?P<path>\S+) (?P<proto>[^"]+)" '
    r"(?P<status>\d{3}) (?P<size>\S+) "
    r'"(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
)

# Apache combined log regex -- handles the same field order but
# is more lenient with the byte-count field (accepts "-") and
# allows optional trailing fields that some Apache configs add.
APACHE_LOG_RE = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)] "
    r'"(?P<method>\S+) (?P<path>\S+)'
    r"(?: (?P<proto>[^\"]*))?"
    r'" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?'
)

LOG_FORMATS: dict[str, re.Pattern[str]] = {
    "nginx": NGINX_LOG_RE,
    "apache": APACHE_LOG_RE,
}

SUSPICIOUS_AGENTS = (
    "bot",
    "spider",
    "crawler",
    "curl",
    "wget",
    "python",
    "java",
    "httpclient",
)

SUSPICIOUS_PATH_HINTS = (
    "/wp-json",
    "/xmlrpc.php",
    "/.env",
    "/phpmyadmin",
    "/wp-admin",
    "/administrator",
)


@dataclass(frozen=True)
class LogEvent:
    ip: str
    method: str
    path: str
    status: int
    agent: str


@dataclass
class TrafficSummary:
    total: int
    top_paths: list[tuple[str, int]]
    top_ips: list[tuple[str, int]]
    top_agents: list[tuple[str, int]]
    status_counts: list[tuple[int, int]]
    suspicious_hits: list[tuple[str, str, str]]


def normalize_path(raw_path: str) -> str:
    return raw_path.split("?", 1)[0]


def parse_line(
    line: str,
    fmt: str = "nginx",
) -> LogEvent | None:
    """Parse a single log line.

    *fmt* selects the regex: ``"nginx"`` (default) or
    ``"apache"``.
    """
    pattern = LOG_FORMATS.get(fmt)
    if pattern is None:
        raise ValueError(
            f"Unknown log format {fmt!r}. "
            f"Choose from: {', '.join(LOG_FORMATS)}"
        )

    match = pattern.match(line.strip())
    if not match:
        return None

    path = normalize_path(match.group("path"))
    agent = match.group("agent") or ""
    return LogEvent(
        ip=match.group("ip"),
        method=match.group("method"),
        path=path,
        status=int(match.group("status")),
        agent=agent,
    )


def classify_suspicious(event: LogEvent) -> str | None:
    agent_lower = event.agent.lower()
    if not agent_lower:
        return "empty-user-agent"
    if any(token in agent_lower for token in SUSPICIOUS_AGENTS):
        return "bot-like-user-agent"
    if any(
        hint in event.path.lower()
        for hint in SUSPICIOUS_PATH_HINTS
    ):
        return "suspicious-path"
    return None


def summarize(
    lines: Iterable[str],
    top: int = 10,
    fmt: str = "nginx",
) -> TrafficSummary:
    """Summarize parsed log events.

    *fmt* is forwarded to :func:`parse_line`.
    """
    path_counter: Counter[str] = Counter()
    ip_counter: Counter[str] = Counter()
    agent_counter: Counter[str] = Counter()
    status_counter: Counter[int] = Counter()
    suspicious_hits: list[tuple[str, str, str]] = []
    total = 0

    for line in lines:
        event = parse_line(line, fmt=fmt)
        if not event:
            continue
        total += 1
        path_counter[event.path] += 1
        ip_counter[event.ip] += 1
        agent_counter[event.agent or "(empty)"] += 1
        status_counter[event.status] += 1
        reason = classify_suspicious(event)
        if reason:
            suspicious_hits.append(
                (reason, event.path, event.agent or "(empty)")
            )

    return TrafficSummary(
        total=total,
        top_paths=path_counter.most_common(top),
        top_ips=ip_counter.most_common(top),
        top_agents=agent_counter.most_common(top),
        status_counts=sorted(status_counter.items()),
        suspicious_hits=suspicious_hits[:top],
    )
