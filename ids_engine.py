from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable


WINDOWS_EVENT_TIME = "%Y-%m-%d %H:%M:%S"
ISO_EVENT_TIME = "%Y-%m-%dT%H:%M:%S"
APACHE_EVENT_TIME = "%d/%b/%Y:%H:%M:%S %z"


IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
KV_PATTERN = re.compile(r"\b([A-Za-z_][\w-]*)=([^\s]+)")
APACHE_PATTERN = re.compile(
    r'^(?P<src_ip>(?:\d{1,3}\.){3}\d{1,3}) \S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>.*?) '
    r'HTTP/(?P<http_version>[^"]+)" (?P<status>\d{3}) (?P<size>\S+)'
)
PROXIFIER_PATTERN = re.compile(
    r"^\[(?P<month>\d{2})\.(?P<day>\d{2}) (?P<clock>\d{2}:\d{2}:\d{2})\] "
    r"(?P<app>.+?) - (?P<target>[^:\s]+):(?P<port>\d{1,5}) (?P<detail>.*)$"
)
BYTE_COUNT_PATTERN = re.compile(r"(?P<count>\d+)\s+bytes\s+(?P<direction>sent|received)", re.IGNORECASE)

FAILED_LOGIN_PATTERNS = (
    "failed password",
    "authentication failure",
    "failed login",
    "logon failure",
    "invalid user",
)

WEB_ATTACK_PATTERNS = {
    "SQL injection probe": re.compile(
        r"('|%27)\s*(or|and)\s*('|%27)?\w+('|%27)?\s*=\s*('|%27)?\w+|union\s+select|sleep\s*\(",
        re.IGNORECASE,
    ),
    "Cross-site scripting probe": re.compile(
        r"<script|%3cscript|javascript:|onerror\s*=",
        re.IGNORECASE,
    ),
    "Path traversal probe": re.compile(
        r"\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f",
        re.IGNORECASE,
    ),
    "Command injection probe": re.compile(
        r"(\||%7c|;|%3b)\s*(cat|whoami|cmd|powershell|wget|curl)\b",
        re.IGNORECASE,
    ),
}


@dataclass(frozen=True)
class Event:
    timestamp: datetime | None
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    event_type: str
    message: str
    fields: dict[str, str]
    line_no: int


@dataclass(frozen=True)
class Alert:
    severity: str
    rule: str
    src_ip: str
    summary: str
    evidence: str
    first_seen: str | None
    last_seen: str | None
    count: int


def load_indicators(path: Path) -> set[str]:
    if not path.exists():
        return set()

    indicators: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#"):
            indicators.add(line.lower())
    return indicators


def parse_timestamp(line: str) -> datetime | None:
    for pattern, fmt in (
        (r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\b", WINDOWS_EVENT_TIME),
        (r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\b", ISO_EVENT_TIME),
    ):
        match = re.search(pattern, line)
        if match:
            return datetime.strptime(match.group(0), fmt)

    apache = re.search(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]", line)
    if apache:
        parsed = datetime.strptime(apache.group(1), APACHE_EVENT_TIME)
        return parsed.replace(tzinfo=None)

    return None


def parse_proxifier_timestamp(month: str, day: str, clock: str) -> datetime | None:
    try:
        return datetime.strptime(f"{datetime.now().year}-{month}-{day} {clock}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def parse_port(value: str | None) -> int | None:
    if not value:
        return None
    try:
        port = int(value)
    except ValueError:
        return None
    return port if 0 < port <= 65535 else None


def normalize_ip(value: str | None) -> str | None:
    if not value:
        return None
    return value if IP_PATTERN.fullmatch(value) else None


def classify_event(message: str, fields: dict[str, str]) -> str:
    if fields.get("log_format") == "proxifier":
        return "proxy_connection"
    lowered = message.lower()
    if any(pattern in lowered for pattern in FAILED_LOGIN_PATTERNS):
        return "failed_login"
    if fields.get("dpt") or fields.get("dst_port") or fields.get("destination_port"):
        return "network_connection"
    if '"' in message and re.search(r"\b(GET|POST|PUT|DELETE|PATCH|HEAD)\b", message):
        return "web_request"
    if "connection" in lowered or "accepted" in lowered or "denied" in lowered:
        return "network_connection"
    return "generic"


def parse_line(line: str, line_no: int) -> Event:
    timestamp = parse_timestamp(line)
    fields = {key.lower(): value for key, value in KV_PATTERN.findall(line)}
    apache_match = APACHE_PATTERN.search(line)
    proxifier_match = PROXIFIER_PATTERN.search(line)

    if proxifier_match:
        groups = proxifier_match.groupdict()
        detail = groups["detail"]
        timestamp = parse_proxifier_timestamp(groups["month"], groups["day"], groups["clock"])
        fields.update(
            {
                "log_format": "proxifier",
                "app": groups["app"].strip(),
                "dst_host": groups["target"],
                "dst_port": groups["port"],
                "detail": detail,
            }
        )
        if detail.startswith("open through proxy"):
            fields["action"] = "open"
        elif detail.startswith("close"):
            fields["action"] = "close"
        elif detail.startswith("error"):
            fields["action"] = "error"
        proxy_match = re.search(r"through proxy ([^:\s]+):(\d{1,5})", detail)
        if proxy_match:
            fields["proxy_host"] = proxy_match.group(1)
            fields["proxy_port"] = proxy_match.group(2)
        for byte_match in BYTE_COUNT_PATTERN.finditer(detail):
            fields[f"{byte_match.group('direction').lower()}_bytes"] = byte_match.group("count")

    if apache_match:
        groups = apache_match.groupdict()
        fields.update(
            {
                "method": groups["method"],
                "path": groups["path"],
                "status": groups["status"],
                "size": groups["size"],
            }
        )

    ips = IP_PATTERN.findall(line)
    src_ip = (
        normalize_ip(fields.get("src"))
        or normalize_ip(fields.get("src_ip"))
        or (apache_match.group("src_ip") if apache_match else None)
        or (ips[0] if ips else None)
    )
    dst_ip = (
        normalize_ip(fields.get("dst"))
        or normalize_ip(fields.get("dst_ip"))
        or normalize_ip(fields.get("destination"))
        or normalize_ip(fields.get("dst_host"))
        or (ips[1] if len(ips) > 1 else None)
    )
    dst_port = (
        parse_port(fields.get("dpt"))
        or parse_port(fields.get("dst_port"))
        or parse_port(fields.get("destination_port"))
    )

    if dst_port is None:
        port_match = re.search(r"\b(?:port|dpt|dst_port)\s*[=:]?\s*(\d{1,5})\b", line, re.IGNORECASE)
        if port_match:
            dst_port = parse_port(port_match.group(1))

    return Event(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        event_type=classify_event(line, fields),
        message=line.strip(),
        fields=fields,
        line_no=line_no,
    )


def parse_log_lines(lines: Iterable[str]) -> list[Event]:
    events = []
    for line_no, line in enumerate(lines, start=1):
        cleaned = line.strip()
        if cleaned:
            events.append(parse_line(cleaned, line_no))
    return events


def parse_log_file(path: Path) -> list[Event]:
    return parse_log_lines(path.read_text(encoding="utf-8", errors="replace").splitlines())


def format_time(value: datetime | None) -> str | None:
    return value.isoformat(sep=" ", timespec="seconds") if value else None


def time_bounds(events: Iterable[Event]) -> tuple[str | None, str | None]:
    times = [event.timestamp for event in events if event.timestamp]
    if not times:
        return None, None
    return format_time(min(times)), format_time(max(times))


def source_label(src_ip: str | None) -> str:
    return src_ip or "unknown"


def event_actor(event: Event) -> str:
    app = event.fields.get("app")
    host = event.fields.get("dst_host")
    if app and host:
        return f"{app} -> {host}"
    return source_label(event.src_ip)


def field_int(event: Event, name: str) -> int | None:
    try:
        return int(event.fields[name])
    except (KeyError, ValueError):
        return None


def detect_failed_logins(events: list[Event], threshold: int = 5, window_minutes: int = 10) -> list[Alert]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.event_type == "failed_login":
            grouped[source_label(event.src_ip)].append(event)

    alerts: list[Alert] = []
    window = timedelta(minutes=window_minutes)
    for src_ip, items in grouped.items():
        dated = sorted((item for item in items if item.timestamp), key=lambda item: item.timestamp or datetime.min)
        if dated:
            start = 0
            for end, event in enumerate(dated):
                while dated[start].timestamp and event.timestamp and event.timestamp - dated[start].timestamp > window:
                    start += 1
                count = end - start + 1
                if count >= threshold:
                    first_seen, last_seen = time_bounds(dated[start : end + 1])
                    alerts.append(
                        Alert(
                            severity="high",
                            rule="Repeated failed login attempts",
                            src_ip=src_ip,
                            summary=f"{count} failed logins within {window_minutes} minutes.",
                            evidence=f"Lines {dated[start].line_no}-{event.line_no}",
                            first_seen=first_seen,
                            last_seen=last_seen,
                            count=count,
                        )
                    )
                    break
        elif len(items) >= threshold:
            alerts.append(
                Alert(
                    severity="medium",
                    rule="Repeated failed login attempts",
                    src_ip=src_ip,
                    summary=f"{len(items)} failed logins without timestamps.",
                    evidence=f"Lines {items[0].line_no}-{items[-1].line_no}",
                    first_seen=None,
                    last_seen=None,
                    count=len(items),
                )
            )
    return alerts


def detect_port_scans(events: list[Event], port_threshold: int = 8, window_minutes: int = 5) -> list[Alert]:
    grouped: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in events:
        if event.src_ip and event.dst_port:
            grouped[(event.src_ip, event.dst_ip or "unknown target")].append(event)

    alerts: list[Alert] = []
    window = timedelta(minutes=window_minutes)
    for (src_ip, dst_ip), items in grouped.items():
        dated = sorted((item for item in items if item.timestamp), key=lambda item: item.timestamp or datetime.min)
        if dated:
            for index, event in enumerate(dated):
                window_items = [
                    item
                    for item in dated[index:]
                    if item.timestamp and event.timestamp and item.timestamp - event.timestamp <= window
                ]
                unique_ports = {item.dst_port for item in window_items if item.dst_port}
                if len(unique_ports) >= port_threshold:
                    first_seen, last_seen = time_bounds(window_items)
                    alerts.append(
                        Alert(
                            severity="critical",
                            rule="Possible port scan",
                            src_ip=src_ip,
                            summary=f"{len(unique_ports)} destination ports touched on {dst_ip}.",
                            evidence="Ports: " + ", ".join(str(port) for port in sorted(unique_ports)[:20]),
                            first_seen=first_seen,
                            last_seen=last_seen,
                            count=len(unique_ports),
                        )
                    )
                    break
        else:
            unique_ports = {item.dst_port for item in items if item.dst_port}
            if len(unique_ports) >= port_threshold:
                alerts.append(
                    Alert(
                        severity="high",
                        rule="Possible port scan",
                        src_ip=src_ip,
                        summary=f"{len(unique_ports)} destination ports touched on {dst_ip}.",
                        evidence="Ports: " + ", ".join(str(port) for port in sorted(unique_ports)[:20]),
                        first_seen=None,
                        last_seen=None,
                        count=len(unique_ports),
                    )
                )
    return alerts


def detect_web_attacks(events: list[Event]) -> list[Alert]:
    alerts: list[Alert] = []
    for event in events:
        if event.event_type != "web_request":
            continue
        target = event.fields.get("path", event.message)
        for name, pattern in WEB_ATTACK_PATTERNS.items():
            if pattern.search(target):
                alerts.append(
                    Alert(
                        severity="high",
                        rule=name,
                        src_ip=source_label(event.src_ip),
                        summary=f"Suspicious web request matched {name.lower()}.",
                        evidence=f"Line {event.line_no}: {target[:160]}",
                        first_seen=format_time(event.timestamp),
                        last_seen=format_time(event.timestamp),
                        count=1,
                    )
                )
                break
    return alerts


def detect_traffic_spikes(events: list[Event], threshold: int = 10, window_minutes: int = 1) -> list[Alert]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.src_ip:
            grouped[event.src_ip].append(event)

    alerts: list[Alert] = []
    window = timedelta(minutes=window_minutes)
    for src_ip, items in grouped.items():
        dated = sorted((item for item in items if item.timestamp), key=lambda item: item.timestamp or datetime.min)
        if not dated:
            if len(items) >= threshold:
                alerts.append(
                    Alert(
                        severity="medium",
                        rule="Traffic spike",
                        src_ip=src_ip,
                        summary=f"{len(items)} events from one source.",
                        evidence=f"Lines {items[0].line_no}-{items[-1].line_no}",
                        first_seen=None,
                        last_seen=None,
                        count=len(items),
                    )
                )
            continue

        start = 0
        for end, event in enumerate(dated):
            while dated[start].timestamp and event.timestamp and event.timestamp - dated[start].timestamp > window:
                start += 1
            count = end - start + 1
            if count >= threshold:
                first_seen, last_seen = time_bounds(dated[start : end + 1])
                alerts.append(
                    Alert(
                        severity="medium",
                        rule="Traffic spike",
                        src_ip=src_ip,
                        summary=f"{count} events within {window_minutes} minute.",
                        evidence=f"Lines {dated[start].line_no}-{event.line_no}",
                        first_seen=first_seen,
                        last_seen=last_seen,
                        count=count,
                    )
                )
                break
    return alerts


def detect_blocklisted_indicators(events: list[Event], indicators: set[str]) -> list[Alert]:
    if not indicators:
        return []

    grouped: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in events:
        candidates = {value.lower() for value in (event.src_ip, event.dst_ip) if value}
        candidates.update(match.lower() for match in re.findall(r"\b[a-z0-9.-]+\.[a-z]{2,}\b", event.message, re.IGNORECASE))
        matched = candidates & indicators
        for indicator in matched:
            grouped[(indicator, source_label(event.src_ip))].append(event)

    alerts: list[Alert] = []
    for (indicator, src_ip), items in grouped.items():
        first_seen, last_seen = time_bounds(items)
        line_numbers = [item.line_no for item in items]
        if len(line_numbers) == 1:
            evidence = f"Line {line_numbers[0]} references {indicator}"
        else:
            evidence = f"Lines {line_numbers[0]}-{line_numbers[-1]} reference {indicator}"
        alerts.append(
            Alert(
                severity="critical",
                rule="Known suspicious indicator",
                src_ip=src_ip,
                summary=f"{len(items)} events reference blocklisted indicator {indicator}.",
                evidence=evidence,
                first_seen=first_seen,
                last_seen=last_seen,
                count=len(items),
            )
        )
    return alerts


def detect_proxy_error_bursts(events: list[Event], threshold: int = 5, window_minutes: int = 15) -> list[Alert]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.fields.get("log_format") == "proxifier" and event.fields.get("action") == "error":
            grouped[event.fields.get("app", "unknown app")].append(event)

    alerts: list[Alert] = []
    window = timedelta(minutes=window_minutes)
    for app, items in grouped.items():
        dated = sorted((item for item in items if item.timestamp), key=lambda item: item.timestamp or datetime.min)
        if not dated and len(items) >= threshold:
            alerts.append(
                Alert(
                    severity="high",
                    rule="Proxy error burst",
                    src_ip=app,
                    summary=f"{len(items)} proxy errors from {app}.",
                    evidence=f"Lines {items[0].line_no}-{items[-1].line_no}",
                    first_seen=None,
                    last_seen=None,
                    count=len(items),
                )
            )
            continue

        start = 0
        for end, event in enumerate(dated):
            while dated[start].timestamp and event.timestamp and event.timestamp - dated[start].timestamp > window:
                start += 1
            count = end - start + 1
            if count >= threshold:
                window_items = dated[start : end + 1]
                hosts = sorted({item.fields.get("dst_host", "unknown") for item in window_items})
                first_seen, last_seen = time_bounds(window_items)
                alerts.append(
                    Alert(
                        severity="high",
                        rule="Proxy error burst",
                        src_ip=app,
                        summary=f"{count} proxy errors from {app} within {window_minutes} minutes.",
                        evidence="Hosts: " + ", ".join(hosts[:8]),
                        first_seen=first_seen,
                        last_seen=last_seen,
                        count=count,
                    )
                )
                break
    return alerts


def detect_proxy_connection_spikes(events: list[Event], threshold: int = 30, window_minutes: int = 1) -> list[Alert]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.fields.get("log_format") == "proxifier":
            grouped[event.fields.get("app", "unknown app")].append(event)

    alerts: list[Alert] = []
    window = timedelta(minutes=window_minutes)
    for app, items in grouped.items():
        dated = sorted((item for item in items if item.timestamp), key=lambda item: item.timestamp or datetime.min)
        start = 0
        for end, event in enumerate(dated):
            while dated[start].timestamp and event.timestamp and event.timestamp - dated[start].timestamp > window:
                start += 1
            count = end - start + 1
            if count >= threshold:
                window_items = dated[start : end + 1]
                hosts = sorted({item.fields.get("dst_host", "unknown") for item in window_items})
                first_seen, last_seen = time_bounds(window_items)
                alerts.append(
                    Alert(
                        severity="medium",
                        rule="Proxy connection spike",
                        src_ip=app,
                        summary=f"{count} Proxifier events from {app} within {window_minutes} minute.",
                        evidence="Hosts: " + ", ".join(hosts[:8]),
                        first_seen=first_seen,
                        last_seen=last_seen,
                        count=count,
                    )
                )
                break
    return alerts


def detect_zero_byte_proxy_closes(events: list[Event], threshold: int = 5, window_minutes: int = 10) -> list[Alert]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.fields.get("log_format") != "proxifier" or event.fields.get("action") != "close":
            continue
        if field_int(event, "sent_bytes") == 0 and field_int(event, "received_bytes") == 0:
            grouped[event.fields.get("app", "unknown app")].append(event)

    alerts: list[Alert] = []
    window = timedelta(minutes=window_minutes)
    for app, items in grouped.items():
        dated = sorted((item for item in items if item.timestamp), key=lambda item: item.timestamp or datetime.min)
        start = 0
        for end, event in enumerate(dated):
            while dated[start].timestamp and event.timestamp and event.timestamp - dated[start].timestamp > window:
                start += 1
            count = end - start + 1
            if count >= threshold:
                window_items = dated[start : end + 1]
                hosts = sorted({item.fields.get("dst_host", "unknown") for item in window_items})
                first_seen, last_seen = time_bounds(window_items)
                alerts.append(
                    Alert(
                        severity="medium",
                        rule="Repeated zero-byte proxy closes",
                        src_ip=app,
                        summary=f"{count} zero-byte proxy closes from {app} within {window_minutes} minutes.",
                        evidence="Hosts: " + ", ".join(hosts[:8]),
                        first_seen=first_seen,
                        last_seen=last_seen,
                        count=count,
                    )
                )
                break
    return alerts


def detect_local_service_proxying(events: list[Event]) -> list[Alert]:
    alerts: list[Alert] = []
    for event in events:
        if event.fields.get("log_format") != "proxifier":
            continue
        if event.fields.get("dst_host") not in {"127.0.0.1", "localhost"}:
            continue
        alerts.append(
            Alert(
                severity="medium",
                rule="Local service routed through proxy",
                src_ip=event.fields.get("app", event_actor(event)),
                summary="A local service connection appeared in the Proxifier log.",
                evidence=f"Line {event.line_no}: {event.message[:160]}",
                first_seen=format_time(event.timestamp),
                last_seen=format_time(event.timestamp),
                count=1,
            )
        )
    return alerts


def severity_counts(alerts: list[Alert]) -> dict[str, int]:
    counts = Counter(alert.severity for alert in alerts)
    return {level: counts.get(level, 0) for level in ("critical", "high", "medium", "low")}


def analyze_events(events: list[Event], indicators: set[str] | None = None) -> dict:
    indicators = indicators or set()
    alerts = []
    alerts.extend(detect_failed_logins(events))
    alerts.extend(detect_port_scans(events))
    alerts.extend(detect_web_attacks(events))
    alerts.extend(detect_traffic_spikes(events))
    alerts.extend(detect_blocklisted_indicators(events, indicators))
    alerts.extend(detect_proxy_error_bursts(events))
    alerts.extend(detect_proxy_connection_spikes(events))
    alerts.extend(detect_zero_byte_proxy_closes(events))
    alerts.extend(detect_local_service_proxying(events))

    alerts.sort(key=lambda alert: ("critical", "high", "medium", "low").index(alert.severity))
    event_type_counts = Counter(event.event_type for event in events)
    src_counts = Counter(event.src_ip for event in events if event.src_ip)
    first_seen, last_seen = time_bounds(events)

    return {
        "summary": {
            "events_analyzed": len(events),
            "alerts": len(alerts),
            "severity_counts": severity_counts(alerts),
            "event_type_counts": dict(event_type_counts),
            "top_sources": src_counts.most_common(8),
            "first_seen": first_seen,
            "last_seen": last_seen,
        },
        "alerts": [asdict(alert) for alert in alerts],
        "events": [
            {
                **asdict(event),
                "timestamp": format_time(event.timestamp),
            }
            for event in events[:300]
        ],
    }


def analyze_file(log_path: Path, indicator_path: Path | None = None) -> dict:
    events = parse_log_file(log_path)
    indicators = load_indicators(indicator_path) if indicator_path else set()
    return analyze_events(events, indicators)


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze a log file with the basic IDS engine.")
    parser.add_argument("log_file", type=Path, help="Path to the log file to analyze.")
    parser.add_argument(
        "--indicators",
        type=Path,
        default=Path("data/blocklist.txt"),
        help="Path to a blocklist indicator file.",
    )
    parser.add_argument("--json", action="store_true", help="Print full JSON output.")
    args = parser.parse_args()

    result = analyze_file(args.log_file, args.indicators)
    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    summary = result["summary"]
    print(f"Events analyzed: {summary['events_analyzed']}")
    print(f"Alerts raised: {summary['alerts']}")
    print("Severity:", summary["severity_counts"])
    print()
    for alert in result["alerts"]:
        print(f"[{alert['severity'].upper()}] {alert['rule']} - {alert['src_ip']}")
        print(f"  {alert['summary']}")
        print(f"  Evidence: {alert['evidence']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
