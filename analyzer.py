"""Offline security log analyzer for synthetic SSH and Apache access logs."""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import ipaddress
from pathlib import Path
import re

SSH_FAILURE = re.compile(r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<clock>\d\d:\d\d:\d\d).*Failed password.*from (?P<ip>[\dA-Fa-f:.]+)')
SSH_SUCCESS = re.compile(r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<clock>\d\d:\d\d:\d\d).*Accepted password.*from (?P<ip>[\dA-Fa-f:.]+)')
APACHE = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<stamp>[^]]+)\] "(?P<method>\S+) (?P<path>\S+) [^"]+" (?P<status>\d{3})')
PROBE = re.compile(r'/(?:\.env|wp-admin|wp-login\.php|phpmyadmin|\.git)(?:[/?]|$)', re.I)


def parse_line(line: str, year: int = 2026) -> dict | None:
    ssh = SSH_FAILURE.search(line) or SSH_SUCCESS.search(line)
    if ssh:
        try:
            stamp = datetime.strptime(f"{year} {ssh['month']} {ssh['day']} {ssh['clock']}", '%Y %b %d %H:%M:%S')
            ipaddress.ip_address(ssh['ip'])
        except ValueError:
            return None
        return {'time': stamp, 'ip': ssh['ip'], 'kind': 'failure' if 'Failed password' in line else 'success', 'probe': False}
    apache = APACHE.search(line)
    if apache:
        try:
            stamp = datetime.strptime(apache['stamp'], '%d/%b/%Y:%H:%M:%S %z').replace(tzinfo=None)
            ipaddress.ip_address(apache['ip'])
        except ValueError:
            return None
        status = int(apache['status'])
        return {'time': stamp, 'ip': apache['ip'], 'kind': 'failure' if status in (401, 403) else 'access', 'probe': bool(PROBE.search(apache['path']))}
    return None


def analyze(lines: list[str], year: int = 2026, threshold: int = 5, window_minutes: int = 5) -> dict:
    events, skipped = [], 0
    for line in lines:
        event = parse_line(line, year)
        if event: events.append(event)
        else: skipped += 1
    failures = Counter(event['ip'] for event in events if event['kind'] == 'failure')
    by_ip = defaultdict(list)
    for event in events:
        if event['kind'] == 'failure': by_ip[event['ip']].append(event['time'])
    incidents = []
    for ip, count in sorted(failures.items()):
        if count >= threshold:
            incidents.append({'severity': 'HIGH', 'ip': ip, 'reason': f'{count} failed authentications (threshold {threshold})'})
        times = sorted(by_ip[ip])
        left = 0
        for right, time in enumerate(times):
            while time - times[left] > timedelta(minutes=window_minutes): left += 1
            if right - left + 1 >= threshold:
                incidents.append({'severity': 'HIGH', 'ip': ip, 'reason': f'{threshold}+ failures within {window_minutes} minutes'})
                break
    for ip in sorted({e['ip'] for e in events if e['probe']}):
        incidents.append({'severity': 'MODERATE', 'ip': ip, 'reason': 'Request for a commonly targeted sensitive path'})
    for ip in sorted({e['ip'] for e in events if e['kind'] == 'success' and (e['time'].hour < 6 or e['time'].hour >= 22)}):
        incidents.append({'severity': 'LOW', 'ip': ip, 'reason': 'Successful login during configured off-hours (22:00–05:59)'})
    return {'parsed': len(events), 'skipped': skipped, 'failures': dict(sorted(failures.items())), 'incidents': incidents}


def report_markdown(summary: dict, source: str) -> str:
    rows = ['# Security Incident Report', '', f'Source: `{source}`', f"Parsed records: {summary['parsed']}; skipped records: {summary['skipped']}", '', '## Failed authentications by IP', '', '| Source IP | Failed attempts |', '|---|---:|']
    rows += [f'| `{ip}` | {count} |' for ip, count in summary['failures'].items()]
    if not summary['failures']: rows.append('| None | 0 |')
    rows += ['', '## Flags', '', '| Severity | Source IP | Observation |', '|---|---|---|']
    rows += [f"| {i['severity']} | `{i['ip']}` | {i['reason']} |" for i in summary['incidents']]
    if not summary['incidents']: rows.append('| INFO | — | No heuristics triggered |')
    rows += ['', '> These flags are heuristics, not proof of an attack. The sample data is synthetic; review context before escalating.', '']
    return '\n'.join(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('logfile', type=Path)
    parser.add_argument('--out', type=Path, default=Path('incident-report.md'))
    parser.add_argument('--year', type=int, default=2026, help='Year to assume for syslog records without a year')
    parser.add_argument('--threshold', type=int, default=5)
    parser.add_argument('--window', type=int, default=5, help='Rapid-attempt window in minutes')
    args = parser.parse_args()
    if args.threshold < 1 or args.window < 1: parser.error('Threshold and window must be positive')
    try:
        lines = args.logfile.read_text(encoding='utf-8').splitlines()
        summary = analyze(lines, args.year, args.threshold, args.window)
        args.out.write_text(report_markdown(summary, args.logfile.name), encoding='utf-8')
    except (OSError, UnicodeError) as exc:
        parser.error(str(exc))
    print(f"Parsed {summary['parsed']} records; {len(summary['incidents'])} flags. Report: {args.out}")

if __name__ == '__main__': main()
