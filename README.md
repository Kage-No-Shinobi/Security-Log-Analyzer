# Security Log Analyzer

Offline, educational log parser for **synthetic** Linux-style SSH authentication and Apache access logs. Uses Python standard library only.

## Run

```bash
python3 analyzer.py samples/auth.log --out incident-report.md
python3 analyzer.py samples/access.log --out web-report.md
python3 analyzer.py samples/auth.log --threshold 5 --window 5
python3 -m unittest discover -s tests -v
```

## Detection rules

- Count SSH failed passwords and HTTP 401/403 responses by source IP.
- Flag sources with **5+ failures** overall (configurable).
- Flag **5+ failures within 5 minutes** (configurable sliding window).
- Flag successful SSH logins during **22:00–05:59** local-to-log timestamps as a **low-confidence** observation.
- Flag access to sensitive paths such as `/.env`, `/.git`, and `/wp-admin`.

Outputs a Markdown incident report with count table, severity and reasons. Lines not matching either supported format are counted as skipped, never invented. SSH syslog timestamps lack a year, supplied via `--year` (defaults to 2026); Apache offset is parsed but normalized to naive datetime for the simple demo. **Do not combine logs from different time zones without normalizing them first.** The tool does not execute commands from logs or connect to networks.

These are alert heuristics, not evidence of confirmed compromise. Legitimate mistakes, shared IPs and automated health checks can create false positives. Review context before treating a flagged record as an incident.
