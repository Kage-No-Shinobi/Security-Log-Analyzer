# Security Incident Report

Source: `auth.log`
Parsed records: 8; skipped records: 0

## Failed authentications by IP

| Source IP | Failed attempts |
|---|---:|
| `192.0.2.10` | 5 |
| `198.51.100.7` | 1 |

## Flags

| Severity | Source IP | Observation |
|---|---|---|
| HIGH | `192.0.2.10` | 5 failed authentications (threshold 5) |
| HIGH | `192.0.2.10` | 5+ failures within 5 minutes |
| LOW | `203.0.113.8` | Successful login during configured off-hours (22:00–05:59) |

> These flags are heuristics, not proof of an attack. The sample data is synthetic; review context before escalating.
