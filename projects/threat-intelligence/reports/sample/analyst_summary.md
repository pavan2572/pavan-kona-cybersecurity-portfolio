# Threat Intelligence Analyst Summary

- Unique normalized indicators: **4**
- Synthetic event matches: **4**

## Confidence bands

| Band | Indicators |
|---|---:|
| High | 3 |
| Medium | 1 |
| Low | 0 |

## Matched events

| Time | Matched indicator | Type | Confidence | Event action |
|---|---|---|---|---|
| 2026-11-06T09:15:00Z | 203.0.113.44 | ipv4 | High | connection_observed |
| 2026-11-06T09:18:00Z | cdn-update.example.test | domain | High | dns_query |
| 2026-11-06T09:25:00Z | https://drop.example.test/login | url | Medium | blocked_by_lab_proxy |
| 2026-11-06T09:30:00Z | ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff | sha256 | High | file_hash_observed |

## Analyst notes

All supplied indicators and events in this run are synthetic training fixtures. The score is based only on analyst-supplied confidence and the age of the last-seen value; it is not a reputation verdict or probability of compromise. Verify provenance, ATT&CK mapping, business context, false positives, and sharing restrictions before operational use.
