# Threat Intelligence & Detection Engineering Lab

**Project type:** IOC triage utility + public vulnerability-intelligence collector + Splunk detections  
**Data policy:** Synthetic fixtures only; no live malicious infrastructure is included

## Executive summary

This project demonstrates a small defensive threat-intelligence workflow: validate and classify indicators, collect the current CISA Known Exploited Vulnerabilities (KEV) catalog, map behavior to MITRE ATT&CK and test Splunk searches against controlled sample logs.

It contains two Python command-line utilities with unit tests, sample IOC and event CSV files, two Splunk searches, analyst notes and report structure. The supplied IPs and domains are documentation/test values, not malicious indicators.

## 1. IOC triage

The IOC utility normalizes IP addresses and domains, checks input shape, assigns a confidence band and marks private, loopback, link-local, reserved and documentation-only values so they are not mistaken for routable threat infrastructure.

Run the synthetic example:

    python scripts/ioc_triage.py data/iocs.synthetic.csv --output reports/ioc-triage.synthetic.csv

The script performs local parsing only. It does not send indicators to third-party enrichment services or make a maliciousness verdict. A syntactically valid public IP is only a public candidate, not automatically malicious.

Input columns: indicator,indicator_type,source,first_seen,confidence,context.

## 2. CISA KEV catalog collection

Run the collector when internet access is available:

    python scripts/kev_watch.py --limit 25 --output reports/kev-latest.csv
    python scripts/kev_watch.py --since 2026-01-01 --output reports/kev-since-date.csv
    python scripts/kev_watch.py --vendor "Example Vendor" --output reports/kev-vendor.csv

The collector reads the public CISA JSON catalog, filters records locally and records catalog version and release date in each exported row. It does not assert that a product is present in your environment. Match vendor/product and CVE records against your own asset inventory before treating an item as applicable.

CISA catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

## 3. Splunk detection validation

The demo authentication and proxy CSVs contain generated data. Import them into a lab Splunk instance as CSV and assign the sourcetypes below:

- portfolio:auth
- portfolio:proxy

The searches expect the sample field names. If your Splunk CSV import uses a different index, replace index=main. The searches derive event time from the timestamp field.

### Detection A — repeated authentication failures / password spraying

File: detections/brute-force.spl

The query aggregates failed Windows-style logon events by source IP and 10-minute window, then identifies either repeated failures or many distinct account names. It is a triage signal; tune thresholds for the real environment and correlate with successful logons, known scanners, VPN egress and identity-provider telemetry.

### Detection B — unusual web egress

File: detections/web-egress.spl

The query highlights repeated proxy requests using script-oriented user agents or non-standard destination ports. Such characteristics are not proof of command-and-control. Investigate process identity, destination reputation, request pattern, TLS details and business context.

## 4. MITRE ATT&CK context

- T1110.001 — Password Guessing: repeated authentication failures may be consistent with credential guessing. https://attack.mitre.org/techniques/T1110/001/
- T1071.001 — Web Protocols: adversaries may blend command-and-control communications into ordinary web traffic. https://attack.mitre.org/techniques/T1071/001/

These are behavioral mappings for detection hypotheses, not attribution of the synthetic logs to an adversary.

## 5. Reproduce the project

Run tests:

    python -m unittest discover -s projects/threat-intelligence/tests -v

Run both local analyzers:

    python projects/threat-intelligence/scripts/ioc_triage.py projects/threat-intelligence/data/iocs.synthetic.csv --output projects/threat-intelligence/reports/ioc-triage.synthetic.csv

    python projects/threat-intelligence/scripts/kev_watch.py --limit 10 --output projects/threat-intelligence/reports/kev-latest.csv

The KEV collector requires an internet connection; IOC triage and tests do not.

## 6. Evidence status

| Artifact | Status |
|---|---|
| IOC triage utility and tests | Included |
| CISA KEV collector and filtering tests | Included |
| Splunk SPL detections | Included |
| Synthetic auth/proxy/IOC fixtures | Included; demonstration only |
| Splunk execution screenshots from author's machine | Pending local execution |
| Live intelligence assessment / incident attribution | Not claimed |

## Analyst workflow

1. Record source, collection time, indicator context and confidence.
2. Validate syntax and classify reserved/demo data.
3. Enrich only through approved sources and record each source and timestamp.
4. Assess freshness, infrastructure reuse and false-positive context.
5. Map observed behavior to ATT&CK only when the evidence supports it.
6. Create a detection hypothesis and test it with synthetic or sanitized logs.
7. Document limitations and recommended defensive actions.

## References

- CISA Known Exploited Vulnerabilities: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- MITRE ATT&CK T1110.001: https://attack.mitre.org/techniques/T1110/001/
- MITRE ATT&CK T1071.001: https://attack.mitre.org/techniques/T1071/001/
