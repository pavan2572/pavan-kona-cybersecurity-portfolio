# Project Catalogue

Explore the three practical project packages. Each has a dedicated portfolio page plus its source code, tests, sample data and technical documentation.

## 01 — API Security: OWASP crAPI & Response Exposure Auditor

**[Open project page](api-security.html)**

- [Technical guide](crapi-api-security/README.md)
- [Python response auditor](crapi-api-security/scripts/api_response_auditor.py)
- [Unit tests](crapi-api-security/tests/test_api_response_auditor.py)
- [Synthetic API response](crapi-api-security/examples/response.synthetic.json)
- [Allowed response fields](crapi-api-security/examples/allowed-fields.txt)
- [Finding report template](crapi-api-security/reports/finding-template.md)

Run the example from the repository root:

    python projects/crapi-api-security/scripts/api_response_auditor.py projects/crapi-api-security/examples/response.synthetic.json --allowlist projects/crapi-api-security/examples/allowed-fields.txt --output projects/crapi-api-security/reports/demo-audit.json

The example deliberately includes unexpected and sensitive-name fields. A non-zero exit status is expected for this synthetic demonstration; it is not a real crAPI finding.

## 02 — Vulnerability Management Pipeline

**[Open project page](vulnerability-management.html)**

- [Technical guide](vulnerability-management/README.md)
- [Local-only Docker target](vulnerability-management/docker-compose.yml)
- [Linux/macOS scan wrapper](vulnerability-management/scripts/scan-local.sh)
- [Windows PowerShell scan wrapper](vulnerability-management/scripts/scan-local.ps1)
- [Nmap XML parser](vulnerability-management/scripts/parse_nmap.py)
- [Risk register utility](vulnerability-management/scripts/risk_register.py)
- [Synthetic Nmap XML](vulnerability-management/data/nmap.synthetic.xml)
- [Synthetic findings CSV](vulnerability-management/data/findings.synthetic.csv)
- [Assessment report template](vulnerability-management/reports/report-template.md)

The vulnerable target is bound to 127.0.0.1:3000. Run the included Nmap wrappers only against the supplied localhost lab.

## 03 — Threat Intelligence & Detection Engineering

**[Open project page](threat-intelligence.html)**

- [Technical guide](threat-intelligence/README.md)
- [IOC triage utility](threat-intelligence/scripts/ioc_triage.py)
- [CISA KEV collector](threat-intelligence/scripts/kev_watch.py)
- [Splunk brute-force search](threat-intelligence/detections/brute-force.spl)
- [Splunk web-egress search](threat-intelligence/detections/web-egress.spl)
- [Synthetic IOC dataset](threat-intelligence/data/iocs.synthetic.csv)
- [Synthetic authentication events](threat-intelligence/data/auth-events.synthetic.csv)
- [Synthetic proxy events](threat-intelligence/data/proxy-events.synthetic.csv)
- [MITRE mapping notes](threat-intelligence/docs/mitre-mapping.md)
- [Analyst report template](threat-intelligence/reports/analyst-report-template.md)

The IOC sample values are reserved documentation/test indicators. The KEV collector fetches the current public catalog when executed.

## Automated checks

    python -m unittest discover -s projects/crapi-api-security/tests -v
    python -m unittest discover -s projects/vulnerability-management/tests -v
    python -m unittest discover -s projects/threat-intelligence/tests -v

GitHub Actions compiles all project scripts and runs the three test suites on pushes to main and pull requests.

## Evidence integrity

Scripts, queries, tests and local lab configurations are delivered here. Sample CSV/JSON/XML records are generated demonstration data. Actual scans, original Burp captures and Splunk screenshots must be collected from the author's authorized local lab before those activities can be claimed as personally executed results.
