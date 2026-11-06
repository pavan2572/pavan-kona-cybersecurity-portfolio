# Project Catalogue

This directory contains three practical cybersecurity project packages. Each project includes its own methodology, runnable tooling or detection content, tests, and clearly labelled sample data.

## 01 — API Security: OWASP crAPI & Response Exposure Auditor

**Focus:** API response minimization and excessive data exposure review.

- [Project guide](crapi-api-security/README.md)
- [Python response auditor](crapi-api-security/scripts/api_response_auditor.py)
- [Unit tests](crapi-api-security/tests/test_api_response_auditor.py)
- [Synthetic API response](crapi-api-security/examples/response.synthetic.json)
- [Allowed response fields](crapi-api-security/examples/allowed-fields.txt)
- [Finding report template](crapi-api-security/reports/finding-template.md)

Run the synthetic demonstration from the repository root:

    python projects/crapi-api-security/scripts/api_response_auditor.py projects/crapi-api-security/examples/response.synthetic.json --allowlist projects/crapi-api-security/examples/allowed-fields.txt --output projects/crapi-api-security/reports/demo-audit.json

The sample intentionally contains unexpected and sensitive-name fields. A non-zero result is expected for this test fixture and does not represent a real crAPI finding.

## 02 — Vulnerability Management Pipeline

**Focus:** local asset discovery, scanner-output parsing, contextual prioritization and retest workflow.

- [Project guide](vulnerability-management/README.md)
- [Local-only Docker target](vulnerability-management/docker-compose.yml)
- [Linux/macOS scan wrapper](vulnerability-management/scripts/scan-local.sh)
- [Windows PowerShell scan wrapper](vulnerability-management/scripts/scan-local.ps1)
- [Nmap XML parser](vulnerability-management/scripts/parse_nmap.py)
- [Risk register utility](vulnerability-management/scripts/risk_register.py)
- [Synthetic Nmap XML](vulnerability-management/data/nmap.synthetic.xml)
- [Synthetic findings CSV](vulnerability-management/data/findings.synthetic.csv)
- [Assessment report template](vulnerability-management/reports/report-template.md)

The lab target binds to 127.0.0.1:3000. Start the app with Docker Compose from the project directory and use the included scan wrappers only against localhost.

## 03 — Threat Intelligence & Detection Engineering

**Focus:** IOC triage, exploited-vulnerability awareness, defensive detection and ATT&CK mapping.

- [Project guide](threat-intelligence/README.md)
- [IOC triage utility](threat-intelligence/scripts/ioc_triage.py)
- [CISA KEV collector](threat-intelligence/scripts/kev_watch.py)
- [Splunk brute-force search](threat-intelligence/detections/brute-force.spl)
- [Splunk web-egress search](threat-intelligence/detections/web-egress.spl)
- [Synthetic IOC dataset](threat-intelligence/data/iocs.synthetic.csv)
- [Synthetic authentication events](threat-intelligence/data/auth-events.synthetic.csv)
- [Synthetic proxy events](threat-intelligence/data/proxy-events.synthetic.csv)
- [MITRE mapping notes](threat-intelligence/docs/mitre-mapping.md)
- [Analyst report template](threat-intelligence/reports/analyst-report-template.md)

The IOC sample values are reserved documentation/test indicators. The KEV collector fetches the current public catalog when run; no live intelligence collection is embedded in the sample data.

## Automated checks

Run all three project test suites from the repository root:

    python -m unittest discover -s projects/crapi-api-security/tests -v
    python -m unittest discover -s projects/vulnerability-management/tests -v
    python -m unittest discover -s projects/threat-intelligence/tests -v

GitHub Actions compiles the project scripts and runs each test suite on pushes to main and pull requests.

## Evidence integrity

The Python tools, tests, queries and local lab configurations are delivered in this repository. Sample CSV/JSON/XML records are generated demonstration data. Actual scans, original Burp captures, and Splunk screenshots must be collected from the author's authorized local lab before claiming those activities as personally executed results.
