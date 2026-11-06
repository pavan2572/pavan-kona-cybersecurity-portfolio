# Pavan Kona | Cybersecurity Portfolio

**Cybersecurity | API Security | Vulnerability Management | Threat Intelligence**

This repository contains reproducible security-lab projects, small defensive tools, detection content, test fixtures, and technical reports. The focus is on explaining the problem, showing the method, and making each artifact repeatable.

## Featured projects

| Project | What is included | Evidence boundary |
|---|---|---|
| [API Security — crAPI & Response Exposure Auditor](projects/crapi-api-security/README.md) | Local crAPI lab guide, JSON response allowlist auditor, tests, sample response and assessment report | The code and synthetic demo are reproducible. The earlier crAPI finding is described as prior hands-on work; original Burp evidence still needs to be added by the author. |
| [Vulnerability Management Pipeline](projects/vulnerability-management/README.md) | Local-only Juice Shop target, Nmap XML parser, risk register, KEV prioritization field, tests and report template | Parser/risk logic and synthetic fixtures are included. A real scan must be run locally and its original output added. |
| [Threat Intelligence & Detection Lab](projects/threat-intelligence/README.md) | IOC triage CLI, CISA KEV feed collector, Splunk detections, MITRE mapping and synthetic log data | Synthetic records are explicitly labelled. The KEV collector fetches current catalog data when run; no live threat attribution is claimed. |

## Technical toolkit

Burp Suite · Nmap · Nessus · Splunk · Wireshark · Kali Linux · Docker · OWASP crAPI · DVWA · Python · SQL

## Repository map

- projects/crapi-api-security/ — API response exposure assessment and auditor.
- projects/vulnerability-management/ — scanner-output processing and prioritization.
- projects/threat-intelligence/ — IOC handling, KEV monitoring and detection engineering.
- docs/ — methodology, evidence standards and portfolio guidance.
- .github/workflows/ — automated Python tests.

## Run the automated checks

Requires Python 3.10 or later. The project scripts use the Python standard library; no pip packages are required.

    python -m unittest discover -s projects/crapi-api-security/tests -v
    python -m unittest discover -s projects/vulnerability-management/tests -v
    python -m unittest discover -s projects/threat-intelligence/tests -v

GitHub Actions runs the same tests on pushes and pull requests.

## About

I am a Computer Science graduate with a Cybersecurity specialization (2025). My practical learning includes API security testing, vulnerability assessment, security monitoring, and threat intelligence. This portfolio is designed to show both the technical work and the reasoning behind it.

## Contact

- GitHub: [pavan2572](https://github.com/pavan2572)
- LinkedIn: add the professional profile URL when ready.
- Email: intentionally omitted until a professional contact address is selected.

## Responsible testing and evidence integrity

All targets in the supplied lab configurations are bound to localhost. Do not scan systems unless you have explicit authorization. Never commit credentials, access tokens, customer information, employer-confidential material, or unredacted personal data.

Synthetic fixtures are labelled as synthetic. A sample report is not a claim that a real scan or investigation was performed. The repository distinguishes reusable tooling, demonstration data, prior hands-on work, and activity that still requires execution on the author's machine.
