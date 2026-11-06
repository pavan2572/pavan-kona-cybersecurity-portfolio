# Pavan Kona | Cybersecurity Portfolio

**API Security · Vulnerability Management · Threat Intelligence**

A practical, reproducible cybersecurity portfolio. Each project contains source code, synthetic test data, documented methodology, and instructions to run the lab locally.

> **Evidence and scope:** The API project includes a self-contained demonstration lab and test suite. The crAPI assessment is documented as prior hands-on work reported by the author; original screenshots and exact endpoint evidence are still to be added. The Vulnerability Management and Threat Intelligence projects are reproducible portfolio labs using deliberately synthetic fixtures. They demonstrate workflow and tooling, not production client engagements or real-world incidents.

## Featured projects

| Project | What is included | Evidence type |
|---|---|---|
| [API Security Assessment](projects/api-security/) | Local vulnerable-versus-remediated API, response minimization tests, crAPI assessment methodology and Burp Suite exercise | Reproducible local lab + automated tests |
| [Vulnerability Management](projects/vulnerability-management/) | Nmap/Nessus XML parsers, asset context, KEV override input, risk prioritization, CSV/Markdown reporting | Synthetic scan fixtures + test suite |
| [Threat Intelligence](projects/threat-intelligence/) | IOC validation and normalization, confidence/freshness scoring, ATT&CK context, Splunk lookup export and SPL detections | Synthetic IOC/event fixtures + test suite |

## Run the labs

Requirements: Python 3.10 or newer. The projects use the Python standard library; no third-party packages are required.

```bash
# Run all automated checks
python -m unittest discover -s projects -p 'test_*.py' -v

# API security demonstration (terminal 1)
python projects/api-security/lab/server.py
# Terminal 2
python projects/api-security/lab/demo_client.py

# Vulnerability management report
python projects/vulnerability-management/src/vulntrack.py \
  --nessus projects/vulnerability-management/data/sample_nessus.xml \
  --nmap projects/vulnerability-management/data/sample_nmap.xml \
  --assets projects/vulnerability-management/data/assets.csv \
  --kev projects/vulnerability-management/data/kev_training_fixture.csv \
  --out projects/vulnerability-management/reports/generated

# Threat intelligence enrichment report
python projects/threat-intelligence/src/threatintel.py \
  --iocs projects/threat-intelligence/data/sample_iocs.csv \
  --events projects/threat-intelligence/data/sample_events.jsonl \
  --as-of 2026-11-06 \
  --out projects/threat-intelligence/reports/generated
```

See each project README for methodology, output interpretation, limitations, and safe-use boundaries.

## Technical toolkit

Burp Suite · Nmap · Nessus · Splunk · Wireshark · Kali Linux · Docker · OWASP crAPI · DVWA · Python · SQL

## About

Computer Science graduate with a Cybersecurity specialization (2025). Current learning focus: application/API security, vulnerability assessment, security operations, and threat intelligence.

## Portfolio website

The static portfolio site is [`index.html`](index.html). GitHub Pages workflow configuration is included in `.github/workflows/pages.yml`.

## Contact

- GitHub: [@pavan2572](https://github.com/pavan2572)
- LinkedIn: add professional profile URL before public release
- Email: add a professional contact address only if you choose to publish it

## Responsible disclosure and safe use

All examples are intentionally local and use synthetic data. Only test systems you own or have explicit written authorization to assess. Do not upload customer information, credentials, access tokens, private indicators, or confidential employer material.

---

*Maintained as a learning portfolio. Status labels distinguish completed, reproducible lab work from prior self-reported activity and future work.*
