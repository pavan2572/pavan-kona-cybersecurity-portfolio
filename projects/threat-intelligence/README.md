# Threat Intelligence Lab

**Status:** Planned lab – not yet completed. The workflow below is a project plan, not a claim of completed intelligence collection or detection engineering.

## Goal
Build a documented, repeatable process for collecting public threat intelligence, evaluating its context, and translating useful indicators or behaviors into defensive detection ideas.

## Proposed sources
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [AlienVault Open Threat Exchange](https://otx.alienvault.com/)
- [MalwareBazaar](https://bazaar.abuse.ch/)

Use public sources responsibly, check source reliability and timestamps, and do not download or execute malware on a normal workstation.

## Workflow
1. Select a public advisory or threat report and record its publication date and source.
2. Extract relevant IOCs only where the source provides them; preserve original context.
3. Enrich indicators with passive/public context and record confidence and freshness.
4. Map described adversary behavior to relevant MITRE ATT&CK techniques.
5. Identify defensive data sources and propose a detection hypothesis.
6. Validate using synthetic or sanitized logs in a local Splunk lab.
7. Record limitations, false-positive considerations, and recommended response actions.

## Intelligence record template
| Field | Value |
|---|---|
| Source / report | TODO |
| Published / collected | TODO |
| Indicator or behavior | TODO |
| Context and confidence | TODO |
| ATT&CK mapping | TODO |
| Defensive relevance | TODO |
| Detection hypothesis | TODO |
| Validation result | TODO |

## Evidence to publish after completing the lab
- Source citations and collection timestamps.
- IOC enrichment notes with confidence and expiry considerations.
- ATT&CK mapping rationale.
- Sanitized Splunk query or detection logic.
- Synthetic test events and observed results.

*Do not publish live victim data, private indicators, credentials, or unverified attribution claims.*
