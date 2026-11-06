# OWASP crAPI – API Security Assessment

**Status:** Prior hands-on project described by the author; this repository contains the documentation framework. Add original lab evidence and verified technical details before presenting the assessment as fully reproducible.

## Objective
Assess an authorized OWASP crAPI lab environment for API security weaknesses, with a focus on excessive data exposure and whether API responses disclose information beyond what a client requires.

## Environment and tools
- OWASP crAPI in a local/containerized lab
- Burp Suite for request interception and response analysis
- Docker for the lab environment
- Kali Linux / browser-based API interaction

## Assessment workflow
1. Confirm the lab is local and authorized; identify the in-scope API functionality.
2. Capture normal application requests and responses while using the application.
3. Inspect response fields and compare them with the data needed by the requesting feature.
4. Check whether sensitive or unnecessary object properties are returned to an unauthorized or lower-privileged client. Do not assume exposure solely because a field exists; validate access context.
5. Record sanitized requests, responses, expected behavior, observed behavior, and reproducibility steps.
6. Recommend server-side response minimization and object/property-level authorization checks.

## Finding template
| Field | Record |
|---|---|
| Endpoint / method | TODO – add verified endpoint |
| Preconditions / role | TODO – document test account and authorization context |
| Observation | TODO – add exact, sanitized response evidence |
| Security impact | TODO – describe only validated impact |
| Severity | TODO – justify with likelihood and impact |
| Remediation | Return only required fields; enforce object/property-level authorization server-side |
| Retest | TODO – add before/after evidence |

## Evidence to add
- Sanitized Burp request and response (remove cookies, tokens, IDs that identify real users, and secrets).
- Screenshot showing the relevant response fields and test context.
- A concise reproduction sequence.
- Remediation and retest evidence, if performed.

## Defensive recommendations
- Apply data minimization to API response schemas.
- Enforce authorization on the server for every object and sensitive property.
- Avoid relying on client-side hiding of fields.
- Add regression tests for role- and ownership-based access.

## References
- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [OWASP crAPI](https://github.com/OWASP/crAPI)

---

*Use only your own authorized lab. Do not publish real credentials, personal data, or third-party system details.*
