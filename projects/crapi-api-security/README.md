# OWASP crAPI — Prior API Security Exercise

**Status:** Prior hands-on activity described by the portfolio author. The author previously reported testing OWASP crAPI with Burp Suite and focusing on Excessive Data Exposure. Original endpoint paths, sanitized request/response captures, exact impact, severity rationale, and retest evidence have not been provided for publication, so no specific finding is asserted here.

## What remains to complete this case study

- Record the crAPI version and the exact local lab setup used.
- Add the endpoint and HTTP method from the original authorized lab exercise.
- Attach sanitized Burp Suite request/response evidence (remove tokens, cookies, IDs, and personal data).
- Explain which properties were unnecessary, who could access them, and how the impact was validated.
- Document the server-side remediation and retest, if performed.

## Reproducible companion lab

A separate local API lab demonstrates excessive response properties and a server-side allowlist with automated tests. It is an educational reproduction of the security principle, **not the OWASP crAPI application and not evidence of a crAPI vulnerability**.

[Open the API Security Assessment Lab →](../api-security/)

[Open the assessment evidence template →](../api-security/reports/assessment-template.md)

## References

- [OWASP crAPI](https://github.com/OWASP/crAPI)
- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [API3:2023 — Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
