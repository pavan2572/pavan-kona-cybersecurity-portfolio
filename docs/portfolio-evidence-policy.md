# Portfolio Evidence and Quality Policy

This portfolio separates reproducible lab output from claims about prior experience.

## Evidence classes

1. **Automated tests:** Assertions executed against the repository code and fixtures. These establish behavior of the local lab only.
2. **Synthetic fixtures:** Clearly labeled training records using reserved IP ranges, `.test` domains, and synthetic identifiers. These are not real incidents or real scan findings.
3. **Prior self-reported experience:** The author has described prior OWASP crAPI testing. Specific endpoints, request/response captures, impact, and severity are not published until original lab evidence is available.
4. **Operational / production evidence:** Not claimed by this repository.

## Before publishing additional evidence

- Redact credentials, cookies, tokens, personal data, customer names, internal IP plans, hostnames, and employer information.
- Keep the original source and date for public threat intelligence.
- Include scope, authorization, tool version, test date, methodology, limitations, and retest result.
- Never invent a vulnerability, CVE mapping, scan result, IOC reputation, attribution claim, or remediation outcome.
- Mark any synthetic fixture and generated report conspicuously as synthetic.
