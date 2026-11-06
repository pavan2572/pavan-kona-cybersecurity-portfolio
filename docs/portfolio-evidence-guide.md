# Portfolio Evidence & Quality Standard

A professional security portfolio must be reproducible and honest. Use this standard for every project.

## Evidence categories

1. **Source artifact** — scripts, configurations, queries, test cases and documentation committed to this repository.
2. **Synthetic demonstration** — generated fixtures used to prove parser logic or demonstrate detections. Label every such item.
3. **Local execution evidence** — original output from a lab run, with date, tool version, scope and target context.
4. **Finding evidence** — sanitized request/response, scanner output or log event supporting a specific observation.
5. **Retest evidence** — before/after proof that a remediation changed the behavior.

Do not present categories 1 or 2 as categories 3–5.

## Redaction checklist

- Remove passwords, API keys, cookies, bearer tokens, session IDs and private keys.
- Remove real customer data, email addresses, phone numbers and personal identifiers.
- Avoid publishing public target IPs or employer network details unless there is explicit written approval.
- Keep a copy of the original evidence privately; publish only a sanitized copy.
- Record the lab scope and authorization.

## Report structure

Every assessment should state objective, scope, exclusions, environment, date, methodology, findings, evidence, impact, severity rationale, remediation, limitations and retest status.

## Completion gate

A project may be labelled **Completed** only after its documented steps have been run in the stated environment, the test suite passes, and the report contains real evidence collected by the author. Until then use **Reproducible lab package — local execution pending**.

## Suggested screenshots

- API Security: sanitized Burp request/response and the auditor's console output.
- Vulnerability Management: Docker target running, Nmap command and parsed inventory, verified findings and retest.
- Threat Intelligence: KEV catalog collection timestamp, IOC triage output, Splunk search results over the supplied synthetic events.

The synthetic fixtures in this repository are for functional demonstrations only. They do not represent genuine malicious infrastructure or a real incident.
