# API Security — OWASP crAPI & Response Exposure Auditor

**Project type:** API security assessment workflow + working Python utility  
**Environment:** OWASP crAPI running locally in Docker  
**Primary focus:** Excessive Data Exposure / object-property minimization

## Executive summary

This project documents a repeatable process for inspecting API responses and checking whether an endpoint returns more object properties than its consumer needs. It includes a command-line auditor that compares JSON response fields with an endpoint-specific allowlist, identifies unexpected properties, and flags suspiciously sensitive field names.

The author previously practised API security assessment with OWASP crAPI, Burp Suite and Docker, including work focused on excessive data exposure. This repository does not invent the exact endpoint, request, severity or original screenshot from that earlier exercise. The supplied example response is synthetic and exists only to demonstrate the auditor.

## Deliverables

- Local crAPI setup and safe assessment procedure.
- Python response-field allowlist auditor (standard library only).
- Recursive JSON field-path handling, including arrays.
- Sensitive-field-name detection.
- Unit tests and a synthetic response fixture.
- Finding and retest report structure.

## 1. Lab setup

Use the official OWASP crAPI project. Its setup guide documents the Docker Compose workflow and local application address.

    git clone https://github.com/OWASP/crAPI.git
    cd crAPI/deploy/docker
    docker compose pull
    docker compose up -d

Open the local application at http://localhost:8888. Keep the lab bound to localhost; do not expose it on a public interface. If your downloaded compose version uses an explicit LISTEN_IP setting, retain 127.0.0.1.

Stop the lab when finished:

    docker compose down

Reference: https://github.com/OWASP/crAPI/blob/develop/docs/setup.md

## 2. Assessment methodology

1. Define the local crAPI instance as the only in-scope target.
2. Create test accounts with different ownership or roles using the application's normal workflow.
3. Browse the normal application workflow and capture requests in Burp Proxy.
4. Identify one response object at a time. Record which fields the current screen or operation actually requires.
5. Compare the response with the minimum expected field set. Consider both excess data and authorization: a field can be unnecessary even when the object itself is legitimately accessible.
6. Validate access-control context with a second test account where the lab scenario permits it. Do not infer an authorization bypass just because an extra field exists.
7. Export only sanitized response JSON. Remove cookies, bearer tokens, personal data and identifiers that could identify another person.
8. Run the auditor against the endpoint-specific allowlist.
9. Record impact, severity rationale, remediation and a retest result.

## 3. Run the included auditor

From the repository root:

    python projects/crapi-api-security/scripts/api_response_auditor.py projects/crapi-api-security/examples/response.synthetic.json --allowlist projects/crapi-api-security/examples/allowed-fields.txt --output projects/crapi-api-security/reports/demo-audit.json

The included sample deliberately contains an unapproved email field and a demo access-token field. The expected non-zero exit status means the sample check detected issues; it is not a live crAPI finding.

Run the tests:

    python -m unittest discover -s projects/crapi-api-security/tests -v

## 4. How the auditor works

- Converts nested JSON objects into dot-separated leaf paths.
- Represents array elements with [] so a rule such as orders[].id can match every item.
- Supports exact allowlist entries and shell-style wildcards.
- Flags unexpected paths separately from sensitive-looking field names.
- Writes a machine-readable JSON report and returns a non-zero exit code when issues are present.

The tool is a response-schema review aid, not a substitute for authorization testing, business-logic testing or manual security analysis.

## 5. Finding report

Use the template in reports/finding-template.md. A defensible finding should include:

- Endpoint and HTTP method.
- Test account role and object ownership context.
- Expected minimum response schema.
- Sanitized observed response.
- Exact unexpected property paths.
- Whether sensitive data was actually accessible and to whom.
- Reproduction steps and impact.
- Severity rationale and remediation.
- Retest status, with before/after evidence.

## 6. Remediation guidance

- Return purpose-built response DTOs rather than serializing complete database models.
- Enforce object- and property-level authorization server-side.
- Minimize fields for each role and workflow.
- Add response-schema regression tests.
- Avoid placing security-sensitive decisions in browser-side code.
- Review GraphQL selection sets and nested API objects as well as REST JSON responses.

## 7. Evidence status

| Artifact | Status |
|---|---|
| Auditor implementation and unit tests | Included in repository |
| Synthetic example and expected behavior | Included; demonstration only |
| crAPI installation instructions | Reproducible using official project |
| Earlier personal crAPI practice | Described by author; original evidence not yet committed |
| Current local Burp capture and retest | Must be collected by author |

## References

- OWASP crAPI: https://owasp.org/projects/crapi/
- crAPI setup: https://github.com/OWASP/crAPI/blob/develop/docs/setup.md
- OWASP API Security Top 10: https://owasp.org/API-Security/
- NIST: https://csrc.nist.gov/
