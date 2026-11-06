# API Security Assessment Lab

**Focus:** Excessive Data Exposure / Broken Object Property Level Authorization (BOPLA) concepts.

**Deliverable:** A local-only Python API that deliberately returns an over-broad profile in its vulnerable route and an allowlisted response in its remediated route, plus automated tests and a Burp Suite exercise.

## What this demonstrates

An API can expose more object properties than a client feature needs. Hiding fields in a frontend does not protect them: the server must enforce property-level authorization and return only the minimum required fields. This lab compares an intentionally unsafe response with a server-side allowlist.

The lab is an educational demonstration and is not the OWASP crAPI application. The author has previously described hands-on crAPI testing focused on excessive data exposure; original screenshots, endpoint details, and exact evidence from that exercise have not yet been supplied, so they are not fabricated here.

## Run locally

Requirements: Python 3.10+. No external packages.

```bash
python lab/server.py
```

The server binds exclusively to `127.0.0.1:8000`. In a second terminal:

```bash
python lab/demo_client.py
```

Or use curl:

```bash
curl -i -H 'X-Demo-User: alice' http://127.0.0.1:8000/api/v1/profile
curl -i -H 'X-Demo-User: alice' http://127.0.0.1:8000/api/v2/profile
```

The two responses use synthetic records. The vulnerable endpoint deliberately returns internal-only properties. The secure endpoint returns the allowlisted profile fields. `X-Demo-User` is a lab identity selector, not real authentication; do not reuse this pattern in production.

## Automated security tests

```bash
python -m unittest discover -s projects/api-security/lab/tests -p 'test_*.py' -v
```

Tests assert that the vulnerable route includes the deliberately overexposed fixture fields and that the remediated route excludes them. They also check unknown demo identities and a health endpoint.

## Burp Suite exercise

1. Start the lab and configure Burp's browser to use the local proxy.
2. Send a request to `/api/v1/profile` with `X-Demo-User: alice`.
3. Inspect the JSON response. Identify properties not required by the profile view, such as internal notes and billing metadata.
4. Repeat against `/api/v2/profile`.
5. Compare the server responses, not only what the browser renders.
6. Save sanitized request/response evidence and explain the data minimization decision.

## Finding write-up template

| Field | Record |
|---|---|
| Asset / endpoint | Local API demo; `/api/v1/profile` |
| Weakness | Response returns more profile properties than the UI requires |
| Preconditions | Local lab; synthetic `alice` identity selector |
| Evidence | Run the client or curl commands; attach sanitized output |
| Impact | Unnecessary disclosure of internal profile metadata to API clients |
| Root cause | Server response serializes the full internal object |
| Remediation | Use a server-side response schema/allowlist and property-level authorization |
| Retest | `/api/v2/profile` exposes only `display_name`, `email`, and `department` |

## Remediation principles

- Use response DTOs/schemas designed for each API operation.
- Apply property-level authorization on the server for sensitive object properties.
- Avoid serializing database/domain objects directly into API responses.
- Test response schemas and authorization boundaries automatically.
- Treat client-side filtering as presentation logic, not a security boundary.

## References

- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [OWASP API3:2023 – Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
- [OWASP crAPI](https://github.com/OWASP/crAPI)

## Limitations

This lab demonstrates one response-minimization pattern using a single local synthetic object. It does not establish the presence of a vulnerability in crAPI, any employer system, or any external service. It is not a substitute for full authentication, authorization, or API lifecycle testing.
