#!/usr/bin/env python3
"""Compare over-broad and allowlisted responses from the local API lab."""
import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

BASE = "http://127.0.0.1:8000"


def fetch(path: str) -> dict:
    request = Request(f"{BASE}{path}", headers={"X-Demo-User": "alice"})
    try:
        with urlopen(request, timeout=3) as response:
            return json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError) as exc:
        raise SystemExit(f"Could not reach the local lab. Start server.py first. Details: {exc}") from exc


if __name__ == "__main__":
    vulnerable = fetch("/api/v1/profile")
    secure = fetch("/api/v2/profile")
    print("VULNERABLE ROUTE — returned property names")
    print(", ".join(sorted(vulnerable)))
    print("\nREMEDIATED ROUTE — returned property names")
    print(", ".join(sorted(secure)))
    print("\nProperties removed from the public response")
    print(", ".join(sorted(set(vulnerable) - set(secure))))
    print("\nSecure response")
    print(json.dumps(secure, indent=2))
