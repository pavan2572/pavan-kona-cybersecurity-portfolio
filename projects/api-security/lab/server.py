#!/usr/bin/env python3
"""Local-only API security lab: vulnerable and remediated profile endpoints."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from urllib.parse import urlsplit

HOST = "127.0.0.1"  # Intentionally never configurable: keep the lab local.
PORT = 8000

# Synthetic-only fixture data. Never place real personal or production data here.
PROFILES = {
    "alice": {
        "id": "demo-1001",
        "display_name": "Alice Example",
        "email": "alice@example.test",
        "department": "Security Learning",
        "internal_notes": "Synthetic internal note - should not be returned to the profile client.",
        "billing_status": "training-only",
        "recovery_email": "recovery-alice@example.test",
    }
}
PUBLIC_PROFILE_FIELDS = ("display_name", "email", "department")


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "PortfolioAPILab/1.0"

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        path = urlsplit(self.path).path
        if path == "/healthz":
            self._send_json(200, {"status": "ok", "scope": "local-demo"})
            return

        if path not in ("/api/v1/profile", "/api/v2/profile"):
            self._send_json(404, {"error": "not_found"})
            return

        # This header selects a synthetic fixture only. It is not authentication.
        demo_user = self.headers.get("X-Demo-User", "")
        profile = PROFILES.get(demo_user)
        if profile is None:
            self._send_json(403, {"error": "unknown_demo_identity"})
            return

        if path == "/api/v1/profile":
            # Intentionally vulnerable: serializes every internal property.
            self._send_json(200, profile)
            return

        # Remediated: explicitly serialize only fields needed by this feature.
        safe_profile = {field: profile[field] for field in PUBLIC_PROFILE_FIELDS}
        self._send_json(200, safe_profile)

    def log_message(self, fmt: str, *args) -> None:
        # Keep terminal output readable while retaining the request method/path.
        print(f"[api-lab] {self.address_string()} - {fmt % args}")


def create_server(port: int = PORT) -> ThreadingHTTPServer:
    """Create the local lab HTTP server; port=0 is useful for automated tests."""
    return ThreadingHTTPServer((HOST, port), DemoHandler)


if __name__ == "__main__":
    server = create_server(PORT)
    print(f"API Security Lab listening only on http://{HOST}:{PORT}")
    print("Use Ctrl+C to stop. Synthetic training data only.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping API Security Lab.")
    finally:
        server.server_close()
