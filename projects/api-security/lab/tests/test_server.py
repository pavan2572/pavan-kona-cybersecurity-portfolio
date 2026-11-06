import json
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server


class APISecurityLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = server.create_server(0)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)

    def get_json(self, path, identity="alice"):
        headers = {"X-Demo-User": identity} if identity is not None else {}
        request = Request(self.base + path, headers=headers)
        with urlopen(request, timeout=2) as response:
            return response.status, json.loads(response.read().decode())

    def test_vulnerable_route_exposes_internal_properties(self):
        status, payload = self.get_json("/api/v1/profile")
        self.assertEqual(status, 200)
        self.assertIn("internal_notes", payload)
        self.assertIn("billing_status", payload)
        self.assertIn("recovery_email", payload)

    def test_secure_route_returns_only_allowlisted_properties(self):
        status, payload = self.get_json("/api/v2/profile")
        self.assertEqual(status, 200)
        self.assertEqual(set(payload), set(server.PUBLIC_PROFILE_FIELDS))
        self.assertNotIn("internal_notes", payload)
        self.assertNotIn("billing_status", payload)

    def test_unknown_demo_identity_is_denied(self):
        request = Request(self.base + "/api/v2/profile", headers={"X-Demo-User": "unknown"})
        with self.assertRaises(HTTPError) as error:
            urlopen(request, timeout=2)
        self.assertEqual(error.exception.code, 403)

    def test_health_endpoint(self):
        status, payload = self.get_json("/healthz", identity=None)
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")


if __name__ == "__main__":
    unittest.main()
