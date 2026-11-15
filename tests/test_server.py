import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from pulsewatch.server import make_handler
from pulsewatch.store import Store


class IdleWorker:
    def __init__(self):
        self.lock = threading.Lock()
        self.pending = set()

    def enqueue(self, site_id, url):
        with self.lock:
            self.pending.add(site_id)
        return True


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store = Store(f"{self.temp_dir.name}/pulsewatch.sqlite3")
        self.worker = IdleWorker()
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0), make_handler(self.store, self.worker, 0)
        )
        self.port = self.server.server_port
        self.server.RequestHandlerClass = make_handler(
            self.store, self.worker, self.port
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.port}"
        self.origin = self.base

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp_dir.cleanup()

    def request(self, path, method="GET", body=None, headers=None):
        payload = None if body is None else json.dumps(body).encode()
        request = Request(
            self.base + path,
            data=payload,
            method=method,
            headers=headers or {},
        )
        return urlopen(request, timeout=3)

    def test_dashboard_and_security_headers_are_served(self):
        response = self.request("/")
        self.assertEqual(response.status, 200)
        self.assertIn(b"Your websites", response.read())
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])

    def test_site_lifecycle_is_persisted_and_private_targets_are_rejected(self):
        with self.assertRaises(HTTPError) as error:
            self.request(
                "/api/sites",
                "POST",
                {"url": "http://127.0.0.1/"},
                {"Origin": self.origin},
            )
        self.assertEqual(error.exception.code, 400)

        response = self.request(
            "/api/sites",
            "POST",
            {"url": "https://93.184.216.34/"},
            {"Origin": self.origin},
        )
        self.assertEqual(response.status, 201)
        site = json.loads(response.read())
        self.assertEqual(site["url"], "https://93.184.216.34/")
        self.assertIsNone(site.get("last_check"))

        listing = json.loads(self.request("/api/sites").read())
        self.assertEqual([item["id"] for item in listing], [site["id"]])

        response = self.request(
            f"/api/sites/{site['id']}",
            "PATCH",
            {"paused": True},
            {"Origin": self.origin},
        )
        self.assertEqual(json.loads(response.read()), {"paused": True})

        response = self.request(
            f"/api/sites/{site['id']}",
            "DELETE",
            headers={"Origin": self.origin},
        )
        self.assertEqual(json.loads(response.read()), {"deleted": True})
        self.assertEqual(json.loads(self.request("/api/sites").read()), [])


if __name__ == "__main__":
    unittest.main()
