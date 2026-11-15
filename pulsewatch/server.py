from __future__ import annotations

import json
import logging
import os
import queue
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .monitor import details_json, perform_check, resolve_public_address, validate_url
from .store import Store

logger = logging.getLogger("pulsewatch")
ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = ROOT / "static"
CHECK_INTERVAL_SECONDS = max(300, int(os.environ.get("PULSEWATCH_CHECK_INTERVAL", "300")))
DATABASE_PATH = Path(
    os.environ.get("PULSEWATCH_DB_PATH", str(ROOT / "data" / "pulsewatch.sqlite3"))
)
QUEUE_CAPACITY = 100
MANUAL_CHECK_COOLDOWN_SECONDS = 30


class MonitorWorker:
    def __init__(self, store: Store):
        self.store = store
        self.jobs: queue.Queue[tuple[str, str]] = queue.Queue(maxsize=QUEUE_CAPACITY)
        self.pending: set[str] = set()
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.threads = [
            threading.Thread(target=self._scheduler, name="pulsewatch-scheduler", daemon=True),
            threading.Thread(target=self._worker, name="pulsewatch-worker-1", daemon=True),
            threading.Thread(target=self._worker, name="pulsewatch-worker-2", daemon=True),
        ]

    def start(self) -> None:
        for thread in self.threads:
            thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        for thread in self.threads:
            thread.join(timeout=2)

    def enqueue(self, site_id: str, url: str) -> bool:
        with self.lock:
            if site_id in self.pending:
                return False
            self.pending.add(site_id)
            try:
                self.jobs.put_nowait((site_id, url))
            except queue.Full:
                self.pending.remove(site_id)
                return False
        return True

    def _scheduler(self) -> None:
        while not self.stop_event.is_set():
            for site in self.store.due_sites(CHECK_INTERVAL_SECONDS):
                self.enqueue(site["id"], site["url"])
            self.stop_event.wait(5)

    def _worker(self) -> None:
        while not self.stop_event.is_set():
            try:
                site_id, url = self.jobs.get(timeout=1)
            except queue.Empty:
                continue
            try:
                site = self.store.get_site(site_id)
                if site is None or site["paused"]:
                    continue
                result = perform_check(url)
                self.store.record_check(site_id, result, details_json(result))
            except Exception:
                logger.exception("Could not save monitoring result for site %s", site_id)
            finally:
                with self.lock:
                    self.pending.discard(site_id)
                self.jobs.task_done()


def _safe_host(value: str, port: int) -> bool:
    return value in {
        f"127.0.0.1:{port}",
        f"localhost:{port}",
        f"[::1]:{port}",
    }


def make_handler(store: Store, worker: MonitorWorker, port: int):
    class Handler(BaseHTTPRequestHandler):
        server_version = "PulseWatch/0.1"
        sys_version = ""

        def _headers(self) -> None:
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                "connect-src 'self'; img-src 'self' data:; object-src 'none'; "
                "base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
            )
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")

        def _send_json(self, status: int, value: dict | list) -> None:
            payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self._headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _send_file(self, path: Path, content_type: str) -> None:
            try:
                payload = path.read_bytes()
            except OSError:
                self._send_json(404, {"error": "Not found."})
                return
            self.send_response(200)
            self._headers()
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _request_origin_allowed(self) -> bool:
            host = self.headers.get("Host", "")
            origin = self.headers.get("Origin")
            if not _safe_host(host, port):
                return False
            return origin is None or origin in {
                f"http://127.0.0.1:{port}",
                f"http://localhost:{port}",
                f"http://[::1]:{port}",
            }

        def _body(self) -> dict:
            raw_length = self.headers.get("Content-Length", "0")
            if not raw_length.isdigit() or int(raw_length) > 4096:
                raise ValueError("Request body is too large or invalid.")
            raw = self.rfile.read(int(raw_length))
            try:
                value = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise ValueError("Request body must be valid JSON.") from exc
            if not isinstance(value, dict):
                raise ValueError("Request body must be a JSON object.")
            return value

        def _parts(self) -> list[str]:
            return [unquote(part) for part in urlsplit(self.path).path.split("/") if part]

        def do_GET(self) -> None:
            if not _safe_host(self.headers.get("Host", ""), port):
                self._send_json(400, {"error": "Invalid Host header."})
                return
            parts = self._parts()
            if self.path.split("?", 1)[0] == "/":
                self._send_file(STATIC_DIR / "index.html", "text/html; charset=utf-8")
            elif self.path.split("?", 1)[0] == "/app.js":
                self._send_file(STATIC_DIR / "app.js", "text/javascript; charset=utf-8")
            elif self.path.split("?", 1)[0] == "/styles.css":
                self._send_file(STATIC_DIR / "styles.css", "text/css; charset=utf-8")
            elif parts == ["api", "sites"]:
                self._send_json(200, store.list_sites())
            elif len(parts) == 4 and parts[:2] == ["api", "sites"] and parts[3] == "checks":
                site_id = parts[2]
                if store.get_site(site_id) is None:
                    self._send_json(404, {"error": "Website not found."})
                    return
                self._send_json(200, store.list_checks(site_id))
            else:
                self._send_json(404, {"error": "Not found."})

        def do_POST(self) -> None:
            if not self._request_origin_allowed():
                self._send_json(403, {"error": "Request origin is not allowed."})
                return
            parts = self._parts()
            try:
                body = self._body()
                if parts == ["api", "sites"]:
                    canonical, _, port, host = validate_url(body.get("url"))
                    resolve_public_address(host, port)
                    site = store.create_site(canonical)
                    worker.enqueue(site["id"], site["url"])
                    self._send_json(201, site)
                    return
                if len(parts) == 4 and parts[:2] == ["api", "sites"] and parts[3] == "check":
                    site = store.get_site(parts[2])
                    if site is None:
                        self._send_json(404, {"error": "Website not found."})
                        return
                    latest = store.latest_check(site["id"])
                    if latest is not None:
                        from datetime import datetime, timezone

                        last_time = datetime.fromisoformat(latest["checked_at"])
                        age = (datetime.now(timezone.utc) - last_time).total_seconds()
                        if age < MANUAL_CHECK_COOLDOWN_SECONDS:
                            self._send_json(429, {"error": "Wait before requesting another check."})
                            return
                    if not worker.enqueue(site["id"], site["url"]):
                        self._send_json(429, {"error": "A check is already queued or the queue is full."})
                        return
                    self._send_json(202, {"queued": True})
                    return
                self._send_json(404, {"error": "Not found."})
            except ValueError as exc:
                self._send_json(400, {"error": str(exc)})
            except OSError:
                self._send_json(503, {"error": "The hostname could not be safely resolved."})
            except sqlite3.IntegrityError:
                self._send_json(409, {"error": "That website is already being monitored."})
            except Exception:
                logger.exception("Request could not be completed")
                self._send_json(500, {"error": "The request could not be completed."})

        def do_PATCH(self) -> None:
            if not self._request_origin_allowed():
                self._send_json(403, {"error": "Request origin is not allowed."})
                return
            parts = self._parts()
            if len(parts) != 3 or parts[:2] != ["api", "sites"]:
                self._send_json(404, {"error": "Not found."})
                return
            try:
                body = self._body()
                paused = body.get("paused")
                if not isinstance(paused, bool):
                    raise ValueError("paused must be true or false.")
                if not store.set_paused(parts[2], paused):
                    self._send_json(404, {"error": "Website not found."})
                    return
                self._send_json(200, {"paused": paused})
            except ValueError as exc:
                self._send_json(400, {"error": str(exc)})

        def do_DELETE(self) -> None:
            if not self._request_origin_allowed():
                self._send_json(403, {"error": "Request origin is not allowed."})
                return
            parts = self._parts()
            if len(parts) != 3 or parts[:2] != ["api", "sites"]:
                self._send_json(404, {"error": "Not found."})
                return
            if not store.delete_site(parts[2]):
                self._send_json(404, {"error": "Website not found."})
                return
            with worker.lock:
                worker.pending.discard(parts[2])
            self._send_json(200, {"deleted": True})

        def log_message(self, format: str, *args) -> None:
            logger.info("%s - %s", self.address_string(), format % args)

    return Handler


def create_server(host: str = "127.0.0.1", port: int = 8000, database_path=None):
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError("PulseWatch local MVP must bind to loopback only.")
    store = Store(database_path or DATABASE_PATH)
    server = ThreadingHTTPServer((host, port), make_handler(store, None, port))
    server.daemon_threads = True
    worker = MonitorWorker(store)
    server.RequestHandlerClass = make_handler(store, worker, server.server_port)
    return server, worker


def serve(host: str = "127.0.0.1", port: int = 8000, database_path=None) -> None:
    server, worker = create_server(host, port, database_path)
    worker.start()
    logger.info("PulseWatch is listening at http://%s:%s", host, server.server_port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down PulseWatch")
    finally:
        server.shutdown()
        server.server_close()
        worker.stop()


if __name__ == "__main__":
    logging.basicConfig(
        level=os.environ.get("PULSEWATCH_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    serve()
