# PulseWatch local MVP

PulseWatch currently provides a local, single-user website-monitoring MVP. It stores checks in SQLite and passively records HTTP status, response time, HTTPS certificate dates/issuer, and the presence of five security headers.

## Run

Requires Python 3.11 or newer; the application uses only the Python standard library.

```powershell
python run.py
```

Open <http://127.0.0.1:8000>. The SQLite database is created at `data/pulsewatch.sqlite3`. Set `PULSEWATCH_DB_PATH` to use another persistent local path. Set `PULSEWATCH_CHECK_INTERVAL` to change the interval; values below five minutes are clamped to five minutes.

## Verify

```powershell
python -m unittest discover -s tests -v
```

## Current scope and limitations

- The service binds to loopback only and has no customer accounts; it is not suitable for public deployment.
- The monitor permits only HTTP/HTTPS on ports 80/443, resolves and validates every destination, connects to a validated IP address, validates each redirect before connecting, and limits redirects, timeouts, and response reads.
- A hostname with any non-public DNS answer is rejected. Monitoring uses one validated public address per request.
- Checks are passive GET requests. A final HTTP status from 200 through 399 is classified as a successful availability check; other statuses and transport errors fail.
- HTTPS uses normal certificate-chain and hostname verification. A TLS handshake that fails (including an expired or mismatched certificate) is recorded as a failed check; certificate dates are available for successful TLS handshakes.
- Security-header results report presence, absence, or not-applicable status; they do not prove a site is secure.
- Checks are retained until their website is deleted. There is no account system, incident workflow, email, billing, public status page, cloud deployment, or backup/restore automation.
- The initial public website and the handoff's reported release checks were not available in the linked repository and have not been independently verified.
