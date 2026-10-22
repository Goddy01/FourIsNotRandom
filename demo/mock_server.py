#!/usr/bin/env python3
"""Local mock targets for fourisnotrandom demos (no exploits).

Serves:
  GET /              -> X-Powered-By: PHP/8.3.35  (vulnerable banner)
  GET /patched       -> X-Powered-By: PHP/8.3.36  (fixed banner)
  GET /help          -> GitLab help HTML with version 19.4.2
  GET /api/v4/version -> JSON {"version":"19.4.2"}

Usage:
  python demo/mock_server.py
  # then in another shell:
  fourisnotrandom php url http://127.0.0.1:8765/
  fourisnotrandom gitlab --url http://127.0.0.1:8765
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer

HOST = "127.0.0.1"
PORT = 8765


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:  # quieter
        print(f"[mock] {self.address_string()} {fmt % args}")

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path in {"/", "/index.php"}:
            body = b"<html><body>demo php app</body></html>"
            self._send(200, body, {"X-Powered-By": "PHP/8.3.35", "Content-Type": "text/html"})
        elif path == "/patched":
            body = b"<html><body>patched php app</body></html>"
            self._send(200, body, {"X-Powered-By": "PHP/8.3.36", "Content-Type": "text/html"})
        elif path == "/help":
            body = (
                b"<html><head><title>Help</title></head><body>"
                b"<h1>GitLab Community Edition</h1>"
                b"<p>GitLab Community Edition 19.4.2</p>"
                b"</body></html>"
            )
            self._send(200, body, {"Content-Type": "text/html"})
        elif path == "/api/v4/version":
            body = b'{"version":"19.4.2","revision":"demo0000"}'
            self._send(200, body, {"Content-Type": "application/json"})
        else:
            self._send(404, b"not found", {"Content-Type": "text/plain"})

    def _send(self, code: int, body: bytes, headers: dict[str, str]) -> None:
        self.send_response(code)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    server = HTTPServer((HOST, PORT), Handler)
    print(f"Mock audit targets at http://{HOST}:{PORT}")
    print("  /              PHP 8.3.35 (vulnerable header)")
    print("  /patched       PHP 8.3.36 (fixed header)")
    print("  /help          GitLab 19.4.2 HTML")
    print("  /api/v4/version  GitLab 19.4.2 JSON")
    print("Ctrl+C to stop.")
    server.serve_forever()


if __name__ == "__main__":
    main()
