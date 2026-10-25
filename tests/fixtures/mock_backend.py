"""A tiny stand-in for a model server, for tests only.

Speaks just enough of two APIs:
  * Ollama:     GET /, GET /api/version, GET /api/tags
  * Anthropic:  POST /v1/messages (JSON or SSE stream), POST /v1/messages/count_tokens

Every reply to /v1/messages is the text MOCK_REPLY. Each request is appended
to --log as one JSON line with the method, path and the *names* of the
headers (never their values).

    python tests/fixtures/mock_backend.py --port 0 --log req.jsonl
prints the bound port on the first stdout line, then serves until killed.
Bind address: $ACR_MOCK_BIND (default 127.0.0.1; CI uses 0.0.0.0 so that a
container can reach it through the host gateway on Linux).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MOCK_REPLY = "MOCK-OK"
MOCK_MODEL = "mock-model:latest"
MOCK_DIGEST = "0123456789abcdef" * 4
MOCK_VERSION = "0.0.0-mock"


def message_body(model: str) -> dict:
    return {
        "id": "msg_mock_1",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": [{"type": "text", "text": MOCK_REPLY}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 10, "output_tokens": 2},
    }


def sse_events(model: str) -> list[tuple[str, dict]]:
    msg = message_body(model)
    start = {**msg, "content": [], "stop_reason": None, "usage": {"input_tokens": 10, "output_tokens": 0}}
    return [
        ("message_start", {"type": "message_start", "message": start}),
        (
            "content_block_start",
            {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
        ),
        ("ping", {"type": "ping"}),
        (
            "content_block_delta",
            {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": MOCK_REPLY}},
        ),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        (
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                "usage": {"output_tokens": 2},
            },
        ),
        ("message_stop", {"type": "message_stop"}),
    ]


class Handler(BaseHTTPRequestHandler):
    server_version = "mock-backend/0"
    log_path: str | None = None

    def log_message(self, *a):  # quiet
        pass

    def _record(self) -> None:
        if self.log_path:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(
                    json.dumps(
                        {
                            "method": self.command,
                            "path": self.path,
                            "header_names": sorted(k.lower() for k in self.headers),
                        }
                    )
                    + "\n"
                )

    def _json(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        self._record()
        if self.path == "/":
            body = b"Ollama is running"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/version":
            self._json(200, {"version": MOCK_VERSION})
        elif self.path == "/api/tags":
            self._json(200, {"models": [{"name": MOCK_MODEL, "model": MOCK_MODEL, "digest": MOCK_DIGEST, "size": 1}]})
        else:
            self._json(404, {"error": "not found"})

    def do_HEAD(self):  # noqa: N802
        self._record()
        self.send_response(200)
        self.end_headers()

    def do_POST(self):  # noqa: N802
        self._record()
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            req = json.loads(raw or b"{}")
        except ValueError:
            req = {}
        path = self.path.split("?", 1)[0]
        if path == "/v1/messages/count_tokens":
            self._json(200, {"input_tokens": 10})
            return
        if path != "/v1/messages":
            self._json(404, {"type": "error", "error": {"type": "not_found_error", "message": path}})
            return
        model = req.get("model") or MOCK_MODEL
        if not req.get("stream"):
            self._json(200, message_body(model))
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        for event, data in sse_events(model):
            self.wfile.write(f"event: {event}\ndata: {json.dumps(data)}\n\n".encode())
            self.wfile.flush()
        self.close_connection = True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--log")
    a = ap.parse_args()
    Handler.log_path = a.log
    srv = ThreadingHTTPServer((os.environ.get("ACR_MOCK_BIND", "127.0.0.1"), a.port), Handler)
    print(srv.server_address[1], flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
