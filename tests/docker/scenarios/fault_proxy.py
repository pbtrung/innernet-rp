#!/usr/bin/env python3
"""M9 Docker scenario: a real, minimal fault-injection relay.

Sits between a peer's real innernet client process and the real server,
on the peer's own loopback, inside the peer's own container/network
namespace. The peer's InterfaceConfig.server.internal_endpoint is
rewritten to point here (see m9_faults.sh) before `up --daemon` starts,
so every real HTTP request still crosses the peer's real, already-up
WireGuard tunnel -- only the last hop is relayed through this process.
This never touches production code paths; it exists purely as test
infrastructure, matching design case 4/5/7's need for real, kernel-level
fault injection (lost/duplicate responses, stale replay) that no existing
mocked-transport unit test can provide.

Fault modes (selected by environment variables):
  FAULT_MODE=drop-response
    The Nth (FAULT_COUNT, default 1) request whose path contains
    FAULT_MATCH is still forwarded to the real server (so the server's
    durable state advances for real), but its response is never sent
    back to the client -- the connection is closed with nothing written,
    exactly what a lost response over a real network looks like. The
    client's own already-implemented retry/backoff logic (client-
    core::pq_sync) does the rest, including the resulting duplicate
    request delivery to the server.
  FAULT_MODE=replay
    The first request whose path contains FAULT_MATCH is captured, then
    -- once a later request for the SAME peer with a higher phase number
    is observed (proving the exchange has moved on) -- replayed
    (resent) to the real server as an extra, out-of-band request. Its
    response is logged, not returned to the client. Everything else is
    relayed normally.
"""
import http.client
import http.server
import os
import re
import sys
import threading

REAL_HOST, REAL_PORT = os.environ["REAL_SERVER"].split(":")
REAL_PORT = int(REAL_PORT)
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "17171"))
FAULT_MODE = os.environ.get("FAULT_MODE", "")
FAULT_MATCH = os.environ.get("FAULT_MATCH", "")
FAULT_COUNT = int(os.environ.get("FAULT_COUNT", "1"))

_lock = threading.Lock()
_state = {"triggered": 0, "captured": None, "captured_phase": None, "replayed": False}

PHASE_RE = re.compile(r"phase=(\d+)")


def log(msg: str) -> None:
    print(f"[fault-proxy] {msg}", flush=True)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _relay(self) -> None:
        # Never reuse a connection: keeps a dropped/faulted response from
        # leaving a half-broken persistent connection in the real client's
        # pool that could confuse *unrelated* subsequent requests. Real
        # production HTTP behavior under a lost response is what's under
        # test here, not this relay's own connection-reuse semantics.
        self.close_connection = True
        length = int(self.headers.get("content-length", 0))
        body = self.rfile.read(length) if length else b""
        path = self.path
        method = self.command
        headers = {k: v for k, v in self.headers.items() if k.lower() != "host"}

        phase_match = PHASE_RE.search(path)
        phase = int(phase_match.group(1)) if phase_match else None
        matches = FAULT_MATCH and FAULT_MATCH in path

        replay_now = None
        with _lock:
            if FAULT_MODE == "replay" and matches and _state["captured"] is None:
                _state["captured"] = (method, path, headers, body)
                _state["captured_phase"] = phase
                log(f"captured for later replay: {method} {path}")
            elif (
                FAULT_MODE == "replay"
                and not _state["replayed"]
                and _state["captured"] is not None
                and phase is not None
                and _state["captured_phase"] is not None
                and phase > _state["captured_phase"]
            ):
                replay_now = _state["captured"]
                _state["replayed"] = True

        if replay_now is not None:
            r_method, r_path, r_headers, r_body = replay_now
            log(f"replaying stale request now that phase={phase} was observed: {r_method} {r_path}")
            try:
                conn = http.client.HTTPConnection(REAL_HOST, REAL_PORT, timeout=10)
                conn.request(r_method, r_path, body=r_body, headers=r_headers)
                resp = conn.getresponse()
                log(f"replay response: {resp.status} {resp.read()[:200]!r}")
                conn.close()
            except Exception as exc:
                log(f"replay attempt errored (also acceptable -- server may have already closed the exchange): {exc}")

        drop_this = False
        if FAULT_MODE == "drop-response" and matches:
            with _lock:
                if _state["triggered"] < FAULT_COUNT:
                    _state["triggered"] += 1
                    drop_this = True
                    log(f"dropping response #{_state['triggered']}/{FAULT_COUNT} for {method} {path}")

        try:
            conn = http.client.HTTPConnection(REAL_HOST, REAL_PORT, timeout=10)
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            resp_body = resp.read()
            conn.close()
        except Exception as exc:
            log(f"upstream request failed: {exc}")
            self.close_connection = True
            return

        if drop_this:
            # A real lost response: the server already durably processed
            # the request above; the client simply never hears back.
            self.close_connection = True
            return

        self.send_response(resp.status)
        for k, v in resp.getheaders():
            if k.lower() not in ("transfer-encoding", "connection"):
                self.send_header(k, v)
        self.send_header("content-length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def do_GET(self):
        self._relay()

    def do_PUT(self):
        self._relay()

    def do_POST(self):
        self._relay()

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    log(f"relaying 127.0.0.1:{LISTEN_PORT} -> {REAL_HOST}:{REAL_PORT}, mode={FAULT_MODE!r} match={FAULT_MATCH!r}")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", LISTEN_PORT), Handler)
    server.serve_forever()
