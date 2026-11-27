import importlib.util
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import pathlib
import sys
import threading
import unittest
import urllib.error
import urllib.request

_RELAY_PATH = pathlib.Path(__file__).with_name("ai-relay.py")
_SPEC = importlib.util.spec_from_file_location("ai_relay", _RELAY_PATH)
assert _SPEC and _SPEC.loader
ai_relay = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = ai_relay
_SPEC.loader.exec_module(ai_relay)


class _MockAuthHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:
        return

    def do_GET(self) -> None:
        if self.headers.get("Authorization") == "Bearer valid-jwt":
            body = b'{"revisionDate":"2026-11-27T00:00:00Z"}'
            self.send_response(200)
        else:
            body = b'{"error":"invalid_token"}'
            self.send_response(401)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _MockUpstreamHandler(BaseHTTPRequestHandler):
    last_headers: dict[str, str] = {}

    def log_message(self, format: str, *args) -> None:
        return

    def _reply(self, status: int, obj: dict) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        type(self).last_headers = {k.lower(): v for k, v in self.headers.items()}
        if self.path == "/v1/models":
            self._reply(200, {"data": [{"id": "claude-sonnet-4-5"}]})
            return
        self._reply(404, {"error": {"message": "upstream not found"}})

    def do_POST(self) -> None:
        type(self).last_headers = {k.lower(): v for k, v in self.headers.items()}
        length = int(self.headers.get("Content-Length") or "0")
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        if self.path == "/v1/messages":
            self._reply(200, {"content": [{"type": "text", "text": '{"ok":true}'}], "echo": raw})
            return
        self._reply(404, {"error": {"message": "not found"}})


def _start_server(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


class AiRelayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.auth_srv = _start_server(_MockAuthHandler)
        cls.upstream_srv = _start_server(_MockUpstreamHandler)
        cls.config = ai_relay.RelayConfig(
            bind_host="127.0.0.1",
            port=0,
            auth_url=f"http://127.0.0.1:{cls.auth_srv.server_port}/api/accounts/revision-date",
            self_hosts=frozenset({"152.32.234.200", "127.0.0.1", "localhost"}),
            host_gateway="127.0.0.1",
            timeout=10.0,
        )
        cls.relay_srv = _start_server(ai_relay.make_relay_handler(cls.config))
        cls.relay_base = f"http://127.0.0.1:{cls.relay_srv.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.relay_srv.shutdown()
        cls.relay_srv.server_close()
        cls.upstream_srv.shutdown()
        cls.upstream_srv.server_close()
        cls.auth_srv.shutdown()
        cls.auth_srv.server_close()

    def _req(self, method: str, path: str, body=None, headers=None):
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"{self.relay_base}{path}",
            data=data,
            method=method,
            headers=headers or {},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, dict(resp.headers), json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            return err.code, dict(err.headers), json.loads(err.read().decode("utf-8"))

    def test_health(self) -> None:
        status, hdrs, body = self._req("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(hdrs.get("X-KeyNexus-Relay"), "1")
        self.assertEqual(body, {"ok": True})

    def test_missing_or_invalid_auth(self) -> None:
        s1, h1, _ = self._req("POST", "/", {"url": "http://152.32.234.200:8788/v1/models", "method": "GET"})
        self.assertEqual(s1, 401)
        self.assertEqual(h1.get("X-KeyNexus-Relay"), "1")

        s2, h2, _ = self._req(
            "POST",
            "/",
            {"url": "http://152.32.234.200:8788/v1/models", "method": "GET"},
            {"X-KeyNexus-Auth": "Bearer wrong-token", "Content-Type": "application/json"},
        )
        self.assertEqual(s2, 401)
        self.assertEqual(h2.get("X-KeyNexus-Relay"), "1")

    def test_ssrf_blocks(self) -> None:
        hdr = {"X-KeyNexus-Auth": "Bearer valid-jwt", "Content-Type": "application/json"}
        s_meta, _, _ = self._req("POST", "/", {"url": "http://169.254.169.254/latest/meta-data/", "method": "GET"}, hdr)
        self.assertEqual(s_meta, 403)

        s_internal, _, _ = self._req("POST", "/", {"url": "http://keynexus-server/admin", "method": "GET"}, hdr)
        self.assertEqual(s_internal, 403)

    def test_self_host_rewrite_and_header_sanitization(self) -> None:
        port = self.upstream_srv.server_port
        status, hdrs, body = self._req(
            "POST",
            "/",
            {
                "url": f"http://152.32.234.200:{port}/v1/models",
                "method": "GET",
                "headers": {"x-api-key": "sk-upstream"},
            },
            {"X-KeyNexus-Auth": "Bearer valid-jwt", "Content-Type": "application/json"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(hdrs.get("X-KeyNexus-Relay"), "1")
        self.assertEqual(body["data"][0]["id"], "claude-sonnet-4-5")
        self.assertEqual(_MockUpstreamHandler.last_headers.get("host"), f"152.32.234.200:{port}")
        self.assertEqual(_MockUpstreamHandler.last_headers.get("x-api-key"), "sk-upstream")
        self.assertEqual(_MockUpstreamHandler.last_headers.get("user-agent"), "KeyNexus/2.0")
        self.assertNotIn("x-keynexus-auth", _MockUpstreamHandler.last_headers)

    def test_upstream_404_distinguishable_from_missing_route(self) -> None:
        port = self.upstream_srv.server_port
        status, hdrs, body = self._req(
            "POST",
            "/",
            {"url": f"http://152.32.234.200:{port}/nonexistent", "method": "GET"},
            {"X-KeyNexus-Auth": "Bearer valid-jwt", "Content-Type": "application/json"},
        )
        self.assertEqual(status, 404)
        self.assertEqual(hdrs.get("X-KeyNexus-Relay"), "1")
        self.assertEqual(body["error"]["message"], "upstream not found")


if __name__ == "__main__":
    unittest.main()
