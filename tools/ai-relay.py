#!/usr/bin/env python3
"""Authenticated same-origin HTTP/HTTPS AI gateway relay for KeyNexus Web Client."""

from __future__ import annotations

import dataclasses
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}
HOP_BY_HOP_HEADERS = {
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "keep-alive",
    "accept-encoding",
    "x-keynexus-auth",
}
BLOCKED_HOSTS = {
    "169.254.169.254",
    "100.100.100.200",
    "fd00:ec2::254",
    "metadata.google.internal",
    "keynexus-server",
    "keynexus-caddy",
    "keynexus-ai-relay",
    "pwdsv",
    "vaultwarden",
}


@dataclasses.dataclass(frozen=True)
class RelayConfig:
    """Runtime configuration for the KeyNexus AI relay server."""

    bind_host: str = "0.0.0.0"
    port: int = 8789
    auth_url: str = "http://keynexus-server:80/api/accounts/revision-date"
    self_hosts: frozenset[str] = frozenset({"127.0.0.1", "localhost"})
    host_gateway: str = "host.docker.internal"
    timeout: float = 120.0
    max_body_bytes: int = 20 * 1024 * 1024

    @classmethod
    def from_env(cls) -> "RelayConfig":
        raw_hosts = os.environ.get("RELAY_SELF_HOSTS", "127.0.0.1,localhost")
        self_hosts = frozenset(h.strip().lower() for h in raw_hosts.split(",") if h.strip())
        return cls(
            bind_host=os.environ.get("RELAY_BIND_HOST", "0.0.0.0").strip() or "0.0.0.0",
            port=int(os.environ.get("RELAY_PORT", "8789")),
            auth_url=os.environ.get(
                "KEYNEXUS_AUTH_URL",
                "http://keynexus-server:80/api/accounts/revision-date",
            ).strip(),
            self_hosts=self_hosts or frozenset({"127.0.0.1", "localhost"}),
            host_gateway=os.environ.get("RELAY_HOST_GATEWAY", "host.docker.internal").strip() or "host.docker.internal",
            timeout=float(os.environ.get("RELAY_TIMEOUT", "120")),
            max_body_bytes=int(os.environ.get("RELAY_MAX_BODY_BYTES", str(20 * 1024 * 1024))),
        )


def _format_host_port(host: str, port: int | None) -> str:
    formatted_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{formatted_host}:{port}" if port is not None else formatted_host


def _validate_target_url(raw_url: str, config: RelayConfig) -> tuple[urllib.parse.ParseResult, str, dict[str, str], bool]:
    """Validate URL scheme and SSRF blocklist, and rewrite self-hosts to host gateway."""
    parsed = urllib.parse.urlparse(str(raw_url or "").strip())
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https") or not parsed.netloc or not parsed.hostname:
        raise ValueError("仅支持合法的 http:// 或 https:// 上游地址")

    hostname = parsed.hostname.strip().lower().rstrip(".")
    if hostname in BLOCKED_HOSTS:
        raise PermissionError(f"出于安全限制，禁止中继访问受保护地址: {hostname}")

    try:
        ip_obj = ipaddress.ip_address(hostname)
    except ValueError:
        ip_obj = None
    if ip_obj is not None and (ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified):
        raise PermissionError(f"出于安全限制，禁止中继访问链路本地或保留地址: {hostname}")

    is_self_host = hostname in config.self_hosts
    extra_headers: dict[str, str] = {}
    connect_url = parsed.geturl()
    if is_self_host:
        extra_headers["Host"] = parsed.netloc
        rewritten_netloc = _format_host_port(config.host_gateway, parsed.port)
        if parsed.username or parsed.password:
            auth_prefix = urllib.parse.quote(parsed.username or "", safe="")
            if parsed.password:
                auth_prefix += ":" + urllib.parse.quote(parsed.password, safe="")
            rewritten_netloc = f"{auth_prefix}@{rewritten_netloc}"
        connect_url = urllib.parse.urlunparse(parsed._replace(netloc=rewritten_netloc))

    return parsed, connect_url, extra_headers, is_self_host


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-validate redirect targets against the SSRF policy before following."""

    def __init__(self, config: RelayConfig) -> None:
        self.config = config

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        _, connect_url, extra_headers, _ = _validate_target_url(newurl, self.config)
        next_req = super().redirect_request(req, fp, code, msg, headers, connect_url)
        if next_req is not None:
            for k, v in extra_headers.items():
                next_req.add_unredirected_header(k, v)
        return next_req


def _safe_url_label(parsed: urllib.parse.ParseResult) -> str:
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"


def _verify_keynexus_auth(auth_header: str, config: RelayConfig) -> bool:
    """Validate KeyNexus Bearer token against internal Vaultwarden server."""
    token_hdr = (auth_header or "").strip()
    if not token_hdr.lower().startswith("bearer ") or len(token_hdr) <= 7:
        return False

    req = urllib.request.Request(
        config.auth_url,
        method="GET",
        headers={
            "Authorization": token_hdr,
            "Accept": "application/json",
            "User-Agent": "KeyNexus-Relay/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception:
        return False


def make_relay_handler(config: RelayConfig) -> type[BaseHTTPRequestHandler]:
    """Create a ThreadingHTTPServer request handler bound to `config`."""

    class RelayHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args) -> None:
            # Keep logs minimal and never dump request payloads or secrets.
            return

        def _send_bytes(self, status: int, content_type: str, body: bytes) -> None:
            self.close_connection = True
            self.send_response(status)
            self.send_header("Content-Type", content_type or "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.send_header("X-KeyNexus-Relay", "1")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD" and body:
                self.wfile.write(body)

        def _send_json_error(self, status: int, message: str) -> None:
            payload = json.dumps({"error": {"message": message}}, ensure_ascii=False).encode("utf-8")
            self._send_bytes(status, "application/json; charset=utf-8", payload)

        def do_GET(self) -> None:
            path = urllib.parse.urlparse(self.path).path
            if path in ("/health", "/ai-relay/health"):
                self._send_bytes(200, "application/json; charset=utf-8", b'{"ok":true}')
                return
            self._send_json_error(405, "仅支持 POST /ai-relay 中继请求或 GET /ai-relay/health")

        def do_POST(self) -> None:
            auth_hdr = self.headers.get("X-KeyNexus-Auth") or self.headers.get("Authorization") or ""
            if not _verify_keynexus_auth(auth_hdr, config):
                self._send_json_error(401, "KeyNexus 登录态校验失败，请重新解锁密码库")
                return

            try:
                content_len = int(self.headers.get("Content-Length") or "0")
            except ValueError:
                self._send_json_error(400, "无效的 Content-Length")
                return

            if content_len <= 0:
                self._send_json_error(400, "请求体不能为空")
                return
            if content_len > config.max_body_bytes:
                self._send_json_error(413, "请求体超过中继最大限制")
                return

            raw_req = self.rfile.read(content_len)
            try:
                spec = json.loads(raw_req.decode("utf-8"))
            except Exception:
                self._send_json_error(400, "中继请求必须为合法 JSON")
                return

            if not isinstance(spec, dict):
                self._send_json_error(400, "中继请求体格式错误")
                return

            method = str(spec.get("method") or "POST").strip().upper()
            if method not in ALLOWED_METHODS:
                self._send_json_error(400, f"不支持的 HTTP 方法: {method}")
                return

            try:
                parsed, connect_url, host_override, is_self_host = _validate_target_url(spec.get("url") or "", config)
            except PermissionError as exc:
                self._send_json_error(403, str(exc))
                return
            except ValueError as exc:
                self._send_json_error(400, str(exc))
                return

            out_headers: dict[str, str] = {}
            has_ua = False
            raw_headers = spec.get("headers") or {}
            if isinstance(raw_headers, dict):
                for k, v in raw_headers.items():
                    key = str(k).strip()
                    if not key or key.lower() in HOP_BY_HOP_HEADERS:
                        continue
                    if key.lower() == "user-agent":
                        has_ua = True
                    out_headers[key] = str(v)

            if not has_ua:
                out_headers["User-Agent"] = "KeyNexus/2.0"
            for k, v in host_override.items():
                out_headers[k] = v

            body_val = spec.get("body")
            out_body: bytes | None = None
            if body_val is not None and method not in ("GET", "HEAD"):
                if isinstance(body_val, (dict, list)):
                    out_body = json.dumps(body_val, ensure_ascii=False).encode("utf-8")
                else:
                    out_body = str(body_val).encode("utf-8")

            ssl_ctx = ssl._create_unverified_context() if is_self_host else ssl.create_default_context()
            opener = urllib.request.build_opener(
                _SafeRedirectHandler(config),
                urllib.request.HTTPSHandler(context=ssl_ctx),
            )
            upstream_req = urllib.request.Request(connect_url, data=out_body, headers=out_headers, method=method)

            try:
                try:
                    resp_cm = opener.open(upstream_req, timeout=config.timeout)
                except urllib.error.HTTPError:
                    raise
                except (urllib.error.URLError, TimeoutError, OSError):
                    original_url = parsed.geturl()
                    if not (is_self_host and connect_url != original_url):
                        raise
                    fallback_headers = {k: v for k, v in out_headers.items() if k.lower() != "host"}
                    fallback_req = urllib.request.Request(
                        original_url,
                        data=out_body,
                        headers=fallback_headers,
                        method=method,
                    )
                    resp_cm = opener.open(fallback_req, timeout=config.timeout)

                with resp_cm as resp:
                    resp_body = resp.read()
                    resp_ct = resp.headers.get("Content-Type") or "application/json; charset=utf-8"
                    self._send_bytes(resp.status, resp_ct, resp_body)
            except urllib.error.HTTPError as http_err:
                err_body = http_err.read() if hasattr(http_err, "read") else b""
                err_ct = (http_err.headers.get("Content-Type") if http_err.headers else None) or "application/json; charset=utf-8"
                self._send_bytes(http_err.code, err_ct, err_body)
            except (urllib.error.URLError, TimeoutError, OSError, PermissionError, ValueError) as exc:
                reason = getattr(exc, "reason", exc)
                self._send_json_error(502, f"中继连接上游失败 ({_safe_url_label(parsed)}): {reason}")

    return RelayHandler


def run_server(config: RelayConfig | None = None) -> None:
    cfg = config or RelayConfig.from_env()
    server = ThreadingHTTPServer((cfg.bind_host, cfg.port), make_relay_handler(cfg))
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    run_server()
