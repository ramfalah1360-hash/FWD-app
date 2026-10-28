#!/usr/bin/env python3
"""Chrome-impersonating upstream forwarder for mhr-cfw.

Same wire protocol as upstream_forwarder.js:

    POST /fwd   header: x-upstream-auth: AUTH_KEY
    body:  { u, m, h, b, ct, r }        b = base64 request body
    200:   { s, h, b }                  s = status, h = headers, b = base64 body
    200:   { e: "message" }             relay-level error

The difference is the last hop: requests are issued with curl_cffi's selected
browser impersonation profile. It can mimic parts of a browser TLS/HTTP/2
fingerprint, but it is not a full browser and cannot guarantee acceptance by a
destination or CAPTCHA system.

Requires: curl_cffi 0.16.3 (the Render Blueprint pins this version)
Env:
    AUTH_KEY        required, >= 32 chars
    HOST            default 127.0.0.1 (use 0.0.0.0 on Render)
    PORT            default 8787 (Render injects it)
    IMPERSONATE     default "chrome" (curl_cffi profile; empty = disabled)
    EGRESS_PROXY    optional authenticated HTTP/SOCKS proxy URL; controls target egress IP
    TIMEOUT_MS      default 25000
    MAX_BODY_BYTES  default 50 MB
    REDIRECT_LIMIT  default 5
    ALLOW_PRIVATE   1 = allow private targets (LOCAL TESTING ONLY)
"""

from __future__ import annotations

import base64
import hmac
import ipaddress
import json
import logging
import math
import os
import re
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urljoin, urlsplit

from curl_cffi import requests as cffi_requests

AUTH_KEY = os.environ.get("AUTH_KEY", "")
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8787"))
IMPERSONATE = os.environ.get("IMPERSONATE", "chrome").strip()
TIMEOUT_MS = int(os.environ.get("TIMEOUT_MS", "25000"))
TIMEOUT_S = TIMEOUT_MS / 1000.0
MAX_BODY = int(os.environ.get("MAX_BODY_BYTES", str(50 * 1024 * 1024)))
MAX_REQ = int(os.environ.get("MAX_REQUEST_BYTES", str(50 * 1024 * 1024)))
MAX_ENVELOPE = math.ceil(MAX_REQ * 4 / 3) + 1024 * 1024
REDIRECT_LIMIT = int(os.environ.get("REDIRECT_LIMIT", "5"))
ALLOW_PRIVATE = os.environ.get("ALLOW_PRIVATE", "").strip().lower() in ("1", "true", "yes", "on")
EGRESS_PROXY = os.environ.get("EGRESS_PROXY", "").strip()
ALLOWED_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


def validate_egress_proxy(value: str) -> None:
    if not value:
        return
    try:
        parts = urlsplit(value)
        # curl_cffi/libcurl accepts HTTP(S) and SOCKS proxy URLs. Keep proxy
        # credentials in Render's secret environment variable, never in YAML.
        if parts.scheme.lower() not in ("http", "https", "socks4", "socks4a", "socks5", "socks5h"):
            raise ValueError("unsupported proxy scheme")
        if not parts.hostname:
            raise ValueError("proxy host is missing")
        _ = parts.port  # force validation of malformed/out-of-range ports
        if parts.path not in ("", "/") or parts.query or parts.fragment:
            raise ValueError("proxy URL must not include a path, query, or fragment")
    except ValueError as exc:
        print("FATAL: invalid EGRESS_PROXY: " + str(exc), file=sys.stderr)
        sys.exit(1)


def validate_limits() -> None:
    if not 1 <= PORT <= 65535:
        raise ValueError("PORT must be between 1 and 65535")
    if not 1000 <= TIMEOUT_MS <= 120000:
        raise ValueError("TIMEOUT_MS must be between 1000 and 120000")
    if not 1024 <= MAX_BODY <= 50 * 1024 * 1024:
        raise ValueError("MAX_BODY_BYTES is outside the supported range")
    if not 1024 <= MAX_REQ <= 50 * 1024 * 1024:
        raise ValueError("MAX_REQUEST_BYTES is outside the supported range")
    if not 0 <= REDIRECT_LIMIT <= 10:
        raise ValueError("REDIRECT_LIMIT must be between 0 and 10")

if not AUTH_KEY.strip() or len(AUTH_KEY.strip().encode("utf-8")) < 32 or AUTH_KEY.strip().lower().startswith(
    ("change_me", "replace_with", "strong_secret", "your_secret", "example_secret")
):
    print("FATAL: AUTH_KEY must be a private random key of at least 32 bytes.", file=sys.stderr)
    sys.exit(1)

validate_egress_proxy(EGRESS_PROXY)
try:
    validate_limits()
except ValueError as exc:
    print("FATAL: " + str(exc), file=sys.stderr)
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("forwarder")

SKIP_HEADERS = {
    "host",
    "connection",
    "content-length",
    "transfer-encoding",
    "proxy-connection",
    "proxy-authorization",
    "x-relay-auth",
    "x-upstream-auth",
    "x-relay-hop",
    "x-fwd-hop",
    "accept-encoding",  # let curl_cffi use the impersonation profile's value
    "te",
    "trailer",
    "upgrade",
}

PRIVATE_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa", ".intranet")
PRIVATE_HOSTS = {"localhost", "::1", "::", "metadata", "metadata.google.internal"}

STATUS_PAGE = (
    "<!DOCTYPE html><html><head><title>Forwarder Active</title></head>"
    '<body style="font-family:sans-serif;max-width:600px;margin:40px auto">'
    "<h1>Forwarder <span style=\"color:#16a34a;font-weight:700\">Active</span></h1>"
    "<p>mhr-cfw upstream forwarder.</p>"
    "<p>mode: " + ("proxy egress" if EGRESS_PROXY else "direct egress") + "</p>"
    "</body></html>"
)

_thread_local = threading.local()


def get_session():
    session = getattr(_thread_local, "session", None)
    if session is None:
        kwargs = {}
        # Avoid inheriting an unrelated HTTP_PROXY from the service runtime;
        # EGRESS_PROXY is the only proxy this service should use.
        kwargs["trust_env"] = False
        if IMPERSONATE:
            kwargs["impersonate"] = IMPERSONATE
        if EGRESS_PROXY:
            kwargs["proxy"] = EGRESS_PROXY
        session = cffi_requests.Session(**kwargs)
        _thread_local.session = session
    return session


class RelayError(Exception):
    pass


def error_text(exc: Exception) -> str:
    text = str(exc).strip()
    return text or exc.__class__.__name__


def assert_public(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme.lower() not in ("http", "https") or parts.fragment:
        raise RelayError("unsupported or invalid target URL")
    host = (parts.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise RelayError("empty host")
    if host in PRIVATE_HOSTS or any(host.endswith(suffix) for suffix in PRIVATE_SUFFIXES):
        raise RelayError("private host blocked")
    if parts.username is not None or parts.password is not None:
        raise RelayError("target URL must not contain credentials")
    try:
        port = parts.port
    except ValueError as exc:
        raise RelayError("invalid target port") from exc
    if port == 25:
        raise RelayError("target port is not allowed")
    if ALLOW_PRIVATE:
        return

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise RelayError("DNS resolution failed: " + error_text(exc))

    for info in infos:
        address = info[4][0].split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if not ip.is_global:
            raise RelayError("private address blocked")


def sanitize_headers(raw) -> dict:
    headers = {}
    if not isinstance(raw, dict):
        return headers

    for key, value in list(raw.items())[:100]:
        lower = str(key).lower()
        if lower in SKIP_HEADERS or lower.startswith("x-relay-") or lower.startswith("x-fwd-"):
            continue
        if isinstance(value, list):
            value = ", ".join(str(item) for item in value)
        name = str(key)
        value = str(value)
        if not HEADER_NAME_RE.fullmatch(name) or "\r" in value or "\n" in value:
            continue
        if len(value) > 8192:
            continue
        headers[name] = value
    return headers


def drop_credentials(headers: dict) -> dict:
    return {
        key: value
        for key, value in headers.items()
        if key.lower() not in ("authorization", "cookie", "proxy-authorization")
    }


def strip_header(headers: dict, name: str) -> dict:
    return {key: value for key, value in headers.items() if key.lower() != name}


def is_redirect(status: int) -> bool:
    return status in (301, 302, 303, 307, 308)


def origin_key(url: str) -> tuple[str, str, int | None]:
    parts = urlsplit(url)
    default_port = 443 if parts.scheme.lower() == "https" else 80
    return parts.scheme.lower(), (parts.hostname or "").lower(), parts.port or default_port


def safe_host(url: str) -> str:
    try:
        return urlsplit(url).hostname or "<invalid-host>"
    except ValueError:
        return "<invalid-host>"


def read_response_limited(response, limit: int, deadline: float | None = None) -> bytes:
    chunks = []
    size = 0
    for chunk in response.iter_content():
        if deadline is not None and time.monotonic() > deadline:
            raise RelayError("request timed out")
        if not chunk:
            continue
        size += len(chunk)
        if size > limit:
            raise RelayError("response body too large")
        chunks.append(chunk)
    return b"".join(chunks)


def fetch(method: str, url: str, headers: dict, body: bytes | None, follow: bool, deadline: float):
    session = get_session()

    # A Session keeps a cookie jar. The browser (through the local proxy) is
    # the only cookie authority, so never let one request's cookies leak into
    # the next one (or into another site).
    try:
        session.cookies.clear()
    except Exception:
        pass

    current = url
    current_method = method
    current_headers = dict(headers)
    current_body = body
    origin = origin_key(url)
    for hop in range(REDIRECT_LIMIT + 1):
        assert_public(current)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RelayError("request timed out")

        kwargs = {
            "headers": current_headers,
            "allow_redirects": False,
            "timeout": remaining,
            "stream": True,
        }
        if current_body is not None:
            kwargs["data"] = current_body
        elif current_method in ("POST", "PUT", "PATCH"):
            kwargs["data"] = b""

        response = session.request(current_method, current, **kwargs)

        if not follow or not is_redirect(response.status_code):
            return response

        location = response.headers.get("location")
        if not location:
            return response

        try:
            next_url = urljoin(current, location)
        except ValueError:
            return response
        if urlsplit(next_url).scheme not in ("http", "https"):
            return response
        if hop >= REDIRECT_LIMIT:
            response.close()
            raise RelayError("too many redirects")

        try:
            next_origin = origin_key(next_url)
        except ValueError as exc:
            response.close()
            raise RelayError("invalid redirect URL") from exc
        if next_origin != origin:
            current_headers = drop_credentials(current_headers)
        if (response.status_code == 303 and current_method != "HEAD") or (
            response.status_code in (301, 302)
            and current_method not in ("GET", "HEAD")
        ):
            current_method = "GET"
            current_body = None
            current_headers = strip_header(current_headers, "content-type")

        response.close()
        current = next_url

    raise RelayError("too many redirects")


def build_headers(response) -> dict:
    out = {}
    cookies = []
    for key, value in response.headers.multi_items():
        lower = key.lower()
        if lower in (
            "content-encoding",
            "content-length",
            "transfer-encoding",
            "connection",
            "keep-alive",
            "te",
            "trailer",
            "upgrade",
        ):
            continue
        if lower == "set-cookie":
            cookies.append(value)
            continue
        out[key] = value

    if len(cookies) == 1:
        out["set-cookie"] = cookies[0]
    elif len(cookies) > 1:
        out["set-cookie"] = cookies

    return out


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mhr-forwarder-py"

    def setup(self):
        super().setup()
        self.connection.settimeout(TIMEOUT_S + 15)

    def log_message(self, fmt, *args):  # keep the default quiet
        log.info("%s - %s", self.address_string(), fmt % args)

    def send_body(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_body(status, body, "application/json; charset=utf-8")

    @staticmethod
    def _path_only(path: str) -> str:
        return (urlsplit(path).path or "/").rstrip("/") or "/"

    def do_GET(self):
        if self._path_only(self.path) == "/":
            self.send_body(200, STATUS_PAGE.encode("utf-8"), "text/html; charset=utf-8")
            return
        self.send_json(404, {"e": "not found"})

    def do_HEAD(self):
        # Render's health check may use HEAD; GET already skips the body for it.
        self.do_GET()

    def do_POST(self):
        # Accept POST /, /fwd and /fwd/ so a missing or trailing "/fwd" in the
        # Worker's UPSTREAM_FORWARDER_URL cannot break the relay. Auth is still
        # required, so exposing "/" as an endpoint is safe.
        if self._path_only(self.path) not in ("/", "/fwd"):
            self.send_json(404, {"e": "not found"})
            return

        provided = self.headers.get("x-upstream-auth", "")
        if not hmac.compare_digest(provided, AUTH_KEY):
            self.send_json(401, {"e": "unauthorized"})
            return

        response = None
        if self.headers.get("transfer-encoding"):
            self.close_connection = True
            self.send_json(400, {"e": "transfer-encoding is not supported"})
            return
        try:
            raw_length = self.headers.get("content-length")
            if raw_length is None or not raw_length.isdecimal():
                raise ValueError("invalid content-length")
            length = int(raw_length)
        except ValueError:
            self.send_json(400, {"e": "invalid content-length"})
            return
        if length < 0 or length > MAX_ENVELOPE:
            self.close_connection = True
            self.send_json(413, {"e": "request body too large"})
            return
        raw = self.rfile.read(length) if length else b""
        if len(raw) != length:
            self.close_connection = True
            self.send_json(400, {"e": "incomplete request body"})
            return

        try:
            payload = json.loads(raw)
        except Exception:
            self.send_json(200, {"e": "invalid json"})
            return

        if not isinstance(payload, dict) or not isinstance(payload.get("u"), str):
            self.send_json(200, {"e": "bad url"})
            return

        target = payload["u"]
        try:
            parts = urlsplit(target)
            if parts.scheme.lower() not in ("http", "https") or not parts.hostname or parts.fragment:
                raise ValueError("invalid URL")
            _ = parts.port
        except ValueError:
            self.send_json(200, {"e": "bad url"})
            return

        method = str(payload.get("m") or "GET").upper()
        if method not in ALLOWED_METHODS:
            self.send_json(400, {"e": "unsupported method"})
            return
        headers = sanitize_headers(payload.get("h"))
        follow = payload.get("r") is not False

        body = None
        encoded_body = payload.get("b")
        if encoded_body not in (None, "") and not isinstance(encoded_body, str):
            self.send_json(200, {"e": "invalid base64 body"})
            return
        if encoded_body:
            if len(encoded_body) > math.ceil(MAX_REQ * 4 / 3) + 8:
                self.send_json(200, {"e": "request body too large"})
                return
            try:
                body = base64.b64decode(encoded_body, validate=True)
            except Exception:
                self.send_json(200, {"e": "invalid base64 body"})
                return
            if base64.b64encode(body).decode("ascii") != encoded_body:
                self.send_json(200, {"e": "invalid base64 body"})
                return
            if len(body) > MAX_REQ:
                self.send_json(200, {"e": "request body too large"})
                return

        try:
            deadline = time.monotonic() + TIMEOUT_S
            response = fetch(method, target, headers, body, follow, deadline)
            content = read_response_limited(response, MAX_BODY, deadline)

            encoded = base64.b64encode(content).decode("ascii")
            log.info("%s %s -> %s (%d bytes)", method, safe_host(target), response.status_code, len(content))
            self.send_json(200, {"s": response.status_code, "h": build_headers(response), "b": encoded})
        except RelayError as exc:
            log.warning("%s %s failed (%s)", method, safe_host(target), exc.__class__.__name__)
            self.send_json(200, {"e": error_text(exc)})
        except Exception as exc:
            log.warning("%s %s failed (%s)", method, safe_host(target), exc.__class__.__name__)
            self.send_json(200, {"e": "upstream request failed"})
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> None:
    server = Server((HOST, PORT), Handler)
    log.info(
        "listening on %s:%d (profile=%s, timeout=%.1fs)",
        HOST,
        PORT,
        IMPERSONATE or "none",
        TIMEOUT_S,
    )
    if ALLOW_PRIVATE:
        log.warning("ALLOW_PRIVATE=1 - SSRF protection is disabled")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
