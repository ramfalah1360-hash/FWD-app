#!/usr/bin/env python3
"""vless:// share-URI parser → Xray outbound JSON (Proxy Chain feature).

Shared by two runtimes:
  - App/control_server.py (via importlib) validates the URI before it is
    pushed anywhere, so the GUI fails fast with a readable error.
  - deploy/upstream_forwarder/chain.py builds the actual Xray sidecar
    config on the Render box.

Supported today (the realistic provider space):
  security: none | tls | reality          type: tcp | ws | grpc |
  httpupgrade | xhttp (splithttp)         flow: xtls-rprx-vision (tcp only)
  params: sni/peer/host, fp, pbk, sid, spx, alpn, path, serviceName, mode,
  headerType=http (tcp), allowInsecure/keepInsecure
Deliberately rejected: kcp/quic (UDP transports — the relay chain and the
full-system TUN are TCP-only), any encryption other than "none".
"""

from __future__ import annotations

import ipaddress
import uuid as _uuid
from urllib.parse import urlsplit, parse_qsl, unquote


class VlessError(ValueError):
    """User-actionable parse/validation failure; safe to show in the GUI."""


_SUPPORTED_NETWORKS = ("tcp", "ws", "grpc", "httpupgrade", "xhttp")
_UDP_NETWORKS = ("kcp", "quic")


def _b(values, key, default=""):
    for k, v in values:
        if k == key:
            return v
    return default


def _bool_flag(values, *keys):
    for k, v in values:
        if k in keys and v.strip().lower() in ("1", "true", "yes", "on"):
            return True
    return False


def _is_private_target(host: str) -> bool:
    """True for loopback/private IP literals — the only place Xray still
    accepts unencrypted VLESS (local testing)."""
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False  # domain names are treated as public


def parse_vless_uri(uri: str) -> dict:
    """Parse a vless:// URI into an Xray outbound dict. Raises VlessError."""
    uri = (uri or "").strip()
    if not uri.lower().startswith("vless://"):
        raise VlessError("A vless:// link is expected (it starts with vless://).")
    try:
        parts = urlsplit(uri)
    except ValueError as exc:
        raise VlessError("The link is not a valid URL: %s" % exc)

    userinfo = (parts.username or "").strip()
    if not userinfo:
        raise VlessError("The link has no UUID (vless://UUID@host:port).")
    try:
        _uuid.UUID(userinfo)
    except ValueError:
        raise VlessError("The UUID in the link is not a valid UUID.")

    host = (parts.hostname or "").strip()
    if not host:
        raise VlessError("The link has no server address.")
    port = parts.port
    if not port or not 1 <= port <= 65535:
        raise VlessError("The server port is missing or invalid.")

    try:
        # parse_qsl already percent-decodes values — do NOT unquote again
        # (a second decode corrupts values that legitimately contain '%').
        params = [(k.lower(), v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    except ValueError:
        params = []

    encryption = _b(params, "encryption", "none") or "none"
    if encryption != "none":
        raise VlessError('encryption must be "none" — VLESS does not support "%s".' % encryption)

    network = (_b(params, "type", "tcp") or "tcp").strip().lower()
    if network == "splithttp":
        network = "xhttp"
    if network == "http":
        # v2rayN-style export: type=http means tcp with HTTP obfuscation.
        network = "tcp"
        if not _b(params, "headertype"):
            params.append(("headertype", "http"))
    if network in _UDP_NETWORKS:
        raise VlessError('Transport "%s" is not supported (UDP-based) — use tcp/ws/grpc/httpupgrade/xhttp.' % network)
    if network not in _SUPPORTED_NETWORKS:
        raise VlessError('Transport "%s" is not supported.' % network)

    security = (_b(params, "security", "") or "").strip().lower() or "none"
    if security not in ("none", "tls", "reality"):
        raise VlessError('Security "%s" is not supported — use none, tls, or reality.' % security)
    if security == "none" and not _is_private_target(host):
        # Xray-core 25+ refuses unencrypted VLESS to public addresses
        # ("vless without TLS … is prohibited") — fail here, not on Render.
        raise VlessError("Plain (no TLS) VLESS is rejected by Xray for public "
                         "servers — the config must use security=tls or reality.")

    flow = (_b(params, "flow") or "").strip()
    if flow and network != "tcp":
        raise VlessError('flow=%s is only valid with type=tcp.' % flow)
    if flow and security == "none":
        raise VlessError("flow requires security=tls or reality.")

    user = {"id": userinfo, "encryption": "none", "level": 0}
    if flow:
        user["flow"] = flow

    sni = (_b(params, "sni") or _b(params, "peer") or "").strip()
    fp = (_b(params, "fp") or "").strip() or ("chrome" if security == "reality" else "")
    alpn_raw = (_b(params, "alpn") or "").strip()

    stream = {"network": network, "security": security}
    if security == "tls":
        if not sni:
            sni = host
        tls = {"serverName": sni, "fingerprint": fp or "chrome"}
        alpn = [a for a in alpn_raw.replace("|", ",").split(",") if a.strip()]
        if alpn:
            tls["alpn"] = alpn
        if _bool_flag(params, "allowinsecure", "keepinsecure", "insecure"):
            tls["allowInsecure"] = True
        stream["tlsSettings"] = tls
    elif security == "reality":
        pbk = (_b(params, "pbk") or "").strip()
        sid = (_b(params, "sid") or "").strip()
        if not pbk:
            raise VlessError("reality requires the pbk= (public key) parameter.")
        reality = {
            "serverName": sni or host,
            "fingerprint": fp,
            "publicKey": pbk,
            "shortId": sid,
        }
        spx = (_b(params, "spx") or "").strip()
        if spx:
            reality["spiderX"] = spx
        stream["realitySettings"] = reality

    ws_path = _b(params, "path", "/") or "/"
    ws_host = (_b(params, "host") or "").strip()
    if network == "ws":
        ws = {"path": ws_path or "/"}
        if ws_host:
            ws["headers"] = {"Host": ws_host}
        stream["wsSettings"] = ws
    elif network == "grpc":
        svc = (_b(params, "servicename") or _b(params, "path") or "").strip()
        grpc = {"serviceName": svc, "multiMode": (_b(params, "mode") or "").lower() == "multi"}
        stream["grpcSettings"] = grpc
    elif network in ("httpupgrade", "xhttp"):
        s = {"path": ws_path or "/"}
        if ws_host:
            s["host"] = ws_host
        stream[(network + "Settings")] = s
    elif network == "tcp" and (_b(params, "headertype") or "").lower() == "http":
        header = {"type": "http", "request": {"version": "1.1", "method": "GET", "path": [ws_path or "/"]}}
        if ws_host:
            header["request"]["headers"] = {"Host": [ws_host]}
        stream["tcpSettings"] = {"header": header}

    return {
        "tag": "chain-vless",
        "protocol": "vless",
        "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
        "streamSettings": stream,
        "mux": {"enabled": False, "concurrency": -1},
    }


def validate_vless_uri(uri: str):
    """Validate and return a short human-readable summary.
    Raises VlessError on any problem."""
    out = parse_vless_uri(uri)
    nxt = out["settings"]["vnext"][0]
    st = out["streamSettings"]
    bits = ["%s:%d" % (nxt["address"], nxt["port"]), st["network"], st["security"]]
    if nxt["users"][0].get("flow"):
        bits.append(nxt["users"][0]["flow"])
    return " · ".join(bits)


def build_xray_config(uri: str, socks_port: int = 10808, socks_host: str = "127.0.0.1") -> dict:
    """Full Xray config: one SOCKS5 inbound on localhost + the VLESS outbound."""
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "chain-in",
            "listen": socks_host,
            "port": int(socks_port),
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [parse_vless_uri(uri)],
    }


def mask_uri(uri: str) -> str:
    """Log/GUI-safe form: keeps host:port and label, hides the UUID."""
    uri = (uri or "").strip()
    if not uri.lower().startswith("vless://"):
        return ""
    try:
        parts = urlsplit(uri)
        label = unquote(parts.fragment or "")
        hostpart = "%s:%d" % (parts.hostname or "?", parts.port or 0)
        return "vless://…%s%s" % (hostpart, ("  (%s)" % label) if label else "")
    except ValueError:
        return "vless://…"
