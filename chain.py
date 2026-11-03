#!/usr/bin/env python3
"""Xray sidecar for Proxy Chain: vless:// URI → local SOCKS5 endpoint.

Runs ON the Render box next to forwarder.py. Boot sequence:

    ensure_binary()   download the pinned Xray-core release once per instance
    build_xray_config()  from vless_config (SOCKS5 inbound on 127.0.0.1 only)
    spawn + wait      until the SOCKS port accepts, or die loudly

Strict exit policy (owned by forwarder.py): the forwarder routes its egress
through this SOCKS5 endpoint and refuses to serve direct egress while
PROXY_CHAIN_VLESS is set — if the VLESS server is down, requests fail and
the exit Worker fails over to another forwarder. The boot here only demands
that the LOCAL socks port comes up, so a temporarily unreachable VLESS
server cannot crash-loop the forwarder.

No third-party dependencies (stdlib only) — requirements.txt stays curl_cffi.
"""

from __future__ import annotations

import atexit
import os
import platform
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile

import vless_config

XRAY_VERSION = "v26.10.31"
DOWNLOAD_BASE = ("https://github.com/XTLS/Xray-core/releases/download/"
                 + XRAY_VERSION)
ASSETS = {
    ("Linux", "x86_64"): ("Xray-linux-64.zip", "xray"),
    ("Windows", "AMD64"): ("Xray-windows-64.zip", "xray.exe"),
}
DOWNLOAD_TIMEOUT = 120
START_TIMEOUT = 30

_process = None
_workdir = None


class ChainError(RuntimeError):
    """Forwarder-fatal sidecar failure; message goes to Render logs."""


def _log(msg):
    print("chain: " + msg, flush=True)


def workdir() -> str:
    global _workdir
    if _workdir is None:
        base = os.environ.get("PROXY_CHAIN_WORKDIR") or tempfile.gettempdir()
        _workdir = os.path.join(base, "xray-chain")
        os.makedirs(_workdir, exist_ok=True)
    return _workdir


def asset_name():
    key = (platform.system(), platform.machine())
    try:
        return ASSETS[key]
    except KeyError:
        raise ChainError("no Xray asset for %s/%s" % key)


def binary_path() -> str:
    return os.path.join(workdir(), asset_name()[1])


def _download(url, dest, tries=3):
    for attempt in range(1, tries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "freednet-chain/1.0"})
            with urllib.request.urlopen(req, timeout=60) as resp, open(dest, "wb") as fh:
                while True:
                    chunk = resp.read(1 << 16)
                    if not chunk:
                        break
                    fh.write(chunk)
            return
        except Exception as exc:
            if attempt == tries:
                raise ChainError("download failed: %s" % exc)
            _log("download attempt %d failed (%s) — retrying" % (attempt, exc))
            time.sleep(2 * attempt)


def ensure_binary() -> str:
    """Return the xray binary path, downloading the pinned release once."""
    binary = binary_path()
    stamp = os.path.join(workdir(), "version")
    if os.path.exists(binary) and os.path.exists(stamp) and \
            open(stamp).read().strip() == XRAY_VERSION:
        return binary

    zip_name, exe_name = asset_name()
    zip_path = os.path.join(workdir(), zip_name)
    _log("downloading Xray-core %s (%s)…" % (XRAY_VERSION, zip_name))
    _download("%s/%s" % (DOWNLOAD_BASE, zip_name), zip_path)
    with zipfile.ZipFile(zip_path) as zf:
        zf.extract(exe_name, workdir())
    try:
        os.remove(zip_path)
    except OSError:
        pass
    if os.name != "nt":
        mode = os.stat(binary).st_mode
        os.chmod(binary, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    with open(stamp, "w") as fh:
        fh.write(XRAY_VERSION)
    _log("xray ready: %s" % binary)
    return binary


def _port_open(port, timeout=1.0):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def _stop():
    global _process
    if _process and _process.poll() is None:
        try:
            _process.terminate()
            _process.wait(timeout=5)
        except Exception:
            try:
                _process.kill()
            except Exception:
                pass
    _process = None


def start(uri: str, socks_port: int = 10808) -> str:
    """Bring the sidecar up. Returns the SOCKS URL for EGRESS_PROXY.
    Raises ChainError on any failure (forwarder must not serve direct)."""
    global _process
    if _port_open(socks_port, timeout=0.5):
        raise ChainError("port %d is already in use — refusing to start a "
                         "second chain endpoint" % socks_port)

    binary = ensure_binary()
    config_path = os.path.join(workdir(), "xray-chain.json")
    with open(config_path, "w") as fh:
        import json
        json.dump(vless_config.build_xray_config(uri, socks_port=socks_port), fh, indent=2)

    out_log = open(os.path.join(workdir(), "xray-out.log"), "ab")
    err_log = open(os.path.join(workdir(), "xray-err.log"), "ab")
    _log("starting xray (socks5 127.0.0.1:%d, %s)…" % (
        socks_port, vless_config.mask_uri(uri)))
    _process = subprocess.Popen(
        [binary, "run", "-c", config_path],
        stdout=out_log, stderr=err_log,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    atexit.register(_stop)

    deadline = time.time() + START_TIMEOUT
    while time.time() < deadline:
        if _process.poll() is not None:
            tail = _err_tail()
            raise ChainError("xray exited during startup (code %s)%s"
                             % (_process.returncode, ": " + tail if tail else ""))
        if _port_open(socks_port, timeout=0.5):
            _log("proxy chain socks endpoint is up — egress goes via VLESS")
            return "socks5h://127.0.0.1:%d" % socks_port
        time.sleep(0.4)
    _stop()
    raise ChainError("xray did not open port %d within %ds%s"
                     % (socks_port, START_TIMEOUT, ": " + _err_tail() if _err_tail() else ""))


def _err_tail(limit=400) -> str:
    try:
        with open(os.path.join(workdir(), "xray-err.log"), "rb") as fh:
            return fh.read()[-limit:].decode("utf-8", "replace").strip().replace("\n", " | ")
    except OSError:
        return ""


if __name__ == "__main__":
    # manual smoke test:  python chain.py "vless://…"
    if len(sys.argv) != 2:
        print("usage: chain.py <vless-uri>")
        sys.exit(2)
    socks = start(sys.argv[1])
    print("UP:", socks, "— press Ctrl+C to stop")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        _stop()
