#!/usr/bin/env python3
"""Minimalist encrypted file server. Stores only AES-GCM encrypted blobs.
   Run: python3 server.py [--host HOST] [--port PORT]
"""
from __future__ import annotations

import argparse
import collections
import hmac
import ipaddress
import json
import os
import random
import secrets
import socket
import ssl
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

BASE      = Path(__file__).parent
FILES_DIR  = BASE / "files"
TRASH_DIR  = FILES_DIR / "trash"
TRASH_DAYS = 7   # days before auto-purge
INDEX_HTML = BASE / "index.html"
TOKEN_FILE = BASE / ".api-token"
ARGON2_JS  = BASE / "argon2-bundled.min.js"

MAX_UPLOAD = 2 * 1024 * 1024 * 1024  # 2 GiB
MAX_FETCH  = 1 * 1024 * 1024 * 1024  # 1 GiB
CHUNK      = 65536                   # 64 KiB I/O block

VAULT_TOKEN: str = ""  # set at startup by _load_token()

# ── Response headers ──────────────────────────────────────────────────────────

_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' blob: data:; "
    "media-src blob:; "
    "object-src blob:; "
    "worker-src blob:"   # argon2-browser spawns its WASM worker via blob: URL
)
BASE_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}

# ── Token management ──────────────────────────────────────────────────────────

def _load_token() -> str:
    if TOKEN_FILE.exists():
        t = TOKEN_FILE.read_text().strip()
        if t:
            return t
    t = secrets.token_hex(32)
    TOKEN_FILE.write_text(t + "\n")
    TOKEN_FILE.chmod(0o600)
    print(f"[vault] New auth token written → {TOKEN_FILE}")
    return t

# ── Rate limiter ──────────────────────────────────────────────────────────────

class _RateLimiter:
    def __init__(self):
        self._lock = threading.Lock()
        self._windows: dict = {}

    def allow(self, key: str, limit: int, window: float = 60.0) -> bool:
        now = time.monotonic()
        with self._lock:
            dq = self._windows.setdefault(key, collections.deque())
            while dq and dq[0] < now - window:
                dq.popleft()
            if not dq and key in self._windows:
                pass  # keep for reuse
            if len(dq) >= limit:
                return False
            dq.append(now)
            return True

_limiter = _RateLimiter()

# ── Trash helpers ─────────────────────────────────────────────────────────────

def _secure_delete(path):
    """Overwrite with random bytes, fsync, unlink (best-effort on SSD)."""
    if not path.exists():
        return
    try:
        size = path.stat().st_size
        with open(path, "r+b") as f:
            written = 0
            while written < size:
                n = min(CHUNK, size - written)
                f.write(os.urandom(n))
                written += n
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass
    path.unlink(missing_ok=True)

def _purge_old_trash():
    cutoff = time.time() - TRASH_DAYS * 86400
    for meta_path in list(TRASH_DIR.glob("*.meta")):
        try:
            info = json.loads(meta_path.read_text())
            if info.get("trashed_at", 0) < cutoff:
                _secure_delete(TRASH_DIR / (meta_path.stem + ".enc"))
                meta_path.unlink(missing_ok=True)
        except Exception:
            pass

def _schedule_daily_purge():
    _purge_old_trash()
    t = threading.Timer(86400, _schedule_daily_purge)
    t.daemon = True
    t.start()

# ── SSRF protection ───────────────────────────────────────────────────────────

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Block all HTTP redirects so an attacker can't redirect to an internal URL."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, f"Redirect to {newurl} blocked", headers, fp
        )

_SAFE_OPENER = urllib.request.build_opener(_NoRedirect())

def _validate_url(url: str):
    """Check that URL is http/https with a publicly-routable hostname.
    DNS is resolved once here; urllib resolves again at connect time
    (DNS rebinding window — mitigated by disabling redirects above).
    Returns (ok, error_bytes).
    """
    try:
        p = urllib.parse.urlparse(url)
        if p.scheme not in ("http", "https"):
            return False, b"Only http/https URLs are supported"
        if not p.hostname:
            return False, b"Missing host"
        for info in socket.getaddrinfo(p.hostname, None):
            addr = ipaddress.ip_address(info[4][0])
            if (addr.is_private or addr.is_loopback or
                    addr.is_link_local or addr.is_reserved or addr.is_multicast):
                return False, b"Private or internal addresses are not allowed"
        return True, None
    except socket.gaierror:
        return False, b"Could not resolve host"
    except Exception as e:
        return False, str(e).encode()

# ── HTTP handler ──────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):

    def _clean_path(self):
        return self.path.split("?")[0].split("#")[0]

    def _reply(self, code: int, ctype: str, body: bytes, extra: dict = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in BASE_HEADERS.items():
            self.send_header(k, v)
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _client_ip(self) -> str:
        return self.client_address[0]

    def _rate_check(self, bucket: str, limit: int) -> bool:
        key = f"{self._client_ip()}:{bucket}"
        if not _limiter.allow(key, limit):
            self._reply(429, "text/plain", b"Too many requests", {"Retry-After": "60"})
            return False
        return True

    def _check_auth(self) -> bool:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self._reply(401, "text/plain", b"Unauthorized")
            return False
        if not hmac.compare_digest(VAULT_TOKEN, auth[7:]):
            self._reply(401, "text/plain", b"Unauthorized")
            return False
        return True

    def _validate_id(self, file_id: str) -> bool:
        try:
            uuid.UUID(file_id)
            return True
        except ValueError:
            self._reply(400, "text/plain", b"Invalid ID")
            return False

    # ── GET ──────────────────────────────────────────────────────────────────

    def do_GET(self):
        p = self._clean_path()

        if p in ("/", "/index.html"):
            if not self._rate_check("page", 30):
                return
            html = INDEX_HTML.read_bytes().replace(
                b"__VAULT_TOKEN__", VAULT_TOKEN.encode(), 1
            )
            self._reply(200, "text/html; charset=utf-8", html,
                        {"Content-Security-Policy": _CSP})
            return

        if p == "/argon2.js":
            if not ARGON2_JS.exists():
                self._reply(404, "text/plain",
                            b"argon2-bundled.min.js not found. "
                            b"See README for the one-time download command.")
                return
            self._reply(200, "application/javascript", ARGON2_JS.read_bytes())
            return

        if not self._check_auth():
            return
        if not self._rate_check("read", 120):
            return

        if p == "/files":
            files = sorted(FILES_DIR.glob("*.enc"), key=lambda f: -f.stat().st_mtime)
            self._reply(200, "application/json",
                        json.dumps({"files": [f.stem for f in files]}).encode())
        elif p == "/trash":
            self._list_trash()
        elif p.startswith("/file/"):
            self._serve_file(p[6:])
        else:
            self._reply(404, "text/plain", b"Not found")

    def _list_trash(self):
        items = []
        for meta_path in sorted(TRASH_DIR.glob("*.meta"),
                                key=lambda f: -f.stat().st_mtime):
            try:
                info = json.loads(meta_path.read_text())
                items.append({"id": info.get("uuid", meta_path.stem),
                              "trashed_at": info.get("trashed_at", 0)})
            except Exception:
                pass
        self._reply(200, "application/json",
                    json.dumps({"files": items}).encode())

    def _serve_file(self, file_id: str):
        if not self._validate_id(file_id):
            return
        path = FILES_DIR / f"{file_id}.enc"
        if not path.exists():
            path = TRASH_DIR / f"{file_id}.enc"
        if not path.exists():
            self._reply(404, "text/plain", b"Not found")
            return

        total = path.stat().st_size
        range_hdr = self.headers.get("Range", "")

        if range_hdr.startswith("bytes="):
            try:
                spec = range_hdr[6:].split(",")[0].strip().split("-")
                start = int(spec[0]) if spec[0] else 0
                end   = int(spec[1]) if spec[1] else total - 1
                end   = min(end, total - 1)
                if start > end or start >= total:
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{total}")
                    self.end_headers()
                    return
                chunk_len = end - start + 1
                self.send_response(206)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(chunk_len))
                self.send_header("Content-Range", f"bytes {start}-{end}/{total}")
                self.send_header("Accept-Ranges", "bytes")
                for k, v in BASE_HEADERS.items():
                    self.send_header(k, v)
                self.end_headers()
                with open(path, "rb") as f:
                    f.seek(start)
                    remaining = chunk_len
                    while remaining > 0:
                        data = f.read(min(CHUNK, remaining))
                        if not data:
                            break
                        self.wfile.write(data)
                        remaining -= len(data)
                return
            except (ValueError, IndexError):
                pass

        # Full file — stream in chunks
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(total))
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Content-Disposition",
                         f'attachment; filename="{file_id}.enc"')
        for k, v in BASE_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        with open(path, "rb") as f:
            while True:
                data = f.read(CHUNK)
                if not data:
                    break
                self.wfile.write(data)

    # ── POST ─────────────────────────────────────────────────────────────────

    def do_POST(self):
        p = self._clean_path()
        if not self._check_auth():
            return
        if p == "/upload":
            self._upload()
        elif p == "/fetch":
            self._fetch_url()
        elif p.startswith("/trash/") and p.endswith("/restore"):
            self._restore_file(p[7:-8])
        else:
            self._reply(404, "text/plain", b"Not found")

    def _upload(self):
        if not self._rate_check("upload", 10):
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self._reply(400, "text/plain", b"Bad Content-Length")
            return
        if length == 0:
            self._reply(400, "text/plain", b"Empty body")
            return
        if length > MAX_UPLOAD:
            self._reply(413, "text/plain", b"Too large (max 2 GiB)")
            return

        # Client-generated UUID enables AAD binding; fall back to server UUID
        raw_id = self.headers.get("X-File-ID", "").strip()
        try:
            file_id = str(uuid.UUID(raw_id))
        except ValueError:
            file_id = str(uuid.uuid4())

        dest = FILES_DIR / f"{file_id}.enc"
        if dest.exists():
            self._reply(409, "text/plain", b"File ID already exists")
            return

        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=FILES_DIR, suffix=".tmp", delete=False
            ) as tmp:
                tmp_path = tmp.name
                first = True
                remaining = length
                while remaining > 0:
                    chunk = self.rfile.read(min(CHUNK, remaining))
                    if not chunk:
                        break
                    if first:
                        if len(chunk) < 4 or chunk[:4] != b"ENCF":
                            self.close_connection = True
                            self._reply(400, "text/plain",
                                        b"Invalid format (missing ENCF magic bytes)")
                            return
                        first = False
                    tmp.write(chunk)
                    remaining -= len(chunk)

            if remaining > 0:
                self.close_connection = True
                self._reply(400, "text/plain", b"Incomplete upload")
                return

            os.rename(tmp_path, str(dest))
            tmp_path = None  # rename succeeded — don't delete in finally

            # Randomize mtime so forensic analysis can't read upload timestamps
            mtime = time.time() - random.uniform(0, 90 * 86400)
            os.utime(dest, (mtime, mtime))

            self._reply(201, "application/json",
                        json.dumps({"id": file_id}).encode())

        except Exception as e:
            self._reply(500, "text/plain", f"Upload failed: {e}".encode())
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    def _fetch_url(self):
        if not self._rate_check("fetch", 10):
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self._reply(400, "text/plain", b"Bad Content-Length")
            return
        if length == 0 or length > 4096:
            self._reply(400, "text/plain", b"URL missing or too long")
            return

        url = self.rfile.read(length).decode("utf-8", errors="replace").strip()
        ok, err = _validate_url(url)
        if not ok:
            self._reply(400, "text/plain", err)
            return

        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; Vault/1.0)"},
            )
            with _SAFE_OPENER.open(req, timeout=60) as resp:
                declared = int(resp.headers.get("Content-Length") or 0)
                if declared > MAX_FETCH:
                    self._reply(413, "text/plain",
                                b"Remote file too large (max 500 MB)")
                    return
                data = resp.read(MAX_FETCH + 1)
                if len(data) > MAX_FETCH:
                    self._reply(413, "text/plain",
                                b"Remote file too large (max 500 MB)")
                    return

                mime = (resp.headers.get("Content-Type") or
                        "application/octet-stream").split(";")[0].strip()

                name = ""
                cd = resp.headers.get("Content-Disposition") or ""
                if "filename=" in cd:
                    name = cd.split("filename=")[-1].strip().strip("\"'")
                if not name:
                    name = urllib.parse.urlparse(url).path.rstrip("/").split("/")[-1]
                if not name:
                    name = "download"
                name = ("".join(c for c in name
                                if c not in '/\\:*?"<>|').strip() or "download")

                self._reply(200, mime, data,
                            {"X-Filename": urllib.parse.quote(name)})

        except urllib.error.HTTPError as e:
            self._reply(502, "text/plain",
                        f"Remote returned {e.code}: {e.reason}".encode())
        except urllib.error.URLError as e:
            self._reply(502, "text/plain", f"Fetch failed: {e.reason}".encode())
        except TimeoutError:
            self._reply(504, "text/plain", b"Request timed out")
        except Exception as e:
            self._reply(502, "text/plain", f"Error: {e}".encode())

    def _restore_file(self, file_id: str):
        if not self._validate_id(file_id):
            return
        if not self._rate_check("restore", 30):
            return
        src = TRASH_DIR / f"{file_id}.enc"
        if not src.exists():
            self._reply(404, "text/plain", b"Not found in trash")
            return
        dest = FILES_DIR / f"{file_id}.enc"
        if dest.exists():
            self._reply(409, "text/plain", b"UUID already exists in vault")
            return
        try:
            os.rename(str(src), str(dest))
            (TRASH_DIR / f"{file_id}.meta").unlink(missing_ok=True)
        except OSError as e:
            self._reply(500, "text/plain", f"Restore failed: {e}".encode())
            return
        self.send_response(204)
        for k, v in BASE_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()

    # ── DELETE ───────────────────────────────────────────────────────────────

    def do_DELETE(self):
        p = self._clean_path()
        if not self._check_auth():
            return
        if not self._rate_check("delete", 30):
            return
        if p.startswith("/file/"):
            self._delete_file(p[6:])
        elif p.startswith("/trash/"):
            self._permanent_delete(p[7:])
        else:
            self._reply(404, "text/plain", b"Not found")

    def _delete_file(self, file_id: str):
        if not self._validate_id(file_id):
            return
        src = FILES_DIR / f"{file_id}.enc"
        if not src.exists():
            self._reply(404, "text/plain", b"Not found")
            return
        dest      = TRASH_DIR / f"{file_id}.enc"
        meta_path = TRASH_DIR / f"{file_id}.meta"
        if dest.exists():
            self._reply(409, "text/plain", b"Already in trash")
            return
        try:
            os.rename(str(src), str(dest))
            meta_path.write_text(json.dumps({"trashed_at": int(time.time()), "uuid": file_id}))
        except OSError as e:
            self._reply(500, "text/plain", f"Trash failed: {e}".encode())
            return
        self.send_response(204)
        for k, v in BASE_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()

    def _permanent_delete(self, file_id: str):
        if not self._validate_id(file_id):
            return
        if not self._rate_check("trash_del", 30):
            return
        enc  = TRASH_DIR / f"{file_id}.enc"
        meta = TRASH_DIR / f"{file_id}.meta"
        if not enc.exists() and not meta.exists():
            self._reply(404, "text/plain", b"Not found in trash")
            return
        _secure_delete(enc)
        meta.unlink(missing_ok=True)
        self.send_response(204)
        for k, v in BASE_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()

    def log_message(self, fmt, *args):
        pass

# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Encrypted file server")
    ap.add_argument("--host", default="localhost",
                    help="Bind address (default: localhost)")
    ap.add_argument("--port", type=int, default=9000,
                    help="Port number (default: 9000)")
    args = ap.parse_args()

    FILES_DIR.mkdir(exist_ok=True)
    TRASH_DIR.mkdir(exist_ok=True)

    cert = BASE / "cert.pem"
    key  = BASE / "key.pem"
    has_tls = cert.exists() and key.exists()
    is_local = args.host in ("localhost", "127.0.0.1", "::1")

    if not is_local and not has_tls:
        sys.exit(
            "ERROR: Non-localhost binding requires TLS.\n"
            "Place cert.pem and key.pem in the vault directory.\n"
            "See README for Tailscale certificate setup."
        )

    VAULT_TOKEN = _load_token()
    _schedule_daily_purge()

    server = HTTPServer((args.host, args.port), Handler)
    if has_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    else:
        scheme = "http"

    print(f"[vault] Listening on {scheme}://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[vault] Stopped.")
