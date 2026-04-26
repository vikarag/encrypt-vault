#!/usr/bin/env python3
"""Minimalist encrypted file server. Stores only AES-GCM encrypted blobs.
   Run: python3 server.py [--host HOST] [--port PORT]
"""

import argparse
import ipaddress
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

BASE = Path(__file__).parent
FILES_DIR = BASE / "files"
INDEX_HTML = BASE / "index.html"

NO_CACHE = {"Cache-Control": "no-store", "Pragma": "no-cache"}
MAX_UPLOAD = 2 * 1024 * 1024 * 1024  # 2 GiB
MAX_FETCH  = 500 * 1024 * 1024        # 500 MiB via URL


def _safe_url(url: str):
    """Return (ok, error_bytes). Blocks non-HTTP and private/internal addresses."""
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


class Handler(BaseHTTPRequestHandler):

    def _clean_path(self):
        return self.path.split("?")[0].split("#")[0]

    def _reply(self, code, ctype, body: bytes, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in NO_CACHE.items():
            self.send_header(k, v)
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

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
            self._reply(200, "text/html; charset=utf-8", INDEX_HTML.read_bytes())
        elif p == "/files":
            files = sorted(FILES_DIR.glob("*.enc"), key=lambda f: -f.stat().st_mtime)
            self._reply(200, "application/json",
                        json.dumps({"files": [f.stem for f in files]}).encode())
        elif p.startswith("/file/"):
            self._serve_file(p[6:])
        else:
            self._reply(404, "text/plain", b"Not found")

    def _serve_file(self, file_id: str):
        if not self._validate_id(file_id):
            return
        path = FILES_DIR / f"{file_id}.enc"
        if not path.exists():
            self._reply(404, "text/plain", b"Not found")
            return

        data = path.read_bytes()
        total = len(data)

        # Support Range requests so the frontend can fetch only metadata cheaply
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
                chunk = data[start : end + 1]
                self.send_response(206)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(chunk)))
                self.send_header("Content-Range", f"bytes {start}-{end}/{total}")
                self.send_header("Accept-Ranges", "bytes")
                for k, v in NO_CACHE.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(chunk)
                return
            except (ValueError, IndexError):
                pass

        self._reply(200, "application/octet-stream", data, {
            "Content-Disposition": f'attachment; filename="{file_id}.enc"',
            "Accept-Ranges": "bytes",
        })

    # ── POST ─────────────────────────────────────────────────────────────────

    def do_POST(self):
        p = self._clean_path()
        if p == "/upload":
            self._upload()
        elif p == "/fetch":
            self._fetch_url()
        else:
            self._reply(404, "text/plain", b"Not found")

    def _upload(self):
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
        data = self.rfile.read(length)
        if len(data) < 4 or data[:4] != b"ENCF":
            self._reply(400, "text/plain", b"Invalid format (missing ENCF magic bytes)")
            return
        file_id = str(uuid.uuid4())
        (FILES_DIR / f"{file_id}.enc").write_bytes(data)
        self._reply(201, "application/json", json.dumps({"id": file_id}).encode())

    def _fetch_url(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self._reply(400, "text/plain", b"Bad Content-Length")
            return
        if length == 0 or length > 4096:
            self._reply(400, "text/plain", b"URL missing or too long")
            return

        url = self.rfile.read(length).decode("utf-8", errors="replace").strip()
        ok, err = _safe_url(url)
        if not ok:
            self._reply(400, "text/plain", err)
            return

        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0 (compatible; Vault/1.0)"}
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                declared = int(resp.headers.get("Content-Length") or 0)
                if declared > MAX_FETCH:
                    self._reply(413, "text/plain", b"Remote file too large (max 500 MB)")
                    return
                data = resp.read(MAX_FETCH + 1)
                if len(data) > MAX_FETCH:
                    self._reply(413, "text/plain", b"Remote file too large (max 500 MB)")
                    return

                mime = (resp.headers.get("Content-Type") or "application/octet-stream"
                        ).split(";")[0].strip()

                # Derive filename from Content-Disposition, then URL path
                name = ""
                cd = resp.headers.get("Content-Disposition") or ""
                if "filename=" in cd:
                    name = cd.split("filename=")[-1].strip().strip("\"'")
                if not name:
                    name = urllib.parse.urlparse(url).path.rstrip("/").split("/")[-1]
                if not name:
                    name = "download"
                # Sanitize
                name = "".join(c for c in name if c not in '/\\:*?"<>|').strip() or "download"

                self._reply(200, mime, data,
                            {"X-Filename": urllib.parse.quote(name)})

        except urllib.error.HTTPError as e:
            self._reply(502, "text/plain", f"Remote returned {e.code}: {e.reason}".encode())
        except urllib.error.URLError as e:
            self._reply(502, "text/plain", f"Fetch failed: {e.reason}".encode())
        except TimeoutError:
            self._reply(504, "text/plain", b"Request timed out")
        except Exception as e:
            self._reply(502, "text/plain", f"Error: {e}".encode())

    # ── DELETE ───────────────────────────────────────────────────────────────

    def do_DELETE(self):
        p = self._clean_path()
        if p.startswith("/file/"):
            self._delete_file(p[6:])
        else:
            self._reply(404, "text/plain", b"Not found")

    def _delete_file(self, file_id: str):
        if not self._validate_id(file_id):
            return
        path = FILES_DIR / f"{file_id}.enc"
        if not path.exists():
            self._reply(404, "text/plain", b"Not found")
            return
        path.unlink()
        self.send_response(204)
        for k, v in NO_CACHE.items():
            self.send_header(k, v)
        self.end_headers()

    def log_message(self, fmt, *args):
        pass  # all request logging suppressed


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Encrypted file server")
    ap.add_argument("--host", default="localhost", help="Bind address (default: localhost)")
    ap.add_argument("--port", type=int, default=9000, help="Port (default: 9000)")
    args = ap.parse_args()

    FILES_DIR.mkdir(exist_ok=True)
    server = HTTPServer((args.host, args.port), Handler)

    cert = BASE / "cert.pem"
    key  = BASE / "key.pem"
    if cert.exists() and key.exists():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    else:
        scheme = "http"

    print(f"Vault listening on {scheme}://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
