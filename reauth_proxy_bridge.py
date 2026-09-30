"""Temporary authenticated loopback HTTP proxy for Chromium's SOCKS5 support.

Chromium does not implement SOCKS5 username/password authentication. This
bridge performs the SOCKS handshake and otherwise tunnels bytes unchanged;
TLS remains end-to-end between the browser and the destination.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hmac
import ipaddress
import secrets
import select
import socket
import socketserver
import threading
from urllib.parse import unquote, urlsplit

from reauth_proxy import normalize_proxy, playwright_proxy


def _read_exact(sock: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise OSError("Proxy connection closed")
        result.extend(chunk)
    return bytes(result)


def _authority(value: str, default_port: int | None = None) -> tuple[str, int]:
    parsed = urlsplit("//" + value)
    if (not parsed.hostname or parsed.username is not None or parsed.password is not None
            or parsed.path or parsed.query or parsed.fragment
            or any(ord(char) <= 32 or ord(char) == 127 for char in value)):
        raise ValueError("Invalid proxy target")
    port = parsed.port if parsed.port is not None else default_port
    if port is None or not 1 <= port <= 65535:
        raise ValueError("Invalid proxy target")
    host = parsed.hostname.encode("idna").decode("ascii")
    if not host or len(host.encode("ascii")) > 255:
        raise ValueError("Invalid proxy target")
    return host, port


class _ProxyServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = False

    def handle_error(self, request, client_address):
        # Never let socket failures print a traceback containing proxy details.
        pass


class _ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        bridge = self.server.bridge
        local = self.request
        upstream = None
        if not bridge._register(local):
            return
        response_started = False
        try:
            local.settimeout(10)
            data = bytearray()
            while b"\r\n\r\n" not in data:
                chunk = local.recv(4096)
                if not chunk:
                    return
                data.extend(chunk)
                if len(data) > 65536:
                    raise ValueError("Proxy headers too large")
            header, remaining = bytes(data).split(b"\r\n\r\n", 1)
            lines = header.decode("iso-8859-1").split("\r\n")
            method, target, version = lines[0].split(" ")
            if version not in {"HTTP/1.0", "HTTP/1.1"}:
                raise ValueError("Invalid HTTP version")
            headers = []
            auth = []
            for line in lines[1:]:
                name, value = line.split(":", 1)
                if not name or name.strip() != name:
                    raise ValueError("Invalid proxy header")
                if name.lower() == "proxy-authorization":
                    auth.append(value.strip())
                elif name.lower() not in {"proxy-connection", "connection"}:
                    headers.append((name, value.strip()))
            if len(auth) != 1 or not hmac.compare_digest(auth[0], bridge._expected_auth):
                local.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\n'
                              b'Proxy-Authenticate: Basic realm="local-proxy"\r\n'
                              b'Content-Length: 0\r\nConnection: close\r\n\r\n')
                return
            if method == "CONNECT":
                host, port = _authority(target)
            else:
                parsed = urlsplit(target)
                if parsed.scheme != "http" or parsed.fragment:
                    raise ValueError("Invalid HTTP proxy target")
                host, port = _authority(parsed.netloc, 80)
            upstream = bridge._connect(host, port)
            if method == "CONNECT":
                local.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                response_started = True
                if remaining:
                    upstream.sendall(remaining)
            else:
                path = parsed.path or "/"
                if parsed.query:
                    path += "?" + parsed.query
                request = f"{method} {path} {version}\r\n"
                request += "".join(f"{name}: {value}\r\n" for name, value in headers)
                # A separate upstream connection is opened for each HTTP request.
                request += "Connection: close\r\n\r\n"
                upstream.sendall(request.encode("iso-8859-1") + remaining)
                response_started = True
            local.settimeout(None)
            upstream.settimeout(None)
            while not bridge._stopped.is_set():
                readable, _, _ = select.select([local, upstream], [], [], 0.5)
                for source in readable:
                    chunk = source.recv(65536)
                    if not chunk:
                        return
                    target_socket = upstream if source is local else local
                    target_socket.sendall(chunk)
        except (OSError, ValueError, UnicodeError):
            if not response_started:
                try:
                    local.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                except OSError:
                    pass
        finally:
            bridge._release(local)
            if upstream is not None:
                bridge._release(upstream)


class SocksBrowserBridge:
    """One browser lifetime; random local authentication and bounded cleanup."""

    def __init__(self, proxy: str):
        parsed = urlsplit(normalize_proxy(proxy) or "")
        if parsed.scheme != "socks5" or not parsed.username:
            raise ValueError("SOCKS5 authentication is required for this bridge")
        self._host = parsed.hostname
        self._port = parsed.port or 1080
        self._user = unquote(parsed.username).encode("utf-8")
        self._password = unquote(parsed.password).encode("utf-8")
        self._stopped = threading.Event()
        self._lock = threading.Lock()
        self._sockets: set[socket.socket] = set()
        self._server = _ProxyServer(("127.0.0.1", 0), _ProxyHandler)
        self._server.bridge = self
        user, password = secrets.token_urlsafe(18), secrets.token_urlsafe(24)
        self._expected_auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        self.config = {"server": f"http://127.0.0.1:{self._server.server_address[1]}",
                       "username": user, "password": password,
                       "bypass": "localhost,127.0.0.1,[::1]"}
        self._worker = threading.Thread(target=self._server.serve_forever,
                                        kwargs={"poll_interval": 0.1}, daemon=True)
        self._worker.start()

    def _register(self, sock: socket.socket) -> bool:
        with self._lock:
            if not self._stopped.is_set():
                self._sockets.add(sock)
                return True
        sock.close()
        return False

    def _release(self, sock: socket.socket):
        with self._lock:
            self._sockets.discard(sock)
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()

    def _connect(self, host: str, port: int) -> socket.socket:
        sock = socket.create_connection((self._host, self._port), timeout=10)
        if not self._register(sock):
            raise OSError("Proxy stopped")
        try:
            sock.sendall(b"\x05\x01\x02")
            if _read_exact(sock, 2) != b"\x05\x02":
                raise OSError("SOCKS authentication unavailable")
            sock.sendall(bytes([1, len(self._user)]) + self._user
                         + bytes([len(self._password)]) + self._password)
            if _read_exact(sock, 2) != b"\x01\x00":
                raise OSError("SOCKS authentication failed")
            try:
                address = ipaddress.ip_address(host)
                destination = bytes([1 if address.version == 4 else 4]) + address.packed
            except ValueError:
                encoded = host.encode("idna")
                destination = bytes([3, len(encoded)]) + encoded
            sock.sendall(b"\x05\x01\x00" + destination + port.to_bytes(2, "big"))
            reply = _read_exact(sock, 4)
            if reply[:3] != b"\x05\x00\x00":
                raise OSError("SOCKS connection failed")
            if reply[3] == 1:
                length = 4
            elif reply[3] == 4:
                length = 16
            elif reply[3] == 3:
                length = _read_exact(sock, 1)[0]
            else:
                raise OSError("Invalid SOCKS response")
            _read_exact(sock, length + 2)
            return sock
        except Exception:
            self._release(sock)
            raise

    def close(self):
        if self._stopped.is_set():
            return
        self._stopped.set()
        with self._lock:
            sockets = list(self._sockets)
        for sock in sockets:
            self._release(sock)
        self._server.shutdown()
        self._server.server_close()
        self._worker.join(timeout=1)


@contextmanager
def browser_proxy_context(proxy: str | None):
    canonical = normalize_proxy(proxy)
    if canonical is None:
        yield None
        return
    parsed = urlsplit(canonical)
    if parsed.scheme != "socks5" or parsed.username is None:
        yield playwright_proxy(canonical)
        return
    bridge = SocksBrowserBridge(canonical)
    try:
        yield bridge.config
    finally:
        bridge.close()
