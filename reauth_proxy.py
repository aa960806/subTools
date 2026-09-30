"""Shared proxy parsing. Errors never include proxy credentials."""
from __future__ import annotations

import html
import re
from urllib.parse import quote, unquote, urlsplit


_INVALID = "代理格式无效，请使用 IP:端口:用户名:密码、IP:端口或 HTTP/HTTPS/SOCKS5 代理 URL"


def normalize_proxy(value: str | None, *, default_scheme: str = "http") -> str | None:
    raw = html.unescape(str(value or "")).strip()
    if not raw:
        return None
    try:
        if "://" not in raw:
            if default_scheme not in {"http", "https", "socks5"}:
                raise ValueError
            # A bracketed IPv6 literal is allowed; remaining password colons
            # belong to the password, not additional fields.
            match = re.fullmatch(r"(\[[^\]]+\]|[^:\s]+):(\d+)(?::([^:]+):(.*))?", raw)
            if not match:
                raise ValueError
            host, port, user, password = match.groups()
            if user is not None and (not user or not password):
                raise ValueError
            credentials = f"{quote(user, safe='')}:{quote(password, safe='')}@" if user is not None else ""
            raw = f"{default_scheme}://{credentials}{host}:{port}"
        parsed = urlsplit(raw)
        if (parsed.scheme not in {"http", "https", "socks5"} or not parsed.hostname
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
                or any(char.isspace() for char in parsed.hostname)
                or any(char in raw for char in "\r\n\t\\")):
            raise ValueError
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
        hostname = parsed.hostname.encode("idna").decode("ascii")
        if not re.fullmatch(r"[a-zA-Z0-9_.:-]+", hostname):
            raise ValueError
        hostname = f"[{hostname}]" if ":" in hostname else hostname
        auth = ""
        if parsed.username is not None or parsed.password is not None:
            if not parsed.username or not parsed.password:
                raise ValueError
            if re.search(r"%(?![0-9A-Fa-f]{2})", parsed.username + parsed.password):
                raise ValueError
            user = unquote(parsed.username, errors="strict")
            password = unquote(parsed.password, errors="strict")
            if any(char in user + password for char in "\r\n\t"):
                raise ValueError
            if parsed.scheme == "socks5" and (len(user.encode("utf-8")) > 255 or len(password.encode("utf-8")) > 255):
                raise ValueError
            auth = f"{quote(user, safe='')}:{quote(password, safe='')}@"
        return f"{parsed.scheme}://{auth}{hostname}" + (f":{port}" if port is not None else "")
    except (ValueError, UnicodeError):
        raise ValueError(_INVALID) from None


def playwright_proxy(value: str) -> dict[str, str]:
    canonical = normalize_proxy(value)
    if canonical is None:
        raise ValueError(_INVALID)
    parsed = urlsplit(canonical)
    if parsed.scheme == "socks5" and parsed.username is not None:
        raise ValueError("带认证的 SOCKS5 代理需要浏览器本地转接")
    hostname = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    result = {
        "server": f"{parsed.scheme}://{hostname}" + (f":{parsed.port}" if parsed.port is not None else ""),
        "bypass": "localhost,127.0.0.1,[::1]",
    }
    if parsed.username is not None:
        result["username"] = unquote(parsed.username)
        result["password"] = unquote(parsed.password)
    return result


def browser_proxy_context(proxy: str | None):
    """Return a lifetime context for direct proxies or authenticated SOCKS5."""
    from reauth_proxy_bridge import browser_proxy_context as context
    return context(proxy)
