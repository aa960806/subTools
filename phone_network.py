"""Resolve one explicit network configuration for an entire login batch."""
from __future__ import annotations

import sys
import re
from urllib.parse import urlsplit

from reauth_proxy import normalize_proxy


NETWORK_MODES = {"system": "系统代理", "direct": "直连", "custom": "自定义代理"}
NETWORK_HINTS = {
    "system": "开始时读取 Windows 静态代理，整批统一使用；系统未启用代理时直连。自动代理脚本需改用自定义代理。",
    "direct": "登录、邮箱、短信和换票均直连，不使用系统或环境代理。已保存的自定义地址会保留。",
    "custom": "登录、邮箱、短信和换票统一使用下方地址；完整 URL 以自身协议为准。",
}


def _read_windows_proxy() -> dict:
    if sys.platform != "win32":
        raise ValueError("系统代理读取仅支持 Windows，请选择直连或自定义代理。")
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as key:
            def read(name, default=None):
                try:
                    return winreg.QueryValueEx(key, name)[0]
                except FileNotFoundError:
                    return default

            result = {"enabled": bool(read("ProxyEnable", 0)),
                      "server": read("ProxyServer", ""),
                      "pac": bool(read("AutoConfigURL", "")),
                      "auto_detect": bool(read("AutoDetect", 0))}
            try:
                with winreg.OpenKey(key, "Connections") as connections:
                    data = winreg.QueryValueEx(connections, "DefaultConnectionSettings")[0]
                if not isinstance(data, bytes) or len(data) < 12:
                    raise ValueError("Windows 代理配置不完整，请检查系统设置或使用自定义代理。")
                flags = int.from_bytes(data[8:12], "little")
                # Windows also stores automatic proxy detection in this blob.
                result["pac"] = result["pac"] or bool(flags & 4)
                result["auto_detect"] = result["auto_detect"] or bool(flags & 8)
            except FileNotFoundError:
                pass
            return result
    except OSError:
        raise ValueError("无法读取 Windows 系统代理，请选择直连或填写自定义代理。") from None


def system_proxy() -> str:
    if sys.platform != "win32":
        import os
        return normalize_proxy(os.environ.get("HTTPS_PROXY") or os.environ.get("ALL_PROXY") or os.environ.get("HTTP_PROXY") or "") or ""
    config = _read_windows_proxy()
    if config["pac"] or config["auto_detect"]:
        # httpx cannot share Chrome's PAC/WPAD evaluation. Never silently give
        # the browser and token/SMS clients different network paths.
        raise ValueError("系统使用自动代理脚本或自动检测，无法统一网络；请选择自定义代理并填写实际代理地址，或选择直连。")
    if not config["enabled"]:
        return ""
    server = str(config["server"] or "").strip()
    if not server:
        raise ValueError("Windows 已开启代理但地址为空，请修正系统设置或使用自定义代理。")
    try:
        if not re.match(r"^(?:https?|socks|ftp)\s*=", server, re.IGNORECASE):
            return normalize_proxy(server) or ""
        proxies = {}
        for entry in server.split(";"):
            if not entry.strip():
                continue
            protocol, value = entry.strip().split("=", 1)
            protocol, value = protocol.strip().lower(), value.strip()
            if protocol in proxies or not value:
                raise ValueError
            # Windows `https=host:port` denotes the destination protocol, not
            # TLS to the proxy; its normal transport is HTTP CONNECT.
            proxies[protocol] = normalize_proxy(value, default_scheme="socks5" if protocol == "socks" else "http")
        selected = proxies.get("https") or proxies.get("http") or proxies.get("socks")
        if not selected:
            raise ValueError
        if proxies.get("http") and proxies.get("https") and proxies["http"] != proxies["https"]:
            raise ValueError
        return selected
    except ValueError:
        raise ValueError("系统代理地址无效或按协议使用不同地址；请填写一个自定义代理，以统一登录、邮箱和 token 请求网络。") from None


def resolve_phone_proxy(mode: str, value: str = "", scheme: str = "http") -> str:
    if mode == "direct":
        return ""
    if mode == "system":
        return system_proxy()
    if mode != "custom":
        raise ValueError("请选择系统代理、直连或自定义代理。")
    proxy = normalize_proxy(value, default_scheme=scheme)
    if not proxy:
        raise ValueError("请填写代理地址，或选择系统代理／直连。")
    return proxy


def network_description(source: str, proxy: str) -> str:
    effective = f"{urlsplit(proxy).scheme.upper()} 代理" if proxy else "直连（未使用代理）"
    return f"{NETWORK_MODES.get(source, '指定网络')} → {effective}"
