"""curl_cffi transport adapted from toSub2's tls_transport.py (MIT).

Copyright (c) 2026 poxiao33. See THIRD_PARTY_NOTICES.md.
Only the ordinary HTTPS session transport is used: no security-challenge solver,
profile probing, proxy switching, redirects or automatic request replay.
httpx owns the per-account cookie jar and validates all destinations.
"""
import time

import httpx

from flow_control import AuthFlowError, check_running


class CurlTransport(httpx.BaseTransport):
    def __init__(self, *, proxy, deadline, should_stop):
        from curl_cffi import CurlOpt, requests
        self.deadline, self.should_stop = deadline, should_stop
        self.http = requests.Session(impersonate='chrome', verify=True, trust_env=False,
                                     discard_cookies=True,
                                     curl_options={CurlOpt.PROXY: proxy or '', CurlOpt.NOPROXY: ''})

    def handle_request(self, request):
        from curl_cffi.requests.exceptions import RequestException
        check_running(self.should_stop, self.deadline)
        chunks, size, failure = [], 0, None

        def receive(chunk):
            nonlocal size, failure
            try:
                check_running(self.should_stop, self.deadline)
                size += len(chunk)
                if size > 4 * 1024 * 1024:
                    raise AuthFlowError('needs_interaction', '登录响应过大，已停止协议处理')
                chunks.append(chunk)
                return len(chunk)
            except AuthFlowError as exc:
                failure = exc
                return 0  # Abort libcurl without raising across the C callback.

        # curl supplies a consistent UA for its selected TLS profile and decodes
        # response compression. httpx's UA/encoding defaults must not override it.
        headers = [(k, v) for k, v in request.headers.multi_items()
                   if k.lower() not in ('user-agent', 'accept-encoding')]
        try:
            response = self.http.request(request.method, str(request.url), headers=headers,
                data=request.read() if request.method == 'POST' else None,
                allow_redirects=False, timeout=max(.05, min(15, self.deadline-time.monotonic())),
                content_callback=receive)
        except RequestException:
            if failure:
                raise failure from None
            raise httpx.TransportError('Protocol transport did not confirm the response', request=request) from None
        if failure:
            raise failure
        check_running(self.should_stop, self.deadline)
        headers = [(k, v) for k, v in response.headers.multi_items()
                   if k.lower() not in ('content-encoding', 'content-length', 'transfer-encoding')]
        return httpx.Response(response.status_code, headers=headers, content=b''.join(chunks), request=request)

    def close(self):
        self.http.close()
