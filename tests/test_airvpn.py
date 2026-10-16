"""AirVPN status API client: retries and errors (httpx mocked, no network)."""

import pytest


async def _status_with(monkeypatch, handler):
    import httpx
    import airbl.airvpn as av
    calls = []
    real = httpx.AsyncClient

    def factory(*a, **kw):
        def h(request):
            calls.append(request)
            return handler(len(calls))
        kw["transport"] = httpx.MockTransport(h)
        return real(*a, **kw)

    monkeypatch.setattr(av.httpx, "AsyncClient", factory)
    monkeypatch.setattr(av.AirVPNClient.fetch_status.retry, "sleep", _no_sleep)
    return av, calls


async def _no_sleep(_):
    return None


async def test_client_error_fails_fast_with_real_error(monkeypatch):
    # tenacity used to retry a 404 for ~90 s and then raise RetryError[...]
    import httpx
    av, calls = await _status_with(monkeypatch, lambda n: httpx.Response(404, text="nope"))
    with pytest.raises(httpx.HTTPStatusError):
        await av.get_airvpn_status()
    assert len(calls) == 1


async def test_server_error_is_retried(monkeypatch):
    import httpx
    av, calls = await _status_with(
        monkeypatch, lambda n: httpx.Response(503) if n < 3 else httpx.Response(200, json={"servers": []}))
    status = await av.get_airvpn_status()
    assert len(calls) == 3 and status.servers == []
