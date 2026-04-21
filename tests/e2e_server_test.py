"""End-to-end test: the whole OAuth flow over the ASGI app."""

from __future__ import annotations

import base64
import hashlib
import sys
from collections.abc import Generator
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest


@pytest.fixture
def app_with_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[Any, None, None]:
    monkeypatch.setenv(
        "GOOGLE_ADS_CLIENT_ID", "fake.apps.googleusercontent.com"
    )
    monkeypatch.setenv("GOOGLE_ADS_CLIENT_SECRET", "fake-secret")
    monkeypatch.setenv("GOOGLE_ADS_DEVELOPER_TOKEN", "fake-devtoken")
    monkeypatch.setenv("GOOGLE_ADS_LOGIN_CUSTOMER_ID", "1234567890")
    monkeypatch.setenv("FASTMCP_HOST", "127.0.0.1")
    monkeypatch.setenv("FASTMCP_LOG_LEVEL", "INFO")
    monkeypatch.setenv("SERVER_TRANSPORT", "streamable-http")
    monkeypatch.setenv(
        "FASTMCP_AUTH__ISSUER_URL", "http://127.0.0.1:8000"
    )
    monkeypatch.setenv(
        "FASTMCP_AUTH__RESOURCE_SERVER_URL",
        "http://127.0.0.1:8000/mcp",
    )
    monkeypatch.setenv(
        "FASTMCP_AUTH__REQUIRED_SCOPES",
        '["https://www.googleapis.com/auth/adwords"]',
    )
    monkeypatch.setenv("OAUTH_PROXY_ENABLED", "true")

    for mod in [
        "ads_mcp.coordinator",
        "ads_mcp.oauth_proxy",
        "ads_mcp.settings",
    ]:
        sys.modules.pop(mod, None)

    from ads_mcp import coordinator
    from ads_mcp.oauth_proxy import GOOGLE_TOKEN_URL

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == GOOGLE_TOKEN_URL
        body = dict(
            item.split("=", 1)
            for item in request.content.decode().split("&")
        )
        if body["grant_type"] == "authorization_code":
            return httpx.Response(
                200,
                json={
                    "access_token": "google-AAA",
                    "refresh_token": "google-RRR",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                    "scope": "https://www.googleapis.com/auth/adwords",
                },
            )
        return httpx.Response(400, json={"error": "invalid_grant"})

    assert coordinator._oauth_proxy is not None
    # Swap the proxy's http factory to the mock.
    coordinator._oauth_proxy._http_client_factory = (
        lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        )
    )

    yield coordinator.mcp.streamable_http_app()


@pytest.mark.asyncio
async def test_full_flow_over_http(app_with_proxy: Any) -> None:
    transport = httpx.ASGITransport(app=app_with_proxy)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://127.0.0.1:8000"
    ) as c:
        r = await c.get("/.well-known/oauth-protected-resource/mcp")
        assert r.status_code == 200

        r = await c.get("/.well-known/oauth-authorization-server")
        assert r.status_code == 200

        r = await c.post(
            "/register",
            json={
                "redirect_uris": ["http://localhost:6274/oauth/callback"],
                "client_name": "Test",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "client_secret_post",
            },
        )
        assert r.status_code == 201
        reg = r.json()
        client_id = reg["client_id"]
        client_secret = reg["client_secret"]

        verifier = "v" * 64
        digest = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        r = await c.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": "http://localhost:6274/oauth/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "S1",
                "scope": "https://www.googleapis.com/auth/adwords",
            },
            follow_redirects=False,
        )
        assert r.status_code == 302
        google_url = r.headers["location"]
        assert google_url.startswith(
            "https://accounts.google.com/o/oauth2/v2/auth?"
        )
        google_state = parse_qs(urlparse(google_url).query)["state"][0]

        r = await c.get(
            "/oauth/google/callback",
            params={"code": "google-code", "state": google_state},
            follow_redirects=False,
        )
        assert r.status_code == 302, r.text
        client_redirect = r.headers["location"]
        assert client_redirect.startswith(
            "http://localhost:6274/oauth/callback"
        )
        q = parse_qs(urlparse(client_redirect).query)
        assert q["state"] == ["S1"]
        mcp_code = q["code"][0]

        r = await c.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": mcp_code,
                "redirect_uri": "http://localhost:6274/oauth/callback",
                "client_id": client_id,
                "client_secret": client_secret,
                "code_verifier": verifier,
            },
        )
        assert r.status_code == 200, r.text
        tokens = r.json()
        assert tokens["access_token"]
        assert tokens["refresh_token"]

        r = await c.get("/mcp")
        assert r.status_code == 401
