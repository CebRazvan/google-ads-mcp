"""Tests for the GoogleOAuthProxy authorization-server provider."""

from __future__ import annotations

import base64
import hashlib
import time
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from ads_mcp.oauth_proxy import (
    GOOGLE_TOKEN_URL,
    GoogleOAuthProxy,
    ProxyAuthorizationCode,
    _AccessTokenRecord,
)
from mcp.server.auth.provider import (
    AuthorizationParams,
    AuthorizeError,
)
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl

CLIENT_REDIRECT = "http://localhost:6274/oauth/callback"
OUR_CALLBACK = "http://localhost:8000/oauth/google/callback"


def _pkce_pair() -> tuple[str, str]:
    verifier = "verifier-" + "x" * 50
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


async def _register(proxy: GoogleOAuthProxy) -> OAuthClientInformationFull:
    client = OAuthClientInformationFull(
        client_id="mcp-client-1",
        client_secret="mcp-secret-1",
        redirect_uris=[AnyUrl(CLIENT_REDIRECT)],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        token_endpoint_auth_method="client_secret_post",
        scope="https://www.googleapis.com/auth/adwords",
    )
    await proxy.register_client(client)
    return client


def _proxy_with_handler(
    handler: Callable[[httpx.Request], httpx.Response],
) -> GoogleOAuthProxy:
    return GoogleOAuthProxy(
        google_client_id="upstream-client",
        google_client_secret="upstream-secret",
        callback_url=OUR_CALLBACK,
        upstream_scopes=["https://www.googleapis.com/auth/adwords"],
        http_client_factory=lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ),
    )


@pytest.mark.asyncio
async def test_full_authorization_code_flow() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == GOOGLE_TOKEN_URL
        body = dict(
            item.split("=", 1)
            for item in request.content.decode().split("&")
        )
        assert body["grant_type"] == "authorization_code"
        assert body["code"] == "google-code-xyz"
        assert body["client_id"] == "upstream-client"
        assert body["client_secret"] == "upstream-secret"
        return httpx.Response(
            200,
            json={
                "access_token": "google-access-AAA",
                "refresh_token": "google-refresh-RRR",
                "expires_in": 3600,
                "token_type": "Bearer",
                "scope": "https://www.googleapis.com/auth/adwords",
            },
        )

    proxy = _proxy_with_handler(handler)
    client = await _register(proxy)
    _verifier, challenge = _pkce_pair()

    redirect = await proxy.authorize(
        client,
        AuthorizationParams(
            state="client-state",
            scopes=["https://www.googleapis.com/auth/adwords"],
            code_challenge=challenge,
            redirect_uri=AnyUrl(CLIENT_REDIRECT),
            redirect_uri_provided_explicitly=True,
            resource=None,
        ),
    )
    assert redirect.startswith(
        "https://accounts.google.com/o/oauth2/v2/auth?"
    )
    proxy_state = [
        part.split("=", 1)[1]
        for part in redirect.split("?", 1)[1].split("&")
        if part.startswith("state=")
    ][0]

    final_redirect = await proxy.handle_google_callback(
        code="google-code-xyz", state=proxy_state
    )
    assert final_redirect.startswith(CLIENT_REDIRECT + "?")
    assert "state=client-state" in final_redirect
    mcp_code = [
        part.split("=", 1)[1]
        for part in final_redirect.split("?", 1)[1].split("&")
        if part.startswith("code=")
    ][0]

    auth_code = await proxy.load_authorization_code(client, mcp_code)
    assert auth_code is not None
    assert auth_code.code_challenge == challenge

    tokens = await proxy.exchange_authorization_code(client, auth_code)
    assert tokens.access_token
    assert tokens.refresh_token
    assert tokens.token_type == "Bearer"

    at = await proxy.load_access_token(tokens.access_token)
    assert at is not None
    assert at.token == "google-access-AAA"
    assert at.scopes == ["https://www.googleapis.com/auth/adwords"]


@pytest.mark.asyncio
async def test_refresh_token_flow() -> None:
    exchanges: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = dict(
            item.split("=", 1)
            for item in request.content.decode().split("&")
        )
        exchanges.append(body)
        if body["grant_type"] == "authorization_code":
            return httpx.Response(
                200,
                json={
                    "access_token": "google-A1",
                    "refresh_token": "google-R1",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                },
            )
        return httpx.Response(
            200,
            json={
                "access_token": "google-A2",
                "expires_in": 3600,
                "token_type": "Bearer",
            },
        )

    proxy = _proxy_with_handler(handler)
    client = await _register(proxy)
    _, challenge = _pkce_pair()

    redirect = await proxy.authorize(
        client,
        AuthorizationParams(
            state=None,
            scopes=["https://www.googleapis.com/auth/adwords"],
            code_challenge=challenge,
            redirect_uri=AnyUrl(CLIENT_REDIRECT),
            redirect_uri_provided_explicitly=True,
            resource=None,
        ),
    )
    proxy_state = [
        p.split("=", 1)[1]
        for p in redirect.split("?", 1)[1].split("&")
        if p.startswith("state=")
    ][0]

    await proxy.handle_google_callback(code="g-code", state=proxy_state)
    mcp_code = next(iter(proxy._codes))
    auth_code = await proxy.load_authorization_code(client, mcp_code)
    assert auth_code is not None
    first = await proxy.exchange_authorization_code(client, auth_code)
    assert first.refresh_token is not None

    loaded_rt = await proxy.load_refresh_token(client, first.refresh_token)
    assert loaded_rt is not None
    second = await proxy.exchange_refresh_token(
        client, loaded_rt, ["https://www.googleapis.com/auth/adwords"]
    )
    assert second.access_token != first.access_token
    assert second.refresh_token is not None
    assert second.refresh_token != first.refresh_token

    assert (
        await proxy.load_refresh_token(client, first.refresh_token) is None
    )

    at = await proxy.load_access_token(second.access_token)
    assert at is not None and at.token == "google-A2"

    assert [e["grant_type"] for e in exchanges] == [
        "authorization_code",
        "refresh_token",
    ]


@pytest.mark.asyncio
async def test_unknown_state_rejected() -> None:
    proxy = _proxy_with_handler(
        lambda req: httpx.Response(500)
    )
    with pytest.raises(AuthorizeError):
        await proxy.handle_google_callback(code="x", state="nope")


@pytest.mark.asyncio
async def test_expired_access_token_returns_none() -> None:
    proxy = _proxy_with_handler(lambda req: httpx.Response(500))
    client = await _register(proxy)
    proxy._access_tokens["tok-1"] = _AccessTokenRecord(
        mcp_access_token="tok-1",
        google_access_token="g",
        client_id=client.client_id or "",
        scopes=["https://www.googleapis.com/auth/adwords"],
        expires_at=int(time.time()) - 5,
    )
    assert await proxy.load_access_token("tok-1") is None


@pytest.mark.asyncio
async def test_load_authorization_code_wrong_client() -> None:
    proxy = _proxy_with_handler(lambda req: httpx.Response(500))
    a = await _register(proxy)
    b = OAuthClientInformationFull(
        client_id="other",
        client_secret="s",
        redirect_uris=[AnyUrl(CLIENT_REDIRECT)],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        token_endpoint_auth_method="client_secret_post",
    )
    await proxy.register_client(b)

    proxy._codes["code-a"] = ProxyAuthorizationCode(
        code="code-a",
        scopes=["https://www.googleapis.com/auth/adwords"],
        expires_at=time.time() + 60,
        client_id=a.client_id or "",
        code_challenge="x" * 43,
        redirect_uri=AnyUrl(CLIENT_REDIRECT),
        redirect_uri_provided_explicitly=True,
        resource=None,
        google_access_token="ga",
        google_refresh_token=None,
        google_expires_at=time.time() + 3600,
    )
    assert await proxy.load_authorization_code(b, "code-a") is None
    assert await proxy.load_authorization_code(a, "code-a") is not None


@pytest.mark.asyncio
async def test_upstream_token_failure_surfaces_as_authorize_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "invalid_grant"})

    proxy = _proxy_with_handler(handler)
    client = await _register(proxy)
    _, challenge = _pkce_pair()
    redirect = await proxy.authorize(
        client,
        AuthorizationParams(
            state="s",
            scopes=None,
            code_challenge=challenge,
            redirect_uri=AnyUrl(CLIENT_REDIRECT),
            redirect_uri_provided_explicitly=True,
            resource=None,
        ),
    )
    proxy_state = [
        p.split("=", 1)[1]
        for p in redirect.split("?", 1)[1].split("&")
        if p.startswith("state=")
    ][0]
    with pytest.raises(AuthorizeError):
        await proxy.handle_google_callback(code="bad", state=proxy_state)


_Any = Any  # silence unused import warning in strict type setups
