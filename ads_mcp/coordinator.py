# Copyright 2025 Google LLC All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Module declaring the singleton MCP instance.

The singleton allows other modules to register their tools with the same MCP
server using `@mcp.tool` annotations, thereby 'coordinating' the bootstrapping
of the server.
"""

from __future__ import annotations

import logging
from typing import Literal

import json as _json
from urllib.parse import urlparse as _urlparse

import httpx
from mcp.server.auth import routes as _mcp_auth_routes
from mcp.server.auth.handlers import metadata as _mcp_metadata
from mcp.server.auth.middleware import bearer_auth as _mcp_bearer_auth
from mcp.server.auth.provider import AuthorizeError
from mcp.server.auth.settings import (
    AuthSettings,
    ClientRegistrationOptions,
    RevocationOptions,
)
from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response


def _strip_bare_trailing_slash(url: str) -> str:
    """Drop the trailing slash pydantic AnyHttpUrl adds to bare origins.

    RFC 8414 §3 requires that `issuer` equal the base used to build the
    `/.well-known/oauth-authorization-server` URL. That base is the bare
    origin with no trailing slash (e.g. `https://example.com`), but
    pydantic's AnyHttpUrl normalizes `https://example.com` to
    `https://example.com/` during validation, which strict validators
    (Anthropic's Claude backend) reject and silently fail the OAuth
    `start-auth` step.
    """
    if not isinstance(url, str) or not url.endswith("/"):
        return url
    parsed = _urlparse(url)
    if parsed.path in ("", "/") and not parsed.query and not parsed.fragment:
        return f"{parsed.scheme}://{parsed.netloc}"
    return url


# MCP SDK 1.27.0 advertises only confidential client auth methods in the
# Authorization Server metadata, even though the register handler and the
# MCP spec both support public PKCE clients (token_endpoint_auth_method=
# "none"). Some MCP clients (Claude Web) read this metadata strictly and
# abort OAuth setup before attempting DCR. Patch the metadata builder to
# advertise "none" in addition to the confidential methods.
_original_build_metadata = _mcp_auth_routes.build_metadata


def _build_metadata_with_public_client_support(*args, **kwargs):  # type: ignore[no-untyped-def]
    metadata = _original_build_metadata(*args, **kwargs)
    metadata.token_endpoint_auth_methods_supported = [
        "client_secret_post",
        "client_secret_basic",
        "none",
    ]
    # Match Asana/Linear/Notion: advertise the standard response mode
    # explicitly. Optional per RFC 8414 but all known-working servers
    # publish it, so err on the side of parity.
    if getattr(metadata, "response_modes_supported", None) is None:
        metadata.response_modes_supported = ["query"]
    return metadata


_mcp_auth_routes.build_metadata = _build_metadata_with_public_client_support


# The default 401 shape emitted by MCP SDK 1.27.0 is parseable by the
# reference MCP Python client, but Claude Web's connector bootstrap
# reports `authStatus=token_invalid, authErrorType=unparseable` and
# aborts the OAuth flow before DCR. Empirically, every known-working
# remote OAuth MCP server (Asana, Linear, Notion, Intercom) returns the
# same exact template, which Claude's parser clearly keys on:
#
#   Status: 401
#   Content-Type: application/json
#   WWW-Authenticate:
#       Bearer realm="OAuth",
#              resource_metadata="https://…/.well-known/oauth-protected-resource…",
#              error="invalid_token",
#              error_description="Missing or invalid access token"
#   Body: {"error":"invalid_token","error_description":"Missing or invalid access token"}
#
# Notable versus the SDK default: `realm="OAuth"` is present; parameter
# order is realm → resource_metadata → error → error_description; the
# description is literally "Missing or invalid access token"; body is
# always non-empty. Match that template exactly.
_CLAUDE_COMPAT_DESCRIPTION = "Missing or invalid access token"


async def _send_auth_error_claude_compat(  # type: ignore[no-untyped-def]
    self, send, status_code, error, description
):
    # For 403 (insufficient_scope) keep whatever the SDK gave us — that
    # only happens post-authentication, so Claude's bootstrap parser
    # never sees it in the failing path.
    effective_error = error
    effective_description = description
    if status_code == 401:
        effective_error = "invalid_token"
        effective_description = _CLAUDE_COMPAT_DESCRIPTION

    www_auth_parts: list[str] = ['realm="OAuth"']
    if self.resource_metadata_url:
        www_auth_parts.append(
            f'resource_metadata="{self.resource_metadata_url}"'
        )
    www_auth_parts.append(f'error="{effective_error}"')
    www_auth_parts.append(f'error_description="{effective_description}"')
    www_authenticate = "Bearer " + ", ".join(www_auth_parts)

    body_bytes = _json.dumps(
        {"error": effective_error, "error_description": effective_description},
        separators=(",", ":"),
    ).encode()

    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body_bytes)).encode()),
                (b"www-authenticate", www_authenticate.encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body_bytes})


_mcp_bearer_auth.RequireAuthMiddleware._send_auth_error = (
    _send_auth_error_claude_compat
)


# Normalize bare-origin URLs in AS and RS metadata responses (drop the
# trailing slash pydantic AnyHttpUrl injects into `issuer` and
# `authorization_servers[*]`). Without this, Anthropic's start-auth step
# silently aborts because the returned issuer does not byte-match the
# prefix the client used to fetch /.well-known/oauth-authorization-server.
async def _metadata_handle_normalized(  # type: ignore[no-untyped-def]
    self, request: Request
) -> Response:
    data = self.metadata.model_dump(
        mode="json", by_alias=True, exclude_none=True
    )
    if "issuer" in data:
        data["issuer"] = _strip_bare_trailing_slash(data["issuer"])
    return JSONResponse(
        content=data,
        # Force Anthropic to refetch every start-auth attempt. The SDK
        # default caches for 1 hour, which means any server-side metadata
        # fix is invisible to Claude until the hour rolls over — painful
        # during debugging of the OAuth handshake.
        headers={"Cache-Control": "no-store"},
    )


async def _prm_handle_normalized(  # type: ignore[no-untyped-def]
    self, request: Request
) -> Response:
    data = self.metadata.model_dump(
        mode="json", by_alias=True, exclude_none=True
    )
    servers = data.get("authorization_servers")
    if isinstance(servers, list):
        data["authorization_servers"] = [
            _strip_bare_trailing_slash(s) for s in servers
        ]
    return JSONResponse(
        content=data,
        # Force Anthropic to refetch every start-auth attempt. The SDK
        # default caches for 1 hour, which means any server-side metadata
        # fix is invisible to Claude until the hour rolls over — painful
        # during debugging of the OAuth handshake.
        headers={"Cache-Control": "no-store"},
    )


_mcp_metadata.MetadataHandler.handle = _metadata_handle_normalized
_mcp_metadata.ProtectedResourceMetadataHandler.handle = (
    _prm_handle_normalized
)

from ads_mcp.auth import BearerAuth, TokenVerifier
from ads_mcp.jwt import JWTProvider
from ads_mcp.oauth_proxy import GoogleOAuthProxy
from ads_mcp.settings import (
    BasicAuthSettings,
    BearerAuthSettings,
    FastMcpSettings,
    JwtProviderSettings,
    OAuthProxySettings,
    TokenVerifierSettings,
    google_ads_settings,
)

logger = logging.getLogger(__name__)


def _create_jwt_provider() -> JWTProvider:
    from joserfc import jwk

    settings = JwtProviderSettings()  # type: ignore[call-arg]
    if not settings.private_keys or settings.algorithm is None:
        raise ValueError(
            "JWTProvider cannot be created without private keys and algorithm."
        )

    private_keys = jwk.KeySet.import_key_set({"keys": settings.private_keys})

    return JWTProvider(
        private_keys=private_keys,
        algorithm=settings.algorithm,
        claims=settings.claims,
        token_lifetime=settings.token_lifetime,
    )


def _create_bearer_auth() -> httpx.Auth:
    settings = BearerAuthSettings()
    if settings.token is not None:
        token = settings.token.get_secret_value()
        return BearerAuth(token_provider=lambda: token)
    else:
        return BearerAuth(token_provider=_create_jwt_provider())


def _create_basic_auth() -> httpx.Auth:
    settings: BasicAuthSettings = BasicAuthSettings()  # type: ignore[call-arg]
    return httpx.BasicAuth(
        username=settings.username,
        password=settings.password.get_secret_value(),
    )


def _create_auth(type: Literal["bearer", "basic", "none"]) -> httpx.Auth | None:
    if type == "bearer":
        return _create_bearer_auth()
    elif type == "basic":
        return _create_basic_auth()
    elif type == "none":
        return None
    else:
        raise ValueError(f"Unsupported auth type: {type}")


def _create_token_verifier(
    required_scopes: list[str] | None = None,
) -> TokenVerifier:

    settings = TokenVerifierSettings(required_scopes=required_scopes)
    return TokenVerifier(
        auth=_create_auth(settings.auth),
        url=settings.url,
        method=settings.method,
        required_scopes=settings.required_scopes,
        content_type=settings.content_type,
    )


def _create_oauth_proxy(
    auth_settings: AuthSettings,
    proxy_settings: OAuthProxySettings,
) -> GoogleOAuthProxy:
    # Callback URL is served by this same app. Derive it from the issuer.
    issuer = str(auth_settings.issuer_url).rstrip("/")
    callback_url = issuer + proxy_settings.callback_path
    return GoogleOAuthProxy(
        google_client_id=google_ads_settings.client_id,
        google_client_secret=(
            google_ads_settings.client_secret.get_secret_value()
        ),
        callback_url=callback_url,
        upstream_scopes=proxy_settings.upstream_scopes,
        auth_code_ttl=proxy_settings.auth_code_ttl_seconds,
        pending_ttl=proxy_settings.pending_ttl_seconds,
    )


def _create_mcp_server() -> tuple[FastMCP, GoogleOAuthProxy | None]:
    settings = FastMcpSettings()
    proxy_settings = OAuthProxySettings()

    auth_server_provider: GoogleOAuthProxy | None = None
    token_verifier: TokenVerifier | None = None

    if settings.auth is not None:
        if proxy_settings.enabled:
            # Variant B: this server IS the OAuth AS for MCP clients
            # and proxies upstream to Google.
            # MCP-facing scopes are kept intentionally opaque and separate
            # from the Google scopes this server uses to call the Google Ads
            # API. Advertising the raw Google scope (e.g. the Google Ads
            # scope URL) in MCP metadata caused Claude Web to classify the
            # server as a pre-built Google connector and abort the OAuth
            # flow at "start_error" before ever hitting /register or
            # /authorize. Upstream scopes still flow through
            # GoogleOAuthProxy._upstream_scopes.
            settings.auth = AuthSettings(
                issuer_url=settings.auth.issuer_url,
                resource_server_url=settings.auth.resource_server_url,
                required_scopes=settings.auth.required_scopes,
                client_registration_options=ClientRegistrationOptions(
                    enabled=True,
                    valid_scopes=settings.auth.required_scopes,
                    default_scopes=settings.auth.required_scopes,
                ),
                revocation_options=RevocationOptions(enabled=True),
            )
            auth_server_provider = _create_oauth_proxy(
                settings.auth, proxy_settings
            )
        else:
            token_verifier = _create_token_verifier(
                settings.auth.required_scopes
            )

    settings_dict = settings.model_dump()
    mcp = FastMCP(
        "Google Ads MCP Server",
        auth_server_provider=auth_server_provider,
        token_verifier=token_verifier,
        **settings_dict,
    )
    return mcp, auth_server_provider


mcp, _oauth_proxy = _create_mcp_server()


@mcp.custom_route("/healthz", methods=["GET"])
def healthz(_request: Request) -> Response:
    return JSONResponse({"status": "ok"})


if _oauth_proxy is not None:
    _proxy_settings = OAuthProxySettings()

    @mcp.custom_route(_proxy_settings.callback_path, methods=["GET"])
    async def google_oauth_callback(request: Request) -> Response:
        """Receives the redirect from Google, finalizes the upstream code
        exchange, then redirects the browser back to the MCP client."""
        assert _oauth_proxy is not None  # for type checker

        error = request.query_params.get("error")
        if error is not None:
            desc = request.query_params.get("error_description", error)
            logger.warning("Google OAuth returned error: %s - %s", error, desc)
            return JSONResponse(
                {"error": error, "error_description": desc}, status_code=400
            )

        code = request.query_params.get("code")
        state = request.query_params.get("state")
        if not code or not state:
            return JSONResponse(
                {
                    "error": "invalid_request",
                    "error_description": "Missing code or state",
                },
                status_code=400,
            )

        try:
            redirect_to = await _oauth_proxy.handle_google_callback(
                code=code, state=state
            )
        except AuthorizeError as e:
            return JSONResponse(
                {
                    "error": e.error,
                    "error_description": e.error_description,
                },
                status_code=400,
            )
        except Exception:
            logger.exception("Unexpected error in Google callback")
            return JSONResponse(
                {
                    "error": "server_error",
                    "error_description": "Failed to complete OAuth flow",
                },
                status_code=500,
            )

        return RedirectResponse(
            url=redirect_to,
            status_code=302,
            headers={"Cache-Control": "no-store"},
        )
