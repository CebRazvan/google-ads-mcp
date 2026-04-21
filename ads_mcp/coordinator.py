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

import httpx
from mcp.server.auth.provider import AuthorizeError
from mcp.server.auth.settings import (
    AuthSettings,
    ClientRegistrationOptions,
    RevocationOptions,
)
from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

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
            settings.auth = AuthSettings(
                issuer_url=settings.auth.issuer_url,
                resource_server_url=settings.auth.resource_server_url,
                required_scopes=settings.auth.required_scopes,
                client_registration_options=ClientRegistrationOptions(
                    enabled=True,
                    valid_scopes=proxy_settings.upstream_scopes,
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
