"""OAuth 2.1 Authorization Server that proxies upstream to Google.

MCP clients (Claude Desktop, mcp-remote, MCP Inspector) talk OAuth + DCR
with this server. This server talks classic Google OAuth with a single
pre-registered Google client. The upstream Google access token is used
server-side to call the Google Ads API; it never leaves the server.
"""

from __future__ import annotations

import logging
import secrets
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlencode

import httpx
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyUrl

logger = logging.getLogger(__name__)

GOOGLE_AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105
GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke"

DEFAULT_SCOPES = [
    "openid",
    "email",
    "https://www.googleapis.com/auth/adwords",
]


class ProxyAuthorizationCode(AuthorizationCode):
    google_access_token: str
    google_refresh_token: str | None = None
    google_expires_at: float


class ProxyRefreshToken(RefreshToken):
    google_refresh_token: str


class _PendingAuthorization:
    __slots__ = (
        "client_id",
        "redirect_uri",
        "redirect_uri_provided_explicitly",
        "mcp_code_challenge",
        "mcp_state",
        "scopes",
        "resource",
        "expires_at",
    )

    def __init__(
        self,
        client_id: str,
        redirect_uri: AnyUrl,
        redirect_uri_provided_explicitly: bool,
        mcp_code_challenge: str,
        mcp_state: str | None,
        scopes: list[str] | None,
        resource: str | None,
        expires_at: float,
    ) -> None:
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.redirect_uri_provided_explicitly = redirect_uri_provided_explicitly
        self.mcp_code_challenge = mcp_code_challenge
        self.mcp_state = mcp_state
        self.scopes = scopes
        self.resource = resource
        self.expires_at = expires_at


class _AccessTokenRecord:
    __slots__ = (
        "mcp_access_token",
        "google_access_token",
        "client_id",
        "scopes",
        "expires_at",
    )

    def __init__(
        self,
        mcp_access_token: str,
        google_access_token: str,
        client_id: str,
        scopes: list[str],
        expires_at: int,
    ) -> None:
        self.mcp_access_token = mcp_access_token
        self.google_access_token = google_access_token
        self.client_id = client_id
        self.scopes = scopes
        self.expires_at = expires_at


class GoogleOAuthProxy(
    OAuthAuthorizationServerProvider[
        ProxyAuthorizationCode, ProxyRefreshToken, AccessToken
    ]
):
    def __init__(
        self,
        google_client_id: str,
        google_client_secret: str,
        callback_url: str,
        upstream_scopes: list[str] | None = None,
        auth_code_ttl: int = 300,
        pending_ttl: int = 600,
        http_timeout_seconds: float = 10.0,
        http_client_factory: (
            Callable[[], httpx.AsyncClient] | None
        ) = None,
    ) -> None:
        self._google_client_id = google_client_id
        self._google_client_secret = google_client_secret
        self._callback_url = callback_url
        self._upstream_scopes = upstream_scopes or DEFAULT_SCOPES
        self._auth_code_ttl = auth_code_ttl
        self._pending_ttl = pending_ttl
        self._http_timeout = http_timeout_seconds
        self._http_client_factory = http_client_factory or (
            lambda: httpx.AsyncClient(timeout=self._http_timeout)
        )

        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._pending: dict[str, _PendingAuthorization] = {}
        self._codes: dict[str, ProxyAuthorizationCode] = {}
        self._access_tokens: dict[str, _AccessTokenRecord] = {}
        self._refresh_tokens: dict[str, ProxyRefreshToken] = {}

    # ------------------------------------------------------------------
    # Dynamic Client Registration
    # ------------------------------------------------------------------
    async def get_client(
        self, client_id: str
    ) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(
        self, client_info: OAuthClientInformationFull
    ) -> None:
        if client_info.client_id is None:
            raise ValueError("client_id must be set")
        logger.info(
            "Registered MCP OAuth client",
            extra={"client_id": client_info.client_id},
        )
        self._clients[client_info.client_id] = client_info

    # ------------------------------------------------------------------
    # Authorize: redirect user to Google
    # ------------------------------------------------------------------
    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        self._gc()
        proxy_state = secrets.token_urlsafe(32)
        assert client.client_id is not None
        self._pending[proxy_state] = _PendingAuthorization(
            client_id=client.client_id,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=(
                params.redirect_uri_provided_explicitly
            ),
            mcp_code_challenge=params.code_challenge,
            mcp_state=params.state,
            scopes=params.scopes,
            resource=params.resource,
            expires_at=time.time() + self._pending_ttl,
        )

        google_params = {
            "response_type": "code",
            "client_id": self._google_client_id,
            "redirect_uri": self._callback_url,
            "scope": " ".join(self._upstream_scopes),
            "state": proxy_state,
            "access_type": "offline",
            "prompt": "consent",
            "include_granted_scopes": "true",
        }
        return f"{GOOGLE_AUTHORIZATION_URL}?{urlencode(google_params)}"

    # ------------------------------------------------------------------
    # Google callback: called by our own /oauth/google/callback route
    # ------------------------------------------------------------------
    async def handle_google_callback(
        self, code: str, state: str
    ) -> str:
        """Exchange Google auth code for tokens, store mapping, return URL
        to redirect the browser back to the MCP client."""
        self._gc()
        pending = self._pending.pop(state, None)
        if pending is None or pending.expires_at < time.time():
            raise AuthorizeError(
                error="invalid_request",
                error_description="Unknown or expired state",
            )

        async with self._http_client_factory() as http:
            resp = await http.post(
                GOOGLE_TOKEN_URL,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": self._google_client_id,
                    "client_secret": self._google_client_secret,
                    "redirect_uri": self._callback_url,
                },
            )
        if resp.status_code >= 400:
            logger.error(
                "Google token exchange failed",
                extra={"status": resp.status_code, "body": resp.text},
            )
            raise AuthorizeError(
                error="server_error",
                error_description="Failed to exchange authorization code",
            )

        payload = resp.json()
        google_access = payload["access_token"]
        google_refresh = payload.get("refresh_token")
        expires_in = int(payload.get("expires_in", 3600))
        granted_scope = payload.get("scope", " ".join(self._upstream_scopes))
        granted_scopes = granted_scope.split()

        mcp_code = secrets.token_urlsafe(32)
        self._codes[mcp_code] = ProxyAuthorizationCode(
            code=mcp_code,
            scopes=pending.scopes or granted_scopes,
            expires_at=time.time() + self._auth_code_ttl,
            client_id=pending.client_id,
            code_challenge=pending.mcp_code_challenge,
            redirect_uri=pending.redirect_uri,
            redirect_uri_provided_explicitly=(
                pending.redirect_uri_provided_explicitly
            ),
            resource=pending.resource,
            google_access_token=google_access,
            google_refresh_token=google_refresh,
            google_expires_at=time.time() + expires_in,
        )

        return construct_redirect_uri(
            str(pending.redirect_uri),
            code=mcp_code,
            state=pending.mcp_state,
        )

    # ------------------------------------------------------------------
    # Authorization code exchange
    # ------------------------------------------------------------------
    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> ProxyAuthorizationCode | None:
        self._gc()
        code = self._codes.get(authorization_code)
        if code is None or code.client_id != client.client_id:
            return None
        return code

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: ProxyAuthorizationCode,
    ) -> OAuthToken:
        code = self._codes.pop(authorization_code.code, None)
        if code is None:
            raise TokenError(
                error="invalid_grant",
                error_description="authorization code does not exist",
            )

        mcp_access = secrets.token_urlsafe(32)
        expires_in = max(1, int(code.google_expires_at - time.time()))
        self._access_tokens[mcp_access] = _AccessTokenRecord(
            mcp_access_token=mcp_access,
            google_access_token=code.google_access_token,
            client_id=code.client_id,
            scopes=list(code.scopes),
            expires_at=int(code.google_expires_at),
        )

        mcp_refresh: str | None = None
        if code.google_refresh_token:
            mcp_refresh = secrets.token_urlsafe(32)
            self._refresh_tokens[mcp_refresh] = ProxyRefreshToken(
                token=mcp_refresh,
                client_id=code.client_id,
                scopes=list(code.scopes),
                expires_at=None,
                google_refresh_token=code.google_refresh_token,
            )

        return OAuthToken(
            access_token=mcp_access,
            token_type="Bearer",
            expires_in=expires_in,
            scope=" ".join(code.scopes),
            refresh_token=mcp_refresh,
        )

    # ------------------------------------------------------------------
    # Refresh token flow
    # ------------------------------------------------------------------
    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> ProxyRefreshToken | None:
        rt = self._refresh_tokens.get(refresh_token)
        if rt is None or rt.client_id != client.client_id:
            return None
        return rt

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: ProxyRefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        rt = self._refresh_tokens.get(refresh_token.token)
        if rt is None:
            raise TokenError(
                error="invalid_grant",
                error_description="refresh token does not exist",
            )

        async with self._http_client_factory() as http:
            resp = await http.post(
                GOOGLE_TOKEN_URL,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": rt.google_refresh_token,
                    "client_id": self._google_client_id,
                    "client_secret": self._google_client_secret,
                },
            )
        if resp.status_code >= 400:
            self._refresh_tokens.pop(refresh_token.token, None)
            logger.warning(
                "Google refresh failed; invalidating refresh token",
                extra={"status": resp.status_code},
            )
            raise TokenError(
                error="invalid_grant",
                error_description="refresh failed upstream",
            )

        payload = resp.json()
        google_access = payload["access_token"]
        expires_in = int(payload.get("expires_in", 3600))
        # Google rarely rotates refresh tokens; keep the old one if absent.
        new_google_refresh = payload.get(
            "refresh_token", rt.google_refresh_token
        )

        mcp_access = secrets.token_urlsafe(32)
        self._access_tokens[mcp_access] = _AccessTokenRecord(
            mcp_access_token=mcp_access,
            google_access_token=google_access,
            client_id=rt.client_id,
            scopes=list(scopes),
            expires_at=int(time.time() + expires_in),
        )

        # Rotate our refresh token.
        self._refresh_tokens.pop(refresh_token.token, None)
        new_mcp_refresh = secrets.token_urlsafe(32)
        self._refresh_tokens[new_mcp_refresh] = ProxyRefreshToken(
            token=new_mcp_refresh,
            client_id=rt.client_id,
            scopes=list(scopes),
            expires_at=None,
            google_refresh_token=new_google_refresh,
        )

        return OAuthToken(
            access_token=mcp_access,
            token_type="Bearer",
            expires_in=expires_in,
            scope=" ".join(scopes),
            refresh_token=new_mcp_refresh,
        )

    # ------------------------------------------------------------------
    # Resource-server side: verify our access token, return upstream one
    # ------------------------------------------------------------------
    async def load_access_token(self, token: str) -> AccessToken | None:
        record = self._access_tokens.get(token)
        if record is None:
            return None
        if record.expires_at < int(time.time()):
            self._access_tokens.pop(token, None)
            return None
        # Return the upstream Google access token so downstream code
        # (utils.py `_create_credentials`) can call Google Ads API with it.
        return AccessToken(
            token=record.google_access_token,
            client_id=record.client_id,
            scopes=list(record.scopes),
            expires_at=record.expires_at,
        )

    # ------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------
    async def revoke_token(
        self,
        token: AccessToken | ProxyRefreshToken,
    ) -> None:
        if isinstance(token, AccessToken):
            self._access_tokens.pop(token.token, None)
        else:
            rt = self._refresh_tokens.pop(token.token, None)
            if rt is None:
                return
            # Best-effort revoke upstream.
            try:
                async with self._http_client_factory() as http:
                    await http.post(
                        GOOGLE_REVOKE_URL,
                        data={"token": rt.google_refresh_token},
                    )
            except Exception:
                logger.exception("Google refresh-token revoke failed")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _gc(self) -> None:
        now = time.time()
        now_int = int(now)
        self._pending = {
            k: v for k, v in self._pending.items() if v.expires_at >= now
        }
        self._codes = {
            k: v for k, v in self._codes.items() if v.expires_at >= now
        }
        self._access_tokens = {
            k: v
            for k, v in self._access_tokens.items()
            if v.expires_at >= now_int
        }

    # For tests / introspection only.
    def _debug_state(self) -> dict[str, Any]:
        return {
            "clients": len(self._clients),
            "pending": len(self._pending),
            "codes": len(self._codes),
            "access_tokens": len(self._access_tokens),
            "refresh_tokens": len(self._refresh_tokens),
        }
