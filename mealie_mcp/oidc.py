"""Pocket ID authorization-code client used by the MCP login page."""

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Any
from urllib.parse import urlencode

import httpx


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def emails_match(left: str | None, right: str | None) -> bool:
    if not left or not right:
        return False
    return left.strip().lower() == right.strip().lower()


class PocketIDError(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class PocketID:
    def __init__(self, issuer: str, client_id: str, client_secret: str):
        self.issuer = issuer.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self._http = httpx.AsyncClient(timeout=20.0)
        self._metadata: dict[str, Any] | None = None

    async def aclose(self) -> None:
        await self._http.aclose()

    def redirect_uri(self, public_base: str) -> str:
        return f"{public_base}/oidc/callback"

    async def metadata(self) -> dict[str, Any]:
        if self._metadata is None:
            try:
                response = await self._http.get(f"{self.issuer}/.well-known/openid-configuration")
                response.raise_for_status()
            except httpx.HTTPError as exc:
                raise PocketIDError(f"Could not read Pocket ID discovery document: {exc}") from exc
            self._metadata = response.json()
        return self._metadata

    async def authorize_url(self, public_base: str, state: str, code_challenge: str) -> str:
        meta = await self.metadata()
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri(public_base),
                "scope": "openid email profile",
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )
        return f"{meta['authorization_endpoint']}?{query}"

    async def exchange(self, public_base: str, code: str, code_verifier: str) -> dict[str, Any]:
        meta = await self.metadata()
        try:
            response = await self._http.post(
                meta["token_endpoint"],
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self.redirect_uri(public_base),
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code_verifier": code_verifier,
                },
            )
        except httpx.HTTPError as exc:
            raise PocketIDError(f"Pocket ID token request failed: {exc}") from exc
        if response.status_code >= 400:
            raise PocketIDError(f"Pocket ID rejected the login code ({response.status_code}).")
        return response.json()

    async def userinfo(self, access_token: str) -> dict[str, Any]:
        meta = await self.metadata()
        try:
            response = await self._http.get(
                meta["userinfo_endpoint"],
                headers={"Authorization": f"Bearer {access_token}"},
            )
        except httpx.HTTPError as exc:
            raise PocketIDError(f"Pocket ID userinfo request failed: {exc}") from exc
        if response.status_code >= 400:
            raise PocketIDError(f"Pocket ID refused userinfo ({response.status_code}).")
        return response.json()
