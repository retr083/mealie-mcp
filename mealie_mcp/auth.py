"""OAuth 2.1 authorization server backing the MCP endpoint.

Claude registers itself via Dynamic Client Registration and sends the person to
/login. That page redirects to Pocket ID. After the passkey login, the server
links a Mealie API token for that person and exchanges the MCP authorization
code for a bearer token. Tool calls use the linked token, so Mealie applies
that person's household and admin rights.
"""

from __future__ import annotations

import asyncio
import html
import json
import logging
import secrets
import time
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import AnyUrl
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from .config import Settings
from .mealie import fetch_self
from .oidc import PocketID, PocketIDError, emails_match, pkce_pair

log = logging.getLogger(__name__)

AUTH_CODE_TTL = 300
STATE_TTL = 600
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 300


def _redirect_uri_allowed(uri: str, allowed: list[str]) -> bool:
    """Exact match, except loopback hosts where the port is ignored (RFC 8252 s7.3)."""
    u = urlsplit(uri)
    for a in allowed:
        p = urlsplit(a)
        if u.scheme != p.scheme or u.path != p.path:
            continue
        if u.hostname in ("localhost", "127.0.0.1") and p.hostname in ("localhost", "127.0.0.1"):
            if u.hostname == p.hostname:
                return True
            continue
        if u.netloc == p.netloc:
            return True
    return False


class MealieOAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    def __init__(self, settings: Settings):
        self.settings = settings
        self.state_file = Path(settings.mcp_data_dir) / "auth_state.json"
        self._lock = asyncio.Lock()

        self.pocket_id = PocketID(
            str(settings.pocket_id_issuer),
            settings.pocket_id_client_id,
            settings.pocket_id_client_secret,
        )

        # persisted
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.access_tokens: dict[str, AccessToken] = {}
        self.refresh_tokens: dict[str, RefreshToken] = {}
        self.users: dict[str, dict] = {}  # pocket id sub -> mealie link
        # in-memory only (short lived)
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.pending: dict[str, dict] = {}  # login state -> authorize params
        self._failed_logins: dict[str, tuple[int, float]] = {}  # ip -> (count, lock_until)

        self._load()

    # ---------- persistence ----------

    def _load(self) -> None:
        if not self.state_file.exists():
            return
        try:
            raw = json.loads(self.state_file.read_text())
        except Exception:  # corrupt file: start clean rather than crash
            log.exception("Could not read %s, starting with empty auth state", self.state_file)
            return
        self.clients = {k: OAuthClientInformationFull.model_validate(v) for k, v in raw.get("clients", {}).items()}
        self.access_tokens = {k: AccessToken.model_validate(v) for k, v in raw.get("access_tokens", {}).items()}
        self.refresh_tokens = {k: RefreshToken.model_validate(v) for k, v in raw.get("refresh_tokens", {}).items()}
        self.users = dict(raw.get("users", {}))
        self._prune()
        log.info(
            "Loaded auth state: %d clients, %d access tokens, %d refresh tokens, %d linked users",
            len(self.clients), len(self.access_tokens), len(self.refresh_tokens), len(self.users),
        )

    def _save(self) -> None:
        self._prune()
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "clients": {k: v.model_dump(mode="json") for k, v in self.clients.items()},
            "access_tokens": {k: v.model_dump(mode="json") for k, v in self.access_tokens.items()},
            "refresh_tokens": {k: v.model_dump(mode="json") for k, v in self.refresh_tokens.items()},
            "users": self.users,
        }
        tmp = self.state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=1))
        tmp.replace(self.state_file)
        self.state_file.chmod(0o600)

    def _prune(self) -> None:
        now = time.time()
        self.access_tokens = {k: v for k, v in self.access_tokens.items() if not v.expires_at or v.expires_at > now}
        self.refresh_tokens = {k: v for k, v in self.refresh_tokens.items() if not v.expires_at or v.expires_at > now}
        self.auth_codes = {k: v for k, v in self.auth_codes.items() if v.expires_at > now}
        self.pending = {k: v for k, v in self.pending.items() if v["created"] + STATE_TTL > now}

    # ---------- client registration ----------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        for uri in client_info.redirect_uris or []:
            if not _redirect_uri_allowed(str(uri), self.settings.mcp_allowed_redirect_uris):
                raise RegistrationError(
                    "invalid_redirect_uri",
                    f"redirect_uri {uri} is not allowed by this server (see MCP_ALLOWED_REDIRECT_URIS)",
                )
        async with self._lock:
            self.clients[client_info.client_id] = client_info
            self._save()
        log.info("Registered OAuth client %s (%s)", client_info.client_id, client_info.client_name)

    # ---------- authorization ----------

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        # Our own nonce; the client's `state` is stored and echoed back on redirect.
        login_state = secrets.token_urlsafe(32)
        self.pending[login_state] = {
            "created": time.time(),
            "client_id": client.client_id,
            "client_state": params.state,
            "redirect_uri": str(params.redirect_uri),
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "code_challenge": params.code_challenge,
            "scopes": params.scopes or [self.settings.mcp_scope],
            "resource": params.resource,
        }
        return f"{self.settings.public_base}/login?state={login_state}"

    def _client_ip(self, request: Request) -> str:
        fwd = request.headers.get("cf-connecting-ip") or request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def _locked_out(self, ip: str) -> bool:
        count, until = self._failed_logins.get(ip, (0, 0.0))
        return count >= MAX_FAILED_LOGINS and until > time.time()

    def _record_failure(self, ip: str) -> None:
        count, _ = self._failed_logins.get(ip, (0, 0.0))
        count += 1
        lock_until = time.time() + LOCKOUT_SECONDS if count >= MAX_FAILED_LOGINS else 0.0
        self._failed_logins[ip] = (count, lock_until)

    def mealie_token_for(self, subject: str | None) -> str | None:
        if not subject:
            return None
        user = self.users.get(subject) or {}
        token = user.get("mealie_api_token")
        return token or None

    async def start_login(self, request: Request) -> Response:
        self._prune()
        state = request.query_params.get("state", "")
        pending = self.pending.get(state)
        if not pending:
            return HTMLResponse(
                _page("Sign-in link expired", "<p>Start the connection again from Claude.</p>"), status_code=400
            )
        verifier, challenge = pkce_pair()
        pending["oidc_verifier"] = verifier
        try:
            url = await self.pocket_id.authorize_url(self.settings.public_base, state, challenge)
        except PocketIDError as exc:
            log.exception("Pocket ID authorize URL failed")
            return HTMLResponse(_page("Pocket ID unavailable", f"<p>{html.escape(exc.message)}</p>"), status_code=502)
        return RedirectResponse(url, status_code=302)

    async def handle_oidc_callback(self, request: Request) -> Response:
        self._prune()
        state = request.query_params.get("state", "")
        pending = self.pending.get(state)
        if not pending or "oidc_verifier" not in pending:
            return HTMLResponse(
                _page("Sign-in link expired", "<p>Start the connection again from Claude.</p>"), status_code=400
            )
        if request.query_params.get("error"):
            detail = request.query_params.get("error_description") or request.query_params.get("error")
            return HTMLResponse(_page("Pocket ID login was not completed", f"<p>{html.escape(detail or '')}</p>"), status_code=400)
        code = request.query_params.get("code", "")
        if not code:
            return HTMLResponse(_page("Pocket ID login failed", "<p>No authorization code was returned.</p>"), status_code=400)
        try:
            token = await self.pocket_id.exchange(self.settings.public_base, code, pending["oidc_verifier"])
            info = await self.pocket_id.userinfo(token["access_token"])
        except (PocketIDError, KeyError) as exc:
            message = exc.message if isinstance(exc, PocketIDError) else "Pocket ID did not return an access token."
            log.exception("Pocket ID callback failed")
            return HTMLResponse(_page("Pocket ID login failed", f"<p>{html.escape(message)}</p>"), status_code=502)
        subject = str(info.get("sub") or "")
        email = str(info.get("email") or "")
        if not subject or not email:
            return HTMLResponse(
                _page("Pocket ID login failed", "<p>Pocket ID did not return a subject and email.</p>"),
                status_code=502,
            )
        pending["oidc_sub"] = subject
        pending["oidc_email"] = email
        if subject in self.users:
            return self._finish(pending, state)
        return self._link_page(state, email)

    def _link_page(self, state: str, email: str, error: str | None = None) -> Response:
        err_html = f'<p class="err">{html.escape(error)}</p>' if error else ""
        body = f"""
          <p>Signed in as <strong>{html.escape(email)}</strong>.</p>
          <p class="muted">Paste a Mealie API token from that same account
             (Mealie → your user → API Tokens). Tools will act as this user.</p>
          {err_html}
          <form method="post" action="{self.settings.public_base}/link">
            <input type="hidden" name="state" value="{html.escape(state)}">
            <label for="token">Mealie API token</label>
            <input id="token" name="mealie_api_token" type="password" autocomplete="off" autofocus required>
            <button type="submit">Link and allow access</button>
          </form>"""
        return HTMLResponse(_page("Link your Mealie account", body))

    async def handle_link(self, request: Request) -> Response:
        self._prune()
        form = await request.form()
        state = str(form.get("state") or "")
        mealie_token = str(form.get("mealie_api_token") or "").strip()
        pending = self.pending.get(state)
        if not pending or "oidc_sub" not in pending:
            return HTMLResponse(
                _page("Sign-in link expired", "<p>Start the connection again from Claude.</p>"), status_code=400
            )
        email = pending["oidc_email"]
        ip = self._client_ip(request)
        if self._locked_out(ip):
            return HTMLResponse(_page("Too many attempts", "<p>Try again in a few minutes.</p>"), status_code=429)
        if not mealie_token:
            return self._link_page(state, email, error="Paste a Mealie API token.")
        try:
            profile = await fetch_self(str(self.settings.mealie_url), mealie_token)
        except Exception as exc:  # MealieError or unexpected
            self._record_failure(ip)
            log.warning("Mealie token link failed from %s: %s", ip, exc)
            return self._link_page(state, email, error=str(exc))
        if not emails_match(profile.get("email"), email):
            self._record_failure(ip)
            log.warning("Mealie token email did not match Pocket ID email for %s", email)
            return self._link_page(
                state,
                email,
                error="That token belongs to a different Mealie email than this Pocket ID login.",
            )
        async with self._lock:
            self.users[pending["oidc_sub"]] = {
                "email": email,
                "mealie_api_token": mealie_token,
                "mealie_username": profile.get("username") or "",
            }
            self._save()
        self._failed_logins.pop(ip, None)
        log.info("Linked Pocket ID user %s to Mealie user %s", email, profile.get("username"))
        return self._finish(pending, state)

    def _finish(self, pending: dict, state: str) -> Response:
        subject = pending["oidc_sub"]
        self.pending.pop(state, None)
        code = secrets.token_urlsafe(32)
        self.auth_codes[code] = AuthorizationCode(
            code=code,
            client_id=pending["client_id"],
            redirect_uri=AnyUrl(pending["redirect_uri"]),
            redirect_uri_provided_explicitly=pending["redirect_uri_provided_explicitly"],
            expires_at=time.time() + AUTH_CODE_TTL,
            scopes=pending["scopes"],
            code_challenge=pending["code_challenge"],
            resource=pending["resource"],
            subject=subject,
        )
        log.info("Login OK for %s client %s", pending.get("oidc_email"), pending["client_id"])
        return RedirectResponse(
            construct_redirect_uri(pending["redirect_uri"], code=code, state=pending["client_state"]),
            status_code=302,
        )

    # ---------- tokens ----------

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        code = self.auth_codes.get(authorization_code)
        if code and code.client_id == client.client_id and code.expires_at > time.time():
            return code
        return None

    def _issue(self, client_id: str, scopes: list[str], resource: str | None, subject: str | None) -> OAuthToken:
        now = int(time.time())
        access = secrets.token_urlsafe(48)
        refresh = secrets.token_urlsafe(48)
        self.access_tokens[access] = AccessToken(
            token=access,
            client_id=client_id,
            scopes=scopes,
            expires_at=now + self.settings.mcp_access_token_ttl,
            resource=resource,
            subject=subject,
        )
        self.refresh_tokens[refresh] = RefreshToken(
            token=refresh,
            client_id=client_id,
            scopes=scopes,
            expires_at=now + self.settings.mcp_refresh_token_ttl,
            resource=resource,
            subject=subject,
        )
        self._save()
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=self.settings.mcp_access_token_ttl,
            scope=" ".join(scopes),
            refresh_token=refresh,
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        async with self._lock:
            if self.auth_codes.pop(authorization_code.code, None) is None:
                raise TokenError("invalid_grant", "authorization code already used or expired")
            return self._issue(
                client.client_id, authorization_code.scopes, authorization_code.resource, authorization_code.subject
            )

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        tok = self.refresh_tokens.get(refresh_token)
        if tok and tok.client_id == client.client_id and (not tok.expires_at or tok.expires_at > time.time()):
            return tok
        return None

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]
    ) -> OAuthToken:
        async with self._lock:
            # Rotate: the old refresh token dies with this exchange (OAuth 2.1 for public clients).
            if self.refresh_tokens.pop(refresh_token.token, None) is None:
                raise TokenError("invalid_grant", "refresh token already used or revoked")
            return self._issue(
                client.client_id, scopes or refresh_token.scopes, refresh_token.resource, refresh_token.subject
            )

    async def load_access_token(self, token: str) -> AccessToken | None:
        tok = self.access_tokens.get(token)
        if tok and (not tok.expires_at or tok.expires_at > time.time()):
            return tok
        return None

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        async with self._lock:
            self.access_tokens.pop(token.token, None)
            self.refresh_tokens.pop(token.token, None)
            self._save()


def _page(title: str, body: str) -> str:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)}</title>
<style>
:root{{color-scheme:light dark}}
body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:24px;display:flex;justify-content:center;background:#f6f6f4;color:#1b1b1b}}
@media(prefers-color-scheme:dark){{body{{background:#161616;color:#eee}}}}
main{{max-width:420px;width:100%}}
h1{{font-size:1.4rem;margin:0 0 12px}}
p{{line-height:1.45}} .muted{{opacity:.7;font-size:.9rem}} .err{{color:#c62828;font-weight:600}}
code{{font-size:.9em}}
label{{display:block;margin:18px 0 6px;font-weight:600}}
input[type=password]{{width:100%;box-sizing:border-box;padding:12px;font-size:1rem;border:1px solid #8884;border-radius:8px;background:transparent;color:inherit}}
button{{margin-top:16px;width:100%;padding:12px;font-size:1rem;border:0;border-radius:8px;background:#d97757;color:#fff;font-weight:600;cursor:pointer}}
</style></head><body><main><h1>{html.escape(title)}</h1>{body}</main></body></html>"""
