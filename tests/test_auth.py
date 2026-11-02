import unittest
from unittest.mock import AsyncMock, patch

from mealie_mcp.auth import MealieOAuthProvider, _redirect_uri_allowed
from mealie_mcp.config import Settings
from mealie_mcp.oidc import emails_match, pkce_pair


def settings(tmp: str) -> Settings:
    return Settings(
        mealie_url="http://mealie.local",
        public_url="https://mcp.example.com",
        pocket_id_issuer="https://id.example.com",
        pocket_id_client_id="client",
        pocket_id_client_secret="secret",
        mcp_data_dir=tmp,
    )


class OidcHelpers(unittest.TestCase):
    def test_emails_match_is_case_insensitive(self):
        self.assertTrue(emails_match("Ada@Example.com", "ada@example.com"))
        self.assertFalse(emails_match("ada@example.com", "other@example.com"))
        self.assertFalse(emails_match("", "ada@example.com"))

    def test_chatgpt_redirects_are_allowed(self):
        allowed = ["https://claude.ai/api/mcp/auth_callback"]
        self.assertTrue(
            _redirect_uri_allowed("https://chatgpt.com/connector/oauth/callback-123", allowed)
        )
        self.assertTrue(
            _redirect_uri_allowed("https://chatgpt.com/connector_platform_oauth_redirect", allowed)
        )
        self.assertFalse(_redirect_uri_allowed("https://chatgpt.com/connector/oauth/", allowed))
        self.assertFalse(_redirect_uri_allowed("https://chatgpt.com/connector/oauth/a/b", allowed))
        self.assertFalse(_redirect_uri_allowed("https://evil.example/connector/oauth/abc", allowed))

    def test_pkce_challenge_is_url_safe(self):
        verifier, challenge = pkce_pair()
        self.assertNotIn("=", challenge)
        self.assertNotIn("+", challenge)
        self.assertNotEqual(verifier, challenge)


class LinkedUser(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import tempfile

        self.tmp = tempfile.TemporaryDirectory()
        self.provider = MealieOAuthProvider(settings(self.tmp.name))

    async def asyncTearDown(self):
        await self.provider.pocket_id.aclose()
        self.tmp.cleanup()

    def _pending(self) -> dict:
        return {
            "created": 10**10,
            "client_id": "claude",
            "client_state": "xyz",
            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            "redirect_uri_provided_explicitly": True,
            "code_challenge": "challenge",
            "scopes": ["mealie"],
            "resource": None,
            "oidc_sub": "pocket-1",
            "oidc_email": "ada@example.com",
        }

    async def test_finish_puts_the_pocket_id_subject_on_the_mcp_token(self):
        pending = self._pending()
        self.provider.pending["state1"] = pending
        self.provider.users["pocket-1"] = {
            "email": "ada@example.com",
            "mealie_api_token": "mealie-token",
            "mealie_username": "ada",
        }
        response = self.provider._finish(pending, "state1")
        self.assertEqual(response.status_code, 302)
        code = next(iter(self.provider.auth_codes.values()))
        self.assertEqual(code.subject, "pocket-1")

        class Client:
            client_id = "claude"

        issued = await self.provider.exchange_authorization_code(Client(), code)  # type: ignore[arg-type]
        access = self.provider.access_tokens[issued.access_token]
        self.assertEqual(access.subject, "pocket-1")
        self.assertEqual(self.provider.mealie_token_for(access.subject), "mealie-token")

    async def test_link_rejects_a_token_for_a_different_email(self):
        pending = self._pending()
        self.provider.pending["state1"] = pending
        body = b"state=state1&mealie_api_token=stolen"
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/link",
            "raw_path": b"/link",
            "query_string": b"",
            "headers": [(b"content-type", b"application/x-www-form-urlencoded")],
            "client": ("127.0.0.1", 123),
            "server": ("test", 80),
        }
        sent = False

        async def receive():
            nonlocal sent
            if sent:
                return {"type": "http.disconnect"}
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        from starlette.requests import Request

        request = Request(scope, receive)
        with patch("mealie_mcp.auth.fetch_self", new=AsyncMock(return_value={"email": "other@example.com", "username": "other"})):
            response = await self.provider.handle_link(request)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("pocket-1", self.provider.users)


if __name__ == "__main__":
    unittest.main()
