import json
from typing import Annotated

from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Mealie
    mealie_url: AnyHttpUrl
    mealie_api_token: str

    # This server
    public_url: AnyHttpUrl
    mcp_login_password: str
    mcp_host: str = "0.0.0.0"
    mcp_port: int = 8000
    mcp_data_dir: str = "/data"
    mcp_access_token_ttl: int = 3600  # seconds
    mcp_refresh_token_ttl: int = 60 * 60 * 24 * 30  # 30 days
    mcp_scope: str = "mealie"
    # Redirect URIs a dynamically-registered client may use. Claude's hosted surfaces
    # (web/desktop/mobile) use the claude.ai callback; Claude Code uses a loopback
    # redirect on a random port (port is ignored when matching). Grok (web, mobile and
    # Tesla) uses https://grok.com/connectors-oauth-exchange-code/.
    # NoDecode: read the env var as text (comma-separated, as documented) instead of JSON.
    mcp_allowed_redirect_uris: Annotated[list[str], NoDecode] = [
        "https://claude.ai/api/mcp/auth_callback",
        "http://localhost/callback",
        "http://127.0.0.1/callback",
    ]

    @field_validator("mcp_allowed_redirect_uris", mode="before")
    @classmethod
    def _split_csv(cls, v):
        if isinstance(v, str):
            if v.strip().startswith("["):  # JSON list, still accepted
                return json.loads(v)
            return [s.strip() for s in v.split(",") if s.strip()]
        return v

    @field_validator("mcp_login_password")
    @classmethod
    def _password_len(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("MCP_LOGIN_PASSWORD must be at least 12 characters")
        return v

    @property
    def public_base(self) -> str:
        return str(self.public_url).rstrip("/")

    @property
    def mcp_endpoint(self) -> str:
        return f"{self.public_base}/mcp"
