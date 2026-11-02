from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Mealie
    mealie_url: AnyHttpUrl

    # Pocket ID. The MCP server stays the OAuth server Claude talks to, and
    # redirects the person here so each connector session is their own login.
    pocket_id_issuer: AnyHttpUrl
    pocket_id_client_id: str
    pocket_id_client_secret: str

    # This server
    public_url: AnyHttpUrl
    mcp_host: str = "0.0.0.0"
    mcp_port: int = 8000
    mcp_data_dir: str = "/data"
    mcp_access_token_ttl: int = 3600  # seconds
    mcp_refresh_token_ttl: int = 60 * 60 * 24 * 30  # 30 days
    mcp_scope: str = "mealie"
    # Redirect URIs a dynamically-registered client may use. Claude's hosted surfaces
    # (web/desktop/mobile) use the claude.ai callback; Claude Code uses a loopback
    # redirect on a random port (port is ignored when matching).
    mcp_allowed_redirect_uris: list[str] = [
        "https://claude.ai/api/mcp/auth_callback",
        "http://localhost/callback",
        "http://127.0.0.1/callback",
    ]

    @field_validator("mcp_allowed_redirect_uris", mode="before")
    @classmethod
    def _split_csv(cls, v):
        if isinstance(v, str):
            return [s.strip() for s in v.split(",") if s.strip()]
        return v

    @property
    def public_base(self) -> str:
        return str(self.public_url).rstrip("/")

    @property
    def mcp_endpoint(self) -> str:
        return f"{self.public_base}/mcp"
