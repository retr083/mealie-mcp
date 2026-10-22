# mealie-mcp

A remote MCP server for [Mealie](https://mealie.io) that you can add to Claude as a **custom connector** — including the Claude mobile app — without any third-party auth service.

- **Streamable HTTP** transport at `/mcp` (what Claude's connectors require)
- **Built-in OAuth 2.1 authorization server** (dynamic client registration, PKCE, refresh-token rotation) with a single-password login page — nothing else to run
- Tokens/clients persist to a JSON file, so restarts don't force re-authorisation
- Only allows the configured callback URLs as OAuth redirects (Claude's by default, Grok's on request), so nobody can register a phishing client against your login page
- Failed-login lockout (5 attempts → 5 minute cool-off per IP)

## Tools

| Tool | What it does |
|---|---|
| `search_recipes` | Free-text search, filter by tag/category slug, paginated summaries |
| `get_recipe` | Full recipe: ingredients, steps, notes, nutrition |
| `import_recipe_from_url` | Scrape a recipe web page into Mealie |
| `create_recipe` / `update_recipe` / `delete_recipe` | Recipe CRUD (free-text ingredient lines and steps) |
| `set_recipe_image` | Set a recipe picture from an image URL or base64 data |
| `list_tags_and_categories` | Slugs usable as search filters |
| `list_shopping_lists` / `get_shopping_list` | Lists and their (unchecked) items |
| `add_shopping_items` / `update_shopping_item` / `delete_shopping_items` | Add free-text items, tick/rename/re-quantity, remove |
| `add_recipe_to_shopping_list` | Push a recipe's ingredients onto a list (scalable) |
| `get_meal_plan` / `add_meal_plan_entry` / `delete_meal_plan_entry` | Meal planning by date |
| `mealie_get` | Read-only escape hatch for any `/api/...` GET |

Targets the Mealie **v2/v3 API** (`/api/households/...`); tested against Mealie **v3.22**. If you are still on Mealie 1.x the client transparently falls back to the old `/api/groups/...` paths on a 404.

## Requirements

- Mealie reachable from wherever this runs (LAN is fine)
- A Mealie **API token**: Mealie → your user → *API Tokens* → create (long-lived)
- A **public HTTPS hostname** pointing at this server. Claude's servers must be able to reach it. If you already run a reverse proxy (Nginx Proxy Manager, Caddy, Traefik) with ports 80/443 forwarded, just add a host — see Option B. Otherwise the compose file includes a Cloudflare Tunnel (Option A).

## Run it (Docker, on Proxmox)

On a VM or LXC with Docker:

```bash
git clone https://github.com/retr083/mealie-mcp.git && cd mealie-mcp
cp .env.example .env
nano .env        # MEALIE_URL, MEALIE_API_TOKEN, PUBLIC_URL, MCP_LOGIN_PASSWORD
```

The compose file pulls the pre-built multi-arch image `ghcr.io/retr083/mealie-mcp:latest` (amd64 + arm64). To build from source instead, uncomment `build: .` in `docker-compose.yml` and add `--build` to the commands below.

### Option A — Cloudflare Tunnel (no port forwarding)

1. Cloudflare Zero Trust → *Networks → Tunnels → Create a tunnel* (Cloudflared). Copy the token into `.env` as `TUNNEL_TOKEN=...`.
2. In the tunnel's *Public Hostname* tab add: `mealie-mcp.yourdomain.com` → Service `HTTP` → `mealie-mcp:8000`.
3. Set `PUBLIC_URL=https://mealie-mcp.yourdomain.com` in `.env`, remove the `ports:` block from `docker-compose.yml` (not needed), then:

```bash
docker compose --profile cloudflared up -d
```

### Option B — Nginx Proxy Manager (or any reverse proxy)

```bash
docker compose up -d
```

1. DNS: add an `A`/`CNAME` record for `mealie-mcp.yourdomain.com` pointing at your public IP (same as your other NPM hosts).
2. NPM → *Hosts → Proxy Hosts → Add Proxy Host*:
   - **Domain Names:** `mealie-mcp.yourdomain.com`
   - **Scheme:** `http` · **Forward Hostname/IP:** the Docker host's LAN IP (or the container name `mealie-mcp` if NPM is on the same Docker network) · **Forward Port:** `8000`
   - **Block Common Exploits:** on · **Websockets Support:** on (harmless, not required)
   - **SSL tab:** request a Let's Encrypt certificate, **Force SSL** on, **HTTP/2** on
   - **Advanced tab**, paste:
     ```nginx
     proxy_buffering off;
     proxy_read_timeout 300s;
     proxy_send_timeout 300s;
     ```
     (stops nginx buffering streamed responses and keeps long tool calls — e.g. importing a slow recipe site — from being cut off)
3. Do **not** put an NPM Access List (IP allow-list) on this host — the login page has to be reachable from your phone/browser, not just from Anthropic.

`PUBLIC_URL` in `.env` must be `https://mealie-mcp.yourdomain.com` — it's what the OAuth metadata advertises, and Claude rejects the connector if it doesn't match the URL you enter.

Caddy equivalent, if you ever switch:

```
mealie-mcp.yourdomain.com {
    reverse_proxy 192.168.1.20:8000
}
```

### Check it

- `https://mealie-mcp.yourdomain.com/` → a one-line banner
- `https://mealie-mcp.yourdomain.com/healthz` → `{"ok": true, "mealie": "reachable"}`
- `https://mealie-mcp.yourdomain.com/.well-known/oauth-authorization-server` → JSON metadata

## Connect Claude

**Claude mobile / web / desktop:** Settings → *Connectors* → *Add custom connector* → URL: `https://mealie-mcp.yourdomain.com/mcp` → leave the OAuth client ID/secret fields empty → *Add*. Claude will open your login page; enter `MCP_LOGIN_PASSWORD`. Done — enable the connector in a chat and ask it what's for dinner.

Custom connectors are added per account, so once it's added on the web it appears on mobile too.

**Claude Code:**

```bash
claude mcp add --transport http mealie https://mealie-mcp.yourdomain.com/mcp
```

then `/mcp` inside Claude Code to trigger the login.

## Connect Grok

Grok (web, mobile and the in-car Tesla assistant) supports custom MCP connectors with this server. Add Grok's callback to the allowlist in `.env` and restart:

```bash
MCP_ALLOWED_REDIRECT_URIS=https://grok.com/connectors-oauth-exchange-code/
```

(Keep the Claude callbacks in the list too if you use both.) Then in Grok: *Connectors* → *New connector* → *Custom* → name `Mealie`, URL `https://mealie-mcp.yourdomain.com/mcp`. Grok opens your login page; enter `MCP_LOGIN_PASSWORD`. Connectors belong to the Grok account, so a Tesla signed in to the same account uses it too.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Browser shows `ERR_SSL_UNRECOGNIZED_NAME_ALERT`, or `http://` gives NPM's "Congratulations" page | NPM has no proxy host matching that exact hostname (typo, not saved, or disabled). Fix the proxy host and request the certificate. |
| Claude: "Failed to start MCP authorization" and **nothing** in `docker logs` | Claude never reached you. Hostname must resolve (from the public internet) to a public **IPv4** address — no private/CGNAT ranges, no AAAA-only. Check with `nslookup <host> 8.8.8.8` from mobile data. |
| Claude: "Your account was authorized, but no MCP server was found at the provided URL" | Login worked but the connector URL is wrong — it must end in **`/mcp`**. Delete and re-add the connector with `https://<host>/mcp`. |
| Claude: "Authorization with the MCP server failed" | `PUBLIC_URL` doesn't match the URL you entered (scheme/host must be identical, no trailing slash), or `/token` took >10 s. Check `docker logs mealie-mcp`. |
| `/healthz` returns `503` | The container can't reach `MEALIE_URL`, or `MEALIE_API_TOKEN` is wrong. |
| Tool calls time out on slow recipe imports | Add the `proxy_read_timeout` lines from Option B to your proxy config. |

Every failure toast in Claude includes an `ofid_…` reference; if you file an issue with [anthropics/claude-ai-mcp](https://github.com/anthropics/claude-ai-mcp/issues), include it along with your `docker logs` lines from the attempt.

## Limitations (read before exposing it)

- **Single user, single password.** Anyone who knows the password gets full access to the Mealie account behind the API token. This is designed for a personal homelab, not multi-tenant use.
- **Tokens are stored unhashed** in `data/auth_state.json` (they're random 48-byte secrets, but treat that file like a password file — it lives in a Docker volume for that reason).
- **No account/session UI.** To revoke everything, delete `data/auth_state.json` and restart.
- Pinned to `mcp==2.2.0` — the official SDK's server API is still changing between releases (e.g. `FastMCP` → `MCPServer`), so upgrades need a look, not just a bump.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `MEALIE_URL` | — | Mealie base URL, as seen from this container |
| `MEALIE_API_TOKEN` | — | Mealie API token (the server acts as that user) |
| `PUBLIC_URL` | — | Public HTTPS origin of this server, no trailing slash, no `/mcp` |
| `MCP_LOGIN_PASSWORD` | — | Password for the connect-time login page (min 12 chars) |
| `MCP_HOST` / `MCP_PORT` | `0.0.0.0` / `8000` | Bind address |
| `MCP_DATA_DIR` | `/data` | Where `auth_state.json` lives |
| `MCP_ACCESS_TOKEN_TTL` | `3600` | Access token lifetime (s). Claude refreshes automatically. |
| `MCP_REFRESH_TOKEN_TTL` | `2592000` | Refresh token lifetime (s) — how long before you must log in again |
| `MCP_ALLOWED_REDIRECT_URIS` | claude.ai callback + loopback | Comma-separated (or JSON list) allowlist for OAuth clients; add `https://grok.com/connectors-oauth-exchange-code/` for Grok |

## Security notes

- Everything Claude can do, it does **as the Mealie user who owns the API token**. Create a dedicated Mealie user if you want to limit blast radius.
- The MCP endpoint is only reachable with a valid bearer token; the login page is the only unauthenticated surface (plus OAuth metadata/registration, which are public by design).
- For belt-and-braces you can restrict the hostname at your proxy/tunnel to Anthropic's egress range `160.79.104.0/21` — but note *you* also need to reach `/login` from your phone/browser during connect, so allow that too (or only enforce the IP rule on `/mcp`, `/token`, `/register`).
- Revoke access at any time: delete `data/auth_state.json` and restart (or just rotate `MCP_LOGIN_PASSWORD` — existing tokens keep working until they expire, so delete the file too).

## Local development

```bash
python -m venv .venv && .venv/Scripts/activate      # or source .venv/bin/activate
pip install -e .
MEALIE_URL=http://mealie.lan:9925 MEALIE_API_TOKEN=... PUBLIC_URL=http://127.0.0.1:8000 \
MCP_LOGIN_PASSWORD=correct-horse-battery MCP_DATA_DIR=./data python -m mealie_mcp
```

Built on the official [`mcp`](https://github.com/modelcontextprotocol/python-sdk) Python SDK (2.x) — the SDK provides the `/authorize`, `/token`, `/register`, `/revoke` and `.well-known` endpoints; this project supplies the provider, login page, Mealie client and tools.
