"""Mealie MCP server: Streamable HTTP transport + built-in OAuth, for Claude custom connectors."""

from __future__ import annotations

import base64
import binascii
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import date, timedelta
from typing import Any, Literal

import uvicorn
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response

from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.mcpserver import MCPServer
from mcp_types import ToolAnnotations

from .auth import MealieOAuthProvider
from .config import Settings
from .mealie import MealieClient, plan_entry, recipe_full, recipe_summary, shopping_item

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("mealie_mcp")

settings = Settings()
oauth = MealieOAuthProvider(settings)
_mealie: MealieClient | None = None


def mealie() -> MealieClient:
    assert _mealie is not None, "Mealie client not initialised"
    return _mealie


@asynccontextmanager
async def lifespan(_: MCPServer) -> AsyncIterator[None]:
    global _mealie
    _mealie = MealieClient(str(settings.mealie_url), settings.mealie_api_token)
    try:
        yield
    finally:
        await _mealie.aclose()
        _mealie = None


mcp = MCPServer(
    name="Mealie",
    instructions=(
        "Tools for the user's self-hosted Mealie instance: search and read recipes, import recipes "
        "from URLs, manage shopping lists, and plan meals. Dates are ISO (YYYY-MM-DD). Recipes are "
        "addressed by slug (preferred) or id."
    ),
    auth_server_provider=oauth,
    auth=AuthSettings(
        # Plain strings on purpose: AuthSettings preserves the empty path so the
        # advertised issuer is the canonical "https://host" (no trailing slash).
        issuer_url=settings.public_base,  # type: ignore[arg-type]
        resource_server_url=settings.mcp_endpoint,  # type: ignore[arg-type]
        # Tokens are only ever minted by this same process for this same resource.
        validate_token_resource=False,
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=[settings.mcp_scope],
            default_scopes=[settings.mcp_scope],
        ),
        revocation_options=RevocationOptions(enabled=True),
        required_scopes=[settings.mcp_scope],
    ),
    lifespan=lifespan,
)

READ = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False)
DESTRUCTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False)


# ---------------------------------------------------------------- custom routes

@mcp.custom_route("/login", methods=["GET"])
async def login_get(request: Request) -> Response:
    return oauth.login_page(request)


@mcp.custom_route("/login", methods=["POST"])
async def login_post(request: Request) -> Response:
    return await oauth.handle_login(request)


@mcp.custom_route("/healthz", methods=["GET"])
async def healthz(_: Request) -> Response:
    try:
        await mealie().get("/api/app/about")
        return JSONResponse({"ok": True, "mealie": "reachable"})
    except Exception as e:  # noqa: BLE001
        return JSONResponse({"ok": False, "mealie": str(e)}, status_code=503)


@mcp.custom_route("/", methods=["GET"])
async def index(_: Request) -> Response:
    return PlainTextResponse(f"Mealie MCP server. Add {settings.mcp_endpoint} as a custom connector in your MCP client (for example Claude or Grok).\n")


# ---------------------------------------------------------------- recipes

@mcp.tool(annotations=READ)
async def search_recipes(
    query: str = "",
    tags: list[str] | None = None,
    categories: list[str] | None = None,
    page: int = 1,
    per_page: int = 15,
    order_by: Literal["name", "rating", "created_at", "date_added", "last_made"] = "name",
    order_direction: Literal["asc", "desc"] = "asc",
) -> dict[str, Any]:
    """Search recipes by free text, optionally filtered by tag/category slugs.

    Returns summaries (slug, name, tags, times). Use get_recipe for ingredients and steps.
    Leave query empty to list everything.
    """
    params: dict[str, Any] = {
        "page": page,
        "perPage": min(max(per_page, 1), 50),
        "orderBy": order_by,
        "orderDirection": order_direction,
    }
    if query:
        params["search"] = query
    if tags:
        params["tags"] = tags
    if categories:
        params["categories"] = categories
    data = await mealie().get("/api/recipes", params)
    return {
        "page": data.get("page"),
        "total_pages": data.get("total_pages"),
        "total": data.get("total"),
        "recipes": [recipe_summary(r) for r in data.get("items", [])],
    }


@mcp.tool(annotations=READ)
async def get_recipe(slug: str) -> dict[str, Any]:
    """Get a full recipe (ingredients, instructions, notes, nutrition) by slug or id."""
    return recipe_full(await mealie().get(f"/api/recipes/{slug}"))


@mcp.tool(annotations=WRITE)
async def import_recipe_from_url(url: str, include_tags: bool = True) -> dict[str, Any]:
    """Scrape a recipe web page into Mealie. Returns the new recipe."""
    slug = await mealie().post("/api/recipes/create/url", {"url": url, "includeTags": include_tags})
    return recipe_full(await mealie().get(f"/api/recipes/{slug}"))


@mcp.tool(annotations=WRITE)
async def create_recipe(
    name: str,
    ingredients: list[str],
    instructions: list[str],
    description: str = "",
    servings: int | None = None,
    prep_time: str | None = None,
    cook_time: str | None = None,
    total_time: str | None = None,
    source_url: str | None = None,
) -> dict[str, Any]:
    """Create a recipe from scratch. Ingredients are free-text lines ("2 cups flour");
    instructions are one string per step. Times are free text ("20 minutes")."""
    slug = await mealie().post("/api/recipes", {"name": name})
    patch: dict[str, Any] = {
        "description": description,
        "recipeIngredient": [{"note": line, "display": line} for line in ingredients],
        "recipeInstructions": [{"text": step} for step in instructions],
    }
    if servings is not None:
        patch["recipeServings"] = servings
    if prep_time:
        patch["prepTime"] = prep_time
    if cook_time:
        patch["performTime"] = cook_time
    if total_time:
        patch["totalTime"] = total_time
    if source_url:
        patch["orgURL"] = source_url
    return recipe_full(await mealie().patch(f"/api/recipes/{slug}", patch))


@mcp.tool(annotations=WRITE)
async def update_recipe(
    slug: str,
    name: str | None = None,
    description: str | None = None,
    ingredients: list[str] | None = None,
    instructions: list[str] | None = None,
    servings: int | None = None,
    prep_time: str | None = None,
    cook_time: str | None = None,
    total_time: str | None = None,
    rating: int | None = None,
) -> dict[str, Any]:
    """Update parts of a recipe. Only the fields you pass are changed; ingredients/instructions
    replace the whole list when given."""
    patch: dict[str, Any] = {}
    if name is not None:
        patch["name"] = name
    if description is not None:
        patch["description"] = description
    if ingredients is not None:
        patch["recipeIngredient"] = [{"note": line, "display": line} for line in ingredients]
    if instructions is not None:
        patch["recipeInstructions"] = [{"text": step} for step in instructions]
    if servings is not None:
        patch["recipeServings"] = servings
    if prep_time is not None:
        patch["prepTime"] = prep_time
    if cook_time is not None:
        patch["performTime"] = cook_time
    if total_time is not None:
        patch["totalTime"] = total_time
    if rating is not None:
        patch["rating"] = rating
    if not patch:
        raise ValueError("nothing to update")
    return recipe_full(await mealie().patch(f"/api/recipes/{slug}", patch))


_IMAGE_TYPES = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png", "webp": "image/webp", "gif": "image/gif"}


@mcp.tool(annotations=WRITE)
async def set_recipe_image(
    slug: str,
    image_url: str | None = None,
    image_base64: str | None = None,
    extension: Literal["jpg", "jpeg", "png", "webp", "gif"] = "jpg",
) -> dict[str, Any]:
    """Set or replace a recipe's picture. Give either image_url (Mealie downloads it) or
    image_base64 (raw base64 image data, with extension matching its format). Replaces any
    existing image."""
    if bool(image_url) == bool(image_base64):
        raise ValueError("provide exactly one of image_url or image_base64")
    if image_url:
        await mealie().post(f"/api/recipes/{slug}/image", {"url": image_url})
    else:
        try:
            content = base64.b64decode(image_base64 or "", validate=True)
        except (binascii.Error, ValueError) as e:
            raise ValueError(f"image_base64 is not valid base64: {e}") from e
        if not content:
            raise ValueError("image_base64 is empty")
        await mealie().put_file(
            f"/api/recipes/{slug}/image", "image", f"image.{extension}", content, _IMAGE_TYPES[extension], {"extension": extension}
        )
    return recipe_full(await mealie().get(f"/api/recipes/{slug}"))


@mcp.tool(annotations=DESTRUCTIVE)
async def delete_recipe(slug: str) -> str:
    """Permanently delete a recipe by slug. Confirm with the user first."""
    await mealie().delete(f"/api/recipes/{slug}")
    return f"Deleted recipe {slug}"


@mcp.tool(annotations=READ)
async def list_tags_and_categories() -> dict[str, list[str]]:
    """List all tag and category slugs (usable as filters in search_recipes)."""
    tags = await mealie().get("/api/organizers/tags", {"perPage": -1})
    cats = await mealie().get("/api/organizers/categories", {"perPage": -1})
    return {
        "tags": sorted(t["slug"] for t in tags.get("items", [])),
        "categories": sorted(c["slug"] for c in cats.get("items", [])),
    }


# ---------------------------------------------------------------- shopping lists

@mcp.tool(annotations=READ)
async def list_shopping_lists() -> list[dict[str, Any]]:
    """List shopping lists (id + name). Use get_shopping_list for the items."""
    data = await mealie().get("/api/households/shopping/lists", {"perPage": -1})
    return [{"id": s["id"], "name": s["name"]} for s in data.get("items", [])]


@mcp.tool(annotations=READ)
async def get_shopping_list(list_id: str, include_checked: bool = False) -> dict[str, Any]:
    """Get a shopping list with its items. Unchecked items only unless include_checked=true."""
    s = await mealie().get(f"/api/households/shopping/lists/{list_id}")
    items = [shopping_item(i) for i in s.get("listItems", [])]
    if not include_checked:
        items = [i for i in items if not i["checked"]]
    return {"id": s["id"], "name": s["name"], "items": items}


@mcp.tool(annotations=WRITE)
async def add_shopping_items(list_id: str, items: list[str]) -> dict[str, Any]:
    """Add free-text items ("2 lemons", "olive oil") to a shopping list."""
    payload = [{"shoppingListId": list_id, "note": text.strip(), "checked": False} for text in items if text.strip()]
    if not payload:
        raise ValueError("no items given")
    res = await mealie().post("/api/households/shopping/items/create-bulk", payload)
    created = res.get("createdItems", res) if isinstance(res, dict) else res
    return {"added": [shopping_item(i) for i in created]}


@mcp.tool(annotations=WRITE)
async def update_shopping_item(
    item_id: str,
    checked: bool | None = None,
    text: str | None = None,
    quantity: float | None = None,
) -> dict[str, Any]:
    """Check/uncheck, rename or change the quantity of one shopping list item."""
    item = await mealie().get(f"/api/households/shopping/items/{item_id}")
    if checked is not None:
        item["checked"] = checked
    if text is not None:
        item["note"] = text
        item["display"] = text
        item["food"] = None
        item["foodId"] = None
        item["unit"] = None
        item["unitId"] = None
    if quantity is not None:
        item["quantity"] = quantity
    return shopping_item(await mealie().put(f"/api/households/shopping/items/{item_id}", item))


@mcp.tool(annotations=DESTRUCTIVE)
async def delete_shopping_items(item_ids: list[str]) -> str:
    """Remove items from a shopping list by item id."""
    for item_id in item_ids:
        await mealie().delete(f"/api/households/shopping/items/{item_id}")
    return f"Deleted {len(item_ids)} item(s)"


@mcp.tool(annotations=WRITE)
async def add_recipe_to_shopping_list(list_id: str, recipe_id: str, scale: float = 1.0) -> dict[str, Any]:
    """Add all ingredients of a recipe (by recipe id, not slug) to a shopping list."""
    await mealie().post(
        f"/api/households/shopping/lists/{list_id}/recipe/{recipe_id}",
        {"recipeIncrementQuantity": scale},
    )
    return await get_shopping_list(list_id)


# ---------------------------------------------------------------- meal plans

@mcp.tool(annotations=READ)
async def get_meal_plan(start_date: str | None = None, end_date: str | None = None) -> list[dict[str, Any]]:
    """Get meal plan entries between two dates (inclusive). Defaults to today through +6 days."""
    start = date.fromisoformat(start_date) if start_date else date.today()
    end = date.fromisoformat(end_date) if end_date else start + timedelta(days=6)
    data = await mealie().get(
        "/api/households/mealplans",
        {"start_date": start.isoformat(), "end_date": end.isoformat(), "perPage": -1, "orderBy": "date", "orderDirection": "asc"},
    )
    return [plan_entry(e) for e in data.get("items", [])]


@mcp.tool(annotations=WRITE)
async def add_meal_plan_entry(
    day: str,
    entry_type: Literal["breakfast", "lunch", "dinner", "side", "snack", "drink", "dessert"] = "dinner",
    recipe_id: str | None = None,
    title: str | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    """Plan a meal on a date (YYYY-MM-DD). Give a recipe_id (from search_recipes/get_recipe)
    or a free-text title for something not in Mealie."""
    if not recipe_id and not title:
        raise ValueError("provide recipe_id or title")
    body: dict[str, Any] = {"date": date.fromisoformat(day).isoformat(), "entryType": entry_type}
    if recipe_id:
        body["recipeId"] = recipe_id
    if title:
        body["title"] = title
    if note:
        body["text"] = note
    return plan_entry(await mealie().post("/api/households/mealplans", body))


@mcp.tool(annotations=DESTRUCTIVE)
async def delete_meal_plan_entry(entry_id: str) -> str:
    """Remove a meal plan entry by its id (from get_meal_plan)."""
    await mealie().delete(f"/api/households/mealplans/{entry_id}")
    return f"Deleted meal plan entry {entry_id}"


# ---------------------------------------------------------------- escape hatch

@mcp.tool(annotations=READ)
async def mealie_get(path: str, params: dict[str, Any] | None = None) -> Any:
    """Read-only GET against any Mealie API path (must start with /api/), for things the other
    tools don't cover. Response is returned raw and may be large."""
    return await mealie().get(path, params)


# ---------------------------------------------------------------- entrypoint

def main() -> None:
    log.info("Mealie: %s | public URL: %s | MCP endpoint: %s", settings.mealie_url, settings.public_base, settings.mcp_endpoint)
    app = mcp.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
        host=settings.mcp_host,
    )
    uvicorn.run(
        app,
        host=settings.mcp_host,
        port=settings.mcp_port,
        proxy_headers=True,
        forwarded_allow_ips="*",
        log_level="info",
    )


if __name__ == "__main__":
    main()
