#!/usr/bin/env python3
"""Generate the OpenAPI 3.1 skeleton from the authoritative route table.

The Go mux is the single source of truth for routes; this script keeps the
contract from drifting. It intentionally emits a skeleton (no per-field
schemas yet) so Phase 0 can gate route coverage without pretending to have
complete request/response schemas.
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "platform/services/internal/httpapi/server.go"
OUT = ROOT / "docs/api/openapi.json"

src = SRC.read_text(encoding="utf-8")
routes = re.findall(r'mux\.Handle\("([A-Z]+) ([^"]+)"', src)
if not routes:
    raise SystemExit("no routes found in server.go")

def operation(method: str, path: str):
    params = [
        {"name": name, "in": "path", "required": True, "schema": {"type": "string"}}
        for name in re.findall(r"{([^}]+)}", path)
    ]
    op = {
        "operationId": method.lower() + "_" + re.sub(r"[^A-Za-z0-9]+", "_", path).strip("_"),
        "tags": [path.split("/")[2] if len(path.split("/")) > 2 else "system"],
        "summary": f"{method} {path}",
        "security": [{"bearerAuth": []}],
        "parameters": params,
        "responses": {
            "200": {"description": "OK"},
            "400": {"description": "invalid_request"},
            "401": {"description": "unauthenticated"},
            "403": {"description": "forbidden"},
            "404": {"description": "not_found"},
            "501": {"description": "capability unavailable"},
        },
    }
    if method in ("POST", "PUT", "PATCH"):
        op["requestBody"] = {
            "required": False,
            "content": {"application/json": {"schema": {"type": "object"}}},
        }
    return op

paths = {}
for method, path in routes:
    paths.setdefault(path, {})[method.lower()] = operation(method, path)
    # /v1/entities is a first-class alias of /v1/tenants (single-user regulator).
    if path == "/v1/tenants" or path.startswith("/v1/tenants/"):
        alias = "/v1/entities" + path[len("/v1/tenants"):]
        paths.setdefault(alias, {})[method.lower()] = operation(method, alias)

spec = {
    "openapi": "3.1.0",
    "info": {
        "title": "Lumina EASM API",
        "version": "v1.1-phase0",
        "description": "Generated route skeleton. /v1/entities is the canonical entity path; /v1/tenants is a legacy alias. Request/response schemas are incremental.",
    },
    "servers": [{"url": "/", "description": "same-origin"}],
    "paths": paths,
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer", "description": "Dev bearer token or OIDC access token"}
        }
    },
    "x-easm-entity-alias": {
        "canonical": "/v1/entities",
        "legacy": "/v1/tenants",
        "note": "single-user regulator mode; entity_id is the data domain",
    },
}
OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(spec, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"openapi: {len(routes)} routes -> {len(paths)} paths ({OUT})")
