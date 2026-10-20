#!/usr/bin/env python3
"""Verify OpenAPI route coverage against the authoritative Go mux.

Checks:
1. every mux route (METHOD + path) exists in docs/api/openapi.json;
2. every /v1/tenants route also has a /v1/entities alias operation;
3. bearerAuth security scheme and openapi 3.1 are present.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "platform/services/internal/httpapi/server.go"
SPEC = ROOT / "docs/api/openapi.json"

src = SRC.read_text(encoding="utf-8")
routes = re.findall(r'mux\.Handle\("([A-Z]+) ([^"]+)"', src)
if not routes:
    sys.exit("openapi-check: no routes found in server.go")

spec = json.loads(SPEC.read_text(encoding="utf-8"))
paths = spec.get("paths") or {}
missing = []
for method, path in routes:
    op = (paths.get(path) or {}).get(method.lower())
    if not op:
        missing.append(f"{method} {path}")
    if path == "/v1/tenants" or path.startswith("/v1/tenants/"):
        alias = "/v1/entities" + path[len("/v1/tenants"):]
        if not (paths.get(alias) or {}).get(method.lower()):
            missing.append(f"{method} {alias} (entity alias)")

if spec.get("openapi") != "3.1.0":
    missing.append("openapi version != 3.1.0")
if not (spec.get("components", {}).get("securitySchemes", {}).get("bearerAuth")):
    missing.append("components.securitySchemes.bearerAuth missing")

if missing:
    print("openapi-check FAIL:")
    for m in missing[:40]:
        print("  -", m)
    sys.exit(1)

print(f"openapi-check OK: {len(routes)} routes covered, entity aliases present, bearerAuth present")
