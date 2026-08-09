"""MCP resources. Read-only, non-bulk, licensing-safe.

No resource exposes catalogue rows, bulk content, secrets, or the catalogue
file itself. Resource order is deterministic (sorted by uri).
"""
from __future__ import annotations

import json
from typing import Any, Callable

from ..aeo.machine import diagram
from ..catalogue_gateway import CatalogueGateway
from ..egordian.registry import get_registry

RESOURCE_DEFS: list[dict[str, Any]] = [
    {"uri": "aeo://stage-machine",
     "name": "AEO stage machine",
     "title": "AEO nine-stage deterministic pipeline",
     "description": "Stages, determinism tiers, gates, and blocked capabilities.",
     "mimeType": "application/json"},
    {"uri": "catalogue://manifest",
     "name": "Catalogue manifest",
     "title": "Licensed CTC catalogue manifest",
     "description": "Edition, provenance checksums and counts. No catalogue rows.",
     "mimeType": "application/json"},
    {"uri": "egordian://capability-gaps",
     "name": "eGordian capability gaps",
     "title": "Blocked and undocumented eGordian capabilities",
     "description": "Write paths that cannot be implemented because no route is documented.",
     "mimeType": "application/json"},
    {"uri": "egordian://operations",
     "name": "eGordian operation registry",
     "title": "Allowlisted documented eGordian operations",
     "description": "Exact method, route template, parameters, risk and source URL.",
     "mimeType": "application/json"},
    {"uri": "egordian://help-source",
     "name": "eGordian Help documentation snapshot",
     "title": "Fetched Help page fixture metadata",
     "description": "Checksum and section list of the fetched documentation fixture.",
     "mimeType": "application/json"},
]


def list_resources() -> list[dict[str, Any]]:
    return sorted(RESOURCE_DEFS, key=lambda r: r["uri"])


def read_resource(uri: str, gateway: CatalogueGateway) -> dict[str, Any]:
    registry = get_registry()
    if uri == "aeo://stage-machine":
        body: Any = {"stages": diagram()}
    elif uri == "catalogue://manifest":
        body = gateway.status() | {"licensing": "private-licensed; no bulk export or download"}
    elif uri == "egordian://capability-gaps":
        body = {"capability_gaps": registry.capability_gaps()}
    elif uri == "egordian://operations":
        body = {"operations": [op.to_dict() for op in registry.all()],
                "counts": registry.counts()}
    elif uri == "egordian://help-source":
        body = registry.validate()
    else:
        raise KeyError(uri)
    return {
        "contents": [{
            "uri": uri,
            "mimeType": "application/json",
            "text": json.dumps(body, indent=2, sort_keys=True, default=str),
        }]
    }
