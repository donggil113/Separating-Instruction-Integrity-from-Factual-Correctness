"""Public, deterministic entity-id conventions (shared by the sandbox and any tool that keys a
reference query from an action, e.g. Confirmation-of-Payee takes a payee name)."""
from __future__ import annotations

import re


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def payee_id(name: str) -> str:
    return f"payee:{slug(name)}"


def product_id(sku: str, supplier: str) -> str:
    return f"product:{sku}@{slug(supplier)}"
