"""Small helpers shared by checks."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote

from botocore.exceptions import ClientError


def error_code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_policy(doc: Any) -> dict:
    """IAM returns policy documents either parsed or as URL-encoded JSON."""
    if isinstance(doc, dict):
        return doc
    return json.loads(unquote(doc))


def days_since(when: datetime | None) -> int | None:
    if when is None:
        return None
    return (datetime.now(timezone.utc) - when).days


def paginate(client, operation: str, key: str, **kwargs) -> list:
    items: list = []
    for page in client.get_paginator(operation).paginate(**kwargs):
        items.extend(page.get(key, []))
    return items
