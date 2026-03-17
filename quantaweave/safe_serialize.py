"""
Safe serialization helpers.

Provides JSON + base64 serialization for simple Python types without using
pickle, to avoid arbitrary code execution risks.
"""

from __future__ import annotations

import base64
import json
from typing import Any


def _encode(obj: Any) -> Any:
    if isinstance(obj, bytes):
        return {
            "__type__": "bytes",
            "b64": base64.b64encode(obj).decode("ascii"),
        }
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, dict):
        return {
            "__type__": "dict",
            "items": [[_encode(k), _encode(v)] for k, v in obj.items()],
        }
    if isinstance(obj, (list, tuple)):
        return {
            "__type__": "list",
            "items": [_encode(v) for v in obj],
        }
    raise TypeError(f"Unsupported type for safe serialization: {type(obj)!r}")


def _decode(node: Any) -> Any:
    if isinstance(node, dict):
        node_type = node.get("__type__")
        if node_type == "bytes":
            return base64.b64decode(node["b64"])
        if node_type == "dict":
            return { _decode(k): _decode(v) for k, v in node["items"] }
        if node_type == "list":
            return [ _decode(v) for v in node["items"] ]
        return { k: _decode(v) for k, v in node.items() }
    if isinstance(node, list):
        return [ _decode(v) for v in node ]
    return node


def dumps(obj: Any) -> bytes:
    """Serialize *obj* to UTF-8 JSON bytes using safe encoding."""
    payload = _encode(obj)
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def loads(data: bytes | str) -> Any:
    """Deserialize JSON bytes/str produced by :func:`dumps`."""
    if isinstance(data, bytes):
        text = data.decode("utf-8")
    else:
        text = data
    payload = json.loads(text)
    return _decode(payload)
