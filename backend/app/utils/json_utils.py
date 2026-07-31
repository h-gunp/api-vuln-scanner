import json
from typing import Any


def json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        indent=2,
        separators=(",", ": "),
    ).encode("utf-8")

