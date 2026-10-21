#!/usr/bin/env python3
"""Validate the deliberately small JSON Schema subset used by release files.

The project keeps this dependency-free so release verification works with the
Python standard library on macOS and GitHub-hosted Linux runners. Unknown
schema keywords fail closed instead of being silently ignored.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
from typing import Any


SUPPORTED_KEYWORDS = {
    "$schema",
    "$defs",
    "$ref",
    "title",
    "description",
    "type",
    "const",
    "pattern",
    "minimum",
    "required",
    "properties",
    "additionalProperties",
    "minItems",
    "maxItems",
    "uniqueItems",
    "prefixItems",
    "items",
    "allOf",
}


class ValidationFailure(Exception):
    """Raised when a schema or instance violates the supported contract."""


def fail(message: str) -> None:
    raise ValidationFailure(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"JSON object contains duplicate field {key!r}")
        result[key] = value
    return result


def load_json(path: Path, description: str) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_object,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{description} is not valid UTF-8 JSON: {error}")


def value_key(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def resolve_reference(root: dict[str, Any], reference: Any) -> Any:
    if not isinstance(reference, str) or not reference.startswith("#/"):
        fail(f"schema contains unsupported reference {reference!r}")

    value: Any = root
    for token in reference[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if not isinstance(value, dict) or token not in value:
            fail(f"schema reference cannot be resolved: {reference}")
        value = value[token]
    return value


def matches_type(value: Any, expected: str) -> bool:
    checks = {
        "object": lambda item: isinstance(item, dict),
        "array": lambda item: isinstance(item, list),
        "string": lambda item: isinstance(item, str),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "number": lambda item: (
            isinstance(item, (int, float)) and not isinstance(item, bool)
        ),
        "boolean": lambda item: isinstance(item, bool),
        "null": lambda item: item is None,
    }
    if expected not in checks:
        fail(f"schema contains unsupported type {expected!r}")
    return checks[expected](value)


def validate(value: Any, contract: Any, root: dict[str, Any], path: str) -> None:
    if isinstance(contract, bool):
        if not contract:
            fail(f"{path} is rejected by the schema")
        return
    if not isinstance(contract, dict):
        fail(f"schema at {path} must be an object or boolean")

    unsupported = sorted(set(contract) - SUPPORTED_KEYWORDS)
    if unsupported:
        fail(
            f"schema at {path} uses unsupported keywords: "
            + ", ".join(unsupported)
        )

    if "$ref" in contract:
        validate(value, resolve_reference(root, contract["$ref"]), root, path)

    if "allOf" in contract:
        choices = contract["allOf"]
        if not isinstance(choices, list):
            fail(f"schema allOf at {path} must be an array")
        for choice in choices:
            validate(value, choice, root, path)

    if "type" in contract:
        expected_type = contract["type"]
        if not isinstance(expected_type, str):
            fail(f"schema type at {path} must be a string")
        if not matches_type(value, expected_type):
            fail(f"{path} does not have schema type {expected_type}")

    if "const" in contract and value_key(value) != value_key(contract["const"]):
        fail(f"{path} differs from the schema constant")

    if "pattern" in contract:
        pattern = contract["pattern"]
        if not isinstance(pattern, str):
            fail(f"schema pattern at {path} must be a string")
        try:
            matched = not isinstance(value, str) or re.search(pattern, value) is not None
        except re.error as error:
            fail(f"schema pattern at {path} is invalid: {error}")
        if not matched:
            fail(f"{path} does not match the schema pattern")

    if "minimum" in contract:
        minimum = contract["minimum"]
        if not isinstance(minimum, (int, float)) or isinstance(minimum, bool):
            fail(f"schema minimum at {path} must be a number")
        if (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and value < minimum
        ):
            fail(f"{path} is below the schema minimum")

    if isinstance(value, dict):
        required = contract.get("required", [])
        properties = contract.get("properties", {})
        if not isinstance(required, list) or not all(
            isinstance(item, str) for item in required
        ):
            fail(f"schema required at {path} must be an array of strings")
        if not isinstance(properties, dict):
            fail(f"schema properties at {path} must be an object")

        missing = [name for name in required if name not in value]
        if missing:
            fail(f"{path} is missing schema fields: {', '.join(missing)}")

        for name, child_contract in properties.items():
            if name in value:
                validate(value[name], child_contract, root, f"{path}.{name}")

        extras = sorted(set(value) - set(properties))
        additional = contract.get("additionalProperties", True)
        if extras and additional is False:
            fail(f"{path} has fields forbidden by the schema: {', '.join(extras)}")
        if extras and isinstance(additional, dict):
            for name in extras:
                validate(value[name], additional, root, f"{path}.{name}")

    if isinstance(value, list):
        for keyword in ("minItems", "maxItems"):
            if keyword in contract and (
                not isinstance(contract[keyword], int)
                or isinstance(contract[keyword], bool)
                or contract[keyword] < 0
            ):
                fail(f"schema {keyword} at {path} must be a non-negative integer")
        if "minItems" in contract and len(value) < contract["minItems"]:
            fail(f"{path} has fewer items than the schema permits")
        if "maxItems" in contract and len(value) > contract["maxItems"]:
            fail(f"{path} has more items than the schema permits")
        if contract.get("uniqueItems") is True:
            keys = [value_key(item) for item in value]
            if len(keys) != len(set(keys)):
                fail(f"{path} contains duplicate items forbidden by the schema")

        prefix_items = contract.get("prefixItems", [])
        if not isinstance(prefix_items, list):
            fail(f"schema prefixItems at {path} must be an array")
        for index, child_contract in enumerate(prefix_items[: len(value)]):
            validate(value[index], child_contract, root, f"{path}[{index}]")

        if len(value) > len(prefix_items):
            remaining_contract = contract.get("items", True)
            for index in range(len(prefix_items), len(value)):
                validate(value[index], remaining_contract, root, f"{path}[{index}]")


def main() -> int:
    if len(sys.argv) != 3:
        print(
            f"Usage: {Path(sys.argv[0]).name} SCHEMA.json INSTANCE.json",
            file=sys.stderr,
        )
        return 2

    schema_path = Path(sys.argv[1])
    instance_path = Path(sys.argv[2])
    try:
        schema = load_json(schema_path, "schema")
        instance = load_json(instance_path, "instance")
        if not isinstance(schema, dict):
            fail("schema root must be an object")
        validate(instance, schema, schema, "instance")
    except ValidationFailure as error:
        print(f"JSON Schema validation failed: {error}", file=sys.stderr)
        return 1

    print(f"JSON Schema validation passed: {instance_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
