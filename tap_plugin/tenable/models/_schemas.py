"""JSON Schema fragments the Tenable models share.

Security Center returns almost every scalar as a string ("true", "0", "1699999999"), and the
models store them as returned (req-tenable-response-contract-2), so most fields are a string or
null: null when Tenable did not report the field, the string when it did.
"""

from typing import Any

STR = {"type": "string", "minLength": 1}
STR_OR_NULL = {"type": ["string", "null"]}
OBJECT_OR_NULL = {"type": ["object", "null"]}
ARRAY_OR_NULL = {"type": ["array", "null"]}

#: A record Tenable may stop reporting (req-tenable-states-7).
STATEMENT_STATE = {"type": ["string", "null"], "enum": ["current", "withdrawn", None]}

#: A result's state and how it was resolved (req-tenable-states-3, -6, -8).
RESULT_STATE = {"type": ["string", "null"], "enum": ["current", "resolved", None]}
RESOLUTION_SOURCE = {
    "type": ["string", "null"],
    "enum": ["tenable_mitigated", "not_reported", "aged_out", "identity_changed", None],
}

#: Exactly one parse state per result (req-tenable-parsers).
PARSE_STATE = {"type": ["string", "null"], "enum": ["parsed", "no_parser", "parser_failed", "not_applicable", None]}

#: Where a result was observed from (req-tenable-repository-2).
OBSERVATION_PATH = {"type": ["string", "null"], "enum": ["network", "on_board", "passive", None]}

SHA256_HEX = {"type": "string", "pattern": "^[0-9a-f]{64}$"}


def validated(crud_schema: dict[str, Any]) -> dict[str, Any]:
    """Every CRUD field validated against its own schema."""
    return {name: {"validation": "jsonschema", "schema": schema} for name, schema in crud_schema.items()}
