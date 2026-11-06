#!/usr/bin/env python3
"""Compare a JSON response's leaf fields with an endpoint-specific allowlist.

This is a schema-minimization helper. It does not prove authorization flaws by
itself; testers must establish the user/object context and validate impact.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from pathlib import Path
from typing import Any

SENSITIVE_NAME = re.compile(
    r"(password|passwd|token|secret|api[_-]?key|client[_-]?secret|"
    r"authorization|ssn|social[_-]?security|credit[_-]?card|private[_-]?key)",
    re.IGNORECASE,
)


def leaf_paths(value: Any, prefix: str = "") -> list[str]:
    """Return stable paths to leaf values; array positions use [] notation."""
    if isinstance(value, dict):
        if not value:
            return [prefix or "$"]
        paths: list[str] = []
        for key in sorted(value):
            child = f"{prefix}.{key}" if prefix else str(key)
            paths.extend(leaf_paths(value[key], child))
        return paths
    if isinstance(value, list):
        if not value:
            return [f"{prefix}[]" if prefix else "[]"]
        paths = []
        for item in value:
            paths.extend(leaf_paths(item, f"{prefix}[]"))
        return paths
    return [prefix or "$"]


def load_allowlist(path: Path) -> list[str]:
    raw = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        data = json.loads(raw)
        if not isinstance(data, list) or not all(isinstance(x, str) for x in data):
            raise ValueError("JSON allowlist must be an array of strings")
        entries = data
    else:
        entries = [
            line.strip()
            for line in raw.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    if not entries:
        raise ValueError("Allowlist is empty; refusing to treat every field as unexpected")
    return sorted(set(entries))


def audit(payload: Any, allowlist: list[str]) -> dict[str, Any]:
    fields = sorted(set(leaf_paths(payload)))
    unexpected = [
        field for field in fields
        if not any(fnmatch.fnmatchcase(field, rule) for rule in allowlist)
    ]
    sensitive = [
        field for field in fields
        if any(SENSITIVE_NAME.search(part) for part in field.split("."))
    ]
    return {
        "tool": "api-response-exposure-auditor",
        "scope_note": "Schema review only; validate authorization and impact manually.",
        "field_count": len(fields),
        "observed_fields": fields,
        "allowlist": allowlist,
        "unexpected_fields": unexpected,
        "sensitive_name_matches": sensitive,
        "passed": not unexpected and not sensitive,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("response", type=Path, help="JSON response body saved from an authorized lab")
    parser.add_argument("--allowlist", required=True, type=Path, help="Text or JSON list of allowed field paths")
    parser.add_argument("--output", type=Path, help="Optional path for JSON report output")
    args = parser.parse_args()

    try:
        payload = json.loads(args.response.read_text(encoding="utf-8"))
        allowlist = load_allowlist(args.allowlist)
        report = audit(payload, allowlist)
        rendered = json.dumps(report, indent=2)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered + "\n", encoding="utf-8")
        print(rendered)
        return 0 if report["passed"] else 1
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
