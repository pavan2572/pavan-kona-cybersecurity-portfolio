#!/usr/bin/env python3
"""Normalize and safely classify IOC CSV input without external lookups."""

from __future__ import annotations

import argparse
import csv
import ipaddress
import re
import sys
from pathlib import Path

REQUIRED = {"indicator", "indicator_type", "source", "first_seen", "confidence", "context"}
RESERVED_DOMAINS = {"example.com", "example.net", "example.org", "example"}
RESERVED_SUFFIXES = (".example", ".test", ".invalid", ".localhost")
DOMAIN_PATTERN = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\."
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$",
    re.IGNORECASE,
)


def classify_indicator(indicator: str, indicator_type: str) -> tuple[str, str]:
    value = indicator.strip()
    kind = indicator_type.strip().lower()
    if kind in {"ip", "ipv4", "ipv6"}:
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            return "invalid", "Indicator is not a valid IP address"
        if parsed.is_global:
            return "public_candidate", "Globally routable syntax; reputation is not established"
        return "non_public_or_reserved", "Private, loopback, link-local, multicast, reserved or documentation range"
    if kind in {"domain", "hostname"}:
        normalized = value.rstrip(".").lower()
        if not DOMAIN_PATTERN.fullmatch(normalized):
            return "invalid", "Indicator is not a valid domain name"
        if normalized in RESERVED_DOMAINS or any(
            normalized == suffix.lstrip(".") or normalized.endswith(suffix)
            for suffix in RESERVED_SUFFIXES
        ) or normalized.endswith((".example.com", ".example.net", ".example.org")):
            return "documentation_or_test", "Reserved example or test domain; not a live threat indicator"
        return "domain_candidate", "Syntactically valid domain; reputation is not established"
    return "invalid", "Unsupported indicator_type; use ip, ipv4, ipv6 or domain"


def confidence_band(value: int) -> str:
    if value >= 80:
        return "High"
    if value >= 50:
        return "Medium"
    return "Low"


def triage_row(row: dict[str, str]) -> dict[str, str]:
    try:
        confidence = int(row.get("confidence", "").strip())
    except ValueError as exc:
        raise ValueError(f"Invalid confidence for indicator {row.get('indicator', '')}") from exc
    if not 0 <= confidence <= 100:
        raise ValueError(f"Confidence must be between 0 and 100 for {row.get('indicator', '')}")
    classification, analyst_note = classify_indicator(
        row.get("indicator", ""), row.get("indicator_type", "")
    )
    result = dict(row)
    result.update({
        "normalized_indicator": row.get("indicator", "").strip().lower().rstrip("."),
        "classification": classification,
        "confidence_band": confidence_band(confidence),
        "analyst_note": analyst_note,
    })
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="IOC CSV input")
    parser.add_argument("--output", type=Path, required=True, help="Triage CSV output")
    args = parser.parse_args()
    try:
        with args.input.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            missing = REQUIRED - set(reader.fieldnames or [])
            if missing:
                raise ValueError("Missing required columns: " + ", ".join(sorted(missing)))
            rows = [triage_row(row) for row in reader]
        rows.sort(key=lambda row: (row["classification"], -int(row["confidence"]), row["normalized_indicator"]))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        columns = list(rows[0].keys()) if rows else sorted(REQUIRED) + [
            "normalized_indicator", "classification", "confidence_band", "analyst_note"
        ]
        with args.output.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)
        print(f"Triaged {len(rows)} indicators -> {args.output}")
        return 0
    except (OSError, csv.Error, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
