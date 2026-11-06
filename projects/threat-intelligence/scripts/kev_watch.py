#!/usr/bin/env python3
"""Fetch and filter CISA's public Known Exploited Vulnerabilities JSON catalog."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import date
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FIELDS = [
    "cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded",
    "shortDescription", "requiredAction", "dueDate", "knownRansomwareCampaignUse",
    "catalogVersion", "catalogDateReleased",
]


def filter_records(
    catalog: dict,
    since: str | None = None,
    vendor: str | None = None,
    product: str | None = None,
) -> list[dict[str, str]]:
    records = catalog.get("vulnerabilities", [])
    if not isinstance(records, list):
        raise ValueError("Catalog has no valid vulnerabilities list")
    since_date = date.fromisoformat(since) if since else None
    output = []
    for item in records:
        if not isinstance(item, dict):
            continue
        added = item.get("dateAdded", "")
        if since_date and (not added or date.fromisoformat(added) < since_date):
            continue
        if vendor and vendor.casefold() not in str(item.get("vendorProject", "")).casefold():
            continue
        if product and product.casefold() not in str(item.get("product", "")).casefold():
            continue
        row = {field: str(item.get(field, "")) for field in FIELDS}
        row["catalogVersion"] = str(catalog.get("catalogVersion", ""))
        row["catalogDateReleased"] = str(catalog.get("dateReleased", ""))
        output.append(row)
    output.sort(key=lambda row: row["dateAdded"], reverse=True)
    return output


def fetch_catalog(timeout: int = 30) -> dict:
    request = Request(
        FEED_URL,
        headers={"User-Agent": "Pavan-Kona-Cybersecurity-Portfolio/1.0", "Accept": "application/json"},
    )
    with urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            raise RuntimeError(f"CISA feed returned HTTP {response.status}")
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict) or "vulnerabilities" not in payload:
        raise ValueError("Unexpected CISA KEV feed structure")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since", help="Include catalog entries added on or after YYYY-MM-DD")
    parser.add_argument("--vendor", help="Case-insensitive vendor substring filter")
    parser.add_argument("--product", help="Case-insensitive product substring filter")
    parser.add_argument("--limit", type=int, default=25, help="Maximum rows to export (default: 25)")
    parser.add_argument("--output", type=Path, default=Path("kev-results.csv"), help="CSV output path")
    args = parser.parse_args()
    if args.limit < 1:
        parser.error("--limit must be at least 1")
    try:
        catalog = fetch_catalog()
        rows = filter_records(catalog, args.since, args.vendor, args.product)[:args.limit]
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        print(
            f"CISA KEV catalog {catalog.get('catalogVersion', 'unknown')} "
            f"(released {catalog.get('dateReleased', 'unknown')}): "
            f"exported {len(rows)} rows -> {args.output}"
        )
        return 0
    except (OSError, HTTPError, URLError, TimeoutError, json.JSONDecodeError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
