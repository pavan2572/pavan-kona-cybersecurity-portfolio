#!/usr/bin/env python3
"""Offline IOC validation, normalization, confidence/freshness scoring and export."""
from __future__ import annotations
import argparse
import csv
import ipaddress
import json
import re
from collections import defaultdict
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

HASH_PATTERNS = {"md5": re.compile(r"^[a-fA-F0-9]{32}$"), "sha1": re.compile(r"^[a-fA-F0-9]{40}$"), "sha256": re.compile(r"^[a-fA-F0-9]{64}$")}
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")


def classify_indicator(value: str, declared: str = "") -> tuple[str, str]:
    raw = value.strip()
    kind = declared.strip().lower()
    if kind in ("ip", "ipv4", "ipv6") or not kind:
        try:
            address = ipaddress.ip_address(raw)
            return ("ipv4" if address.version == 4 else "ipv6", str(address))
        except ValueError:
            if kind in ("ip", "ipv4", "ipv6"):
                raise ValueError(f"Invalid IP indicator: {raw}")
    if kind in ("md5", "sha1", "sha256") or not kind:
        for hash_type, pattern in HASH_PATTERNS.items():
            if pattern.fullmatch(raw):
                if kind and kind != hash_type:
                    raise ValueError(f"Declared {kind} does not match {hash_type} length")
                return hash_type, raw.lower()
        if kind in HASH_PATTERNS:
            raise ValueError(f"Invalid {kind} hash: {raw}")
    if kind in ("url", "uri") or (not kind and "://" in raw):
        parsed = urlsplit(raw)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            raise ValueError(f"Invalid HTTP(S) URL: {raw}")
        normalized = urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", parsed.query, ""))
        return "url", normalized
    domain = raw.rstrip(".").lower()
    if DOMAIN_RE.fullmatch(domain):
        return "domain", domain
    raise ValueError(f"Unsupported or invalid indicator: {raw}")


def freshness_points(last_seen: date, as_of: date) -> int:
    age = (as_of - last_seen).days
    if age < 0:
        raise ValueError("last_seen cannot be after the selected as_of date")
    if age <= 7:
        return 30
    if age <= 30:
        return 20
    if age <= 90:
        return 10
    return 0


def enrich_rows(rows: list[dict[str, str]], as_of: date) -> list[dict[str, str | int]]:
    grouped: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        kind, normalized = classify_indicator(row.get("indicator", ""), row.get("type", ""))
        grouped[(kind, normalized)].append(row)
    results = []
    for (kind, indicator), observations in sorted(grouped.items()):
        confidences = []
        dates = []
        first_dates = []
        sources = []
        techniques = []
        tags = []
        for row in observations:
            try:
                confidence = int(row.get("confidence", "0"))
            except ValueError:
                confidence = 0
            if not 0 <= confidence <= 100:
                raise ValueError(f"Confidence must be 0–100 for {indicator}")
            confidences.append(confidence)
            if row.get("last_seen"):
                dates.append(date.fromisoformat(row["last_seen"]))
            if row.get("first_seen"):
                first_dates.append(date.fromisoformat(row["first_seen"]))
            if row.get("source"):
                sources.append(row["source"].strip())
            if row.get("technique_id"):
                techniques.append(row["technique_id"].strip().upper())
            if row.get("tags"):
                tags.extend(t.strip() for t in row["tags"].split(";") if t.strip())
        latest = max(dates) if dates else None
        earliest = min(first_dates) if first_dates else None
        if latest and earliest and earliest > latest:
            raise ValueError(f"first_seen cannot be after last_seen for {indicator}")
        recency = freshness_points(latest, as_of) if latest else 0
        source_confidence = max(confidences) if confidences else 0
        score = min(100, round(source_confidence * 0.7 + recency))
        results.append({
            "indicator": indicator,
            "type": kind,
            "source_confidence": source_confidence,
            "first_seen": earliest.isoformat() if earliest else "",
            "last_seen": latest.isoformat() if latest else "",
            "age_days": (as_of - latest).days if latest else "",
            "freshness_points": recency,
            "priority_score": score,
            "confidence_band": "High" if score >= 75 else "Medium" if score >= 45 else "Low",
            "sources": ";".join(sorted(set(sources))),
            "technique_ids": ";".join(sorted(set(techniques))),
            "tags": ";".join(sorted(set(tags))),
            "observations": len(observations),
        })
    return sorted(results, key=lambda row: (-int(row["priority_score"]), str(row["type"]), str(row["indicator"])))


def load_events(path: Path | None) -> list[dict]:
    if path is None:
        return []
    events = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON event on line {line_number}: {exc}") from exc
            if not isinstance(event, dict):
                raise ValueError(f"Event on line {line_number} must be a JSON object")
            events.append(event)
    return events


def match_events(events: list[dict], indicators: list[dict]) -> list[dict]:
    lookup = {(row["type"], row["indicator"]): row for row in indicators}
    matches = []
    for event in events:
        candidates = []
        for field, kind in (("query", "domain"), ("dest_ip", "ipv4"), ("url", "url"), ("file_hash", "sha256")):
            value = str(event.get(field, "")).strip()
            if not value:
                continue
            try:
                parsed_kind, normalized = classify_indicator(value, kind)
            except ValueError:
                continue
            if (parsed_kind, normalized) in lookup:
                candidates.append(lookup[(parsed_kind, normalized)])
        for match in candidates:
            matches.append({
                "timestamp": event.get("timestamp", ""),
                "src_ip": event.get("src_ip", ""),
                "dest_ip": event.get("dest_ip", ""),
                "query": event.get("query", ""),
                "user": event.get("user", ""),
                "action": event.get("action", ""),
                "matched_indicator": match["indicator"],
                "indicator_type": match["type"],
                "confidence_band": match["confidence_band"],
                "priority_score": match["priority_score"],
            })
    return matches


def write_outputs(indicators: list[dict], matches: list[dict], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    columns = list(indicators[0].keys()) if indicators else ["indicator", "type", "source_confidence", "first_seen", "last_seen", "age_days", "freshness_points", "priority_score", "confidence_band", "sources", "technique_ids", "tags", "observations"]
    with (out / "normalized_iocs.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader(); writer.writerows(indicators)
    with (out / "threat_iocs.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["indicator", "type", "source_confidence", "confidence_band", "priority_score", "technique_ids", "tags"])
        writer.writeheader()
        for row in indicators:
            writer.writerow({key: row.get(key, "") for key in writer.fieldnames})
    match_columns = ["timestamp", "src_ip", "dest_ip", "query", "user", "action", "matched_indicator", "indicator_type", "confidence_band", "priority_score"]
    with (out / "event_matches.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=match_columns); writer.writeheader(); writer.writerows(matches)
    band_counts = {band: sum(1 for row in indicators if row["confidence_band"] == band) for band in ("High", "Medium", "Low")}
    lines = ["# Threat Intelligence Analyst Summary", "", f"- Unique normalized indicators: **{len(indicators)}**", f"- Synthetic event matches: **{len(matches)}**", "", "## Confidence bands", "", "| Band | Indicators |", "|---|---:|"]
    lines.extend(f"| {band} | {band_counts[band]} |" for band in band_counts)
    lines += ["", "## Matched events", "", "| Time | Matched indicator | Type | Confidence | Event action |", "|---|---|---|---|---|"]
    for row in matches:
        lines.append(f"| {row['timestamp']} | {row['matched_indicator']} | {row['indicator_type']} | {row['confidence_band']} | {row['action']} |")
    lines += ["", "## Analyst notes", "", "All supplied indicators and events in this run are synthetic training fixtures. The score is based only on analyst-supplied confidence and the age of the last-seen value; it is not a reputation verdict or probability of compromise. Verify provenance, ATT&CK mapping, business context, false positives, and sharing restrictions before operational use.", ""]
    (out / "analyst_summary.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iocs", required=True, type=Path, help="IOC input CSV")
    parser.add_argument("--events", type=Path, help="Optional JSON Lines event file")
    parser.add_argument("--as-of", required=True, type=date.fromisoformat, help="Scoring date in YYYY-MM-DD format")
    parser.add_argument("--out", required=True, type=Path, help="Output directory")
    args = parser.parse_args()
    if not args.iocs.is_file():
        parser.error(f"IOC file does not exist: {args.iocs}")
    if args.events and not args.events.is_file():
        parser.error(f"Event file does not exist: {args.events}")
    with args.iocs.open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    indicators = enrich_rows(rows, args.as_of)
    matches = match_events(load_events(args.events), indicators)
    write_outputs(indicators, matches, args.out)
    print(f"Normalized {len(indicators)} unique indicators; matched {len(matches)} events.")
    print(f"Reports written to {args.out.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
