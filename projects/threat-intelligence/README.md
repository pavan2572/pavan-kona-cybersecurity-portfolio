# Threat Intelligence: IOC Enrichment & Detection

**Deliverable:** `threatintel.py` — an offline IOC normalization and enrichment pipeline that validates common indicator types, deduplicates records, scores confidence and freshness, maps ATT&CK technique context, and exports a Splunk lookup with summary reports.

## Capabilities

- Validates IPv4 addresses, domains, URLs, and MD5/SHA-1/SHA-256 hashes.
- Canonicalizes indicators and deduplicates repeated observations while retaining source context.
- Calculates transparent confidence/freshness scores using source-provided confidence and last-seen date.
- Preserves ATT&CK technique IDs and tags supplied by the analyst; does not infer attribution.
- Exports normalized IOC CSV, Splunk lookup CSV, and a Markdown analyst summary.
- Includes SPL detections and synthetic JSONL events for offline validation.

## Run the pipeline

Python 3.10+; no third-party packages or external API access required.

```bash
python src/threatintel.py \
  --iocs data/sample_iocs.csv \
  --events data/sample_events.jsonl \
  --as-of 2026-11-06 \
  --out reports/generated
```

Review `normalized_iocs.csv`, `threat_iocs.csv`, `event_matches.csv`, and `analyst_summary.md` in the output folder. Committed examples are available in [the sample analyst summary](reports/sample/analyst_summary.md) and [sample event matches](reports/sample/event_matches.csv).

## Data interpretation

- Confidence is supplied by the analyst/source in the input (0–100); the tool does not certify source reliability.
- Freshness points use `last_seen` relative to the explicit `--as-of` date: 0–7 days = 30, 8–30 = 20, 31–90 = 10, older/unknown = 0.
- `priority_score = min(100, source_confidence × 0.70 + freshness_points)`; the band is High ≥75, Medium ≥45, otherwise Low.
- Priority score is a sorting aid, not a probability of maliciousness.
- ATT&CK technique IDs are retained from the input and should be verified against the source report and current ATT&CK knowledge base.

The bundled values use reserved IP ranges, `.test` domains, and synthetic hashes. They are deliberately non-routable/non-production training values, not real indicators of compromise.

## Splunk detections

Import the generated `threat_iocs.csv` from your output directory as a lookup named `threat_iocs`. The example SPL files expect lab events in the `lab` index and use fields shown in `data/sample_events.jsonl`. Adapt index, sourcetype, field mapping, lookup permissions, and retention to your environment before deployment.

- `detections/splunk/dns_ioc_match.spl` matches DNS queries against domain IOCs.
- `detections/splunk/network_ip_ioc_match.spl` matches destination IPs against IPv4 IOCs.

These searches are starting points for a controlled lab. Add allowlisting, volume controls, asset context, and alert ownership before production use.

## Validation

```bash
python -m unittest discover -s projects -p 'test_*.py' -v
```

Tests cover parsing/validation, deduplication, confidence/freshness scoring, event matching, and output artifacts.

## Analyst workflow

1. Record the report/source, publication date, collection time, and source reliability.
2. Extract indicators with surrounding context and confidence; avoid copying context-free IOC lists.
3. Normalize, validate, deduplicate, and record first/last seen.
4. Enrich indicators with approved passive sources in an operational environment.
5. Map observed behavior to ATT&CK only where supported by evidence.
6. Convert useful indicators into a detection hypothesis and validate against safe/sanitized events.
7. Document false positives, expiry/decay, sharing constraints, and response actions.

## Limitations and safety

This is an offline portfolio pipeline, not an internet IOC reputation service. It makes no live reputation, malware, or actor-attribution claims. Never download or execute malware as part of this project. Validate indicators and context before blocking or escalating them.

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [AlienVault OTX](https://otx.alienvault.com/)
- [MalwareBazaar](https://bazaar.abuse.ch/)
