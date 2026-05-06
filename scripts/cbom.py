#!/usr/bin/env python3
"""Build and summarize a JSON cryptographic bill of materials."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse


FIELDS = [
    "file",
    "line",
    "api",
    "algorithm",
    "mode",
    "key_size",
    "protocol",
    "risk_level",
    "risk_reason",
    "pqc_status",
    "harvest_now_decrypt_later_risk",
]

RISK_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
PQC_ORDER = ["SAFE", "NOT_SAFE", "UNKNOWN"]


def load_json_or_json_lines(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return []

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        items = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                items.append(json.loads(line))
        return items


def find_tuples(decoded: Any) -> list[Any]:
    """Find CodeQL BQRS tuple rows in the common decoded JSON shapes."""
    if isinstance(decoded, dict):
        if isinstance(decoded.get("tuples"), list):
            return decoded["tuples"]
        if isinstance(decoded.get("#select"), dict):
            return find_tuples(decoded["#select"])
        if isinstance(decoded.get("select"), dict):
            return find_tuples(decoded["select"])
        if isinstance(decoded.get("rows"), list):
            return decoded["rows"]
        if isinstance(decoded.get("tuple"), list):
            return [decoded["tuple"]]
        for value in decoded.values():
            rows = find_tuples(value)
            if rows:
                return rows

    if isinstance(decoded, list):
        if all(isinstance(row, list) for row in decoded):
            return decoded
        rows: list[Any] = []
        for item in decoded:
            rows.extend(find_tuples(item))
        return rows

    return []


def scalar(value: Any) -> Any:
    if isinstance(value, dict):
        for key in ("value", "string", "label", "url", "uri"):
            if key in value:
                return scalar(value[key])
        if "sourceLocation" in value:
            return scalar(value["sourceLocation"])
    return value


def normalize_file(value: Any) -> str:
    text = "" if value is None else str(value)
    if text.startswith("file:"):
        parsed = urlparse(text)
        text = unquote(parsed.path)
    return text.replace("\\", "/")


def nullable_text(value: Any) -> str | None:
    text = "" if value is None else str(value)
    return text if text else None


def nullable_int(value: Any) -> int | None:
    if value in (None, "", -1, "-1"):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def boolean_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() == "true"


def row_to_record(row: Any) -> dict[str, Any]:
    if isinstance(row, dict):
        values = row.get("tuple") or row.get("values") or [row.get(field) for field in FIELDS]
    else:
        values = row

    values = [scalar(value) for value in values]
    if len(values) < len(FIELDS):
        raise ValueError(f"Expected at least {len(FIELDS)} columns, got {len(values)}: {values!r}")

    raw = dict(zip(FIELDS, values[: len(FIELDS)]))
    return {
        "file": normalize_file(raw["file"]),
        "line": nullable_int(raw["line"]),
        "api": nullable_text(raw["api"]),
        "algorithm": nullable_text(raw["algorithm"]),
        "mode": nullable_text(raw["mode"]),
        "key_size": nullable_int(raw["key_size"]),
        "protocol": nullable_text(raw["protocol"]),
        "risk_level": nullable_text(raw["risk_level"]) or "LOW",
        "risk_reason": nullable_text(raw["risk_reason"]) or "No known weak pattern",
        "pqc_status": nullable_text(raw["pqc_status"]) or "UNKNOWN",
        "harvest_now_decrypt_later_risk": boolean_value(raw["harvest_now_decrypt_later_risk"]),
    }


def load_inventory(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        data = data["findings"]
    if not isinstance(data, list):
        raise ValueError("inventory.json must contain a list of findings")
    return data


def write_inventory(records: list[dict[str, Any]], output: Path) -> None:
    output.write_text(json.dumps(records, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def pqc_readiness_score(records: list[dict[str, Any]]) -> int:
    if not records:
        return 100

    points = 0.0
    for record in records:
        status = str(record.get("pqc_status", "UNKNOWN")).upper()
        if status == "SAFE":
            points += 1.0
        elif status == "UNKNOWN":
            points += 0.5

    return round((points / len(records)) * 100)


def build_summary(records: list[dict[str, Any]]) -> str:
    risk_counts = Counter(str(record.get("risk_level", "LOW")).upper() for record in records)
    pqc_counts = Counter(str(record.get("pqc_status", "UNKNOWN")).upper() for record in records)
    hndl_count = sum(1 for record in records if record.get("harvest_now_decrypt_later_risk"))
    critical = [record for record in records if str(record.get("risk_level", "")).upper() == "CRITICAL"]

    lines = [
        "Cryptographic Inventory Summary",
        "================================",
        f"Total findings: {len(records)}",
        f"PQC readiness score: {pqc_readiness_score(records)}/100",
        "",
        "Risk levels:",
    ]
    lines.extend(f"- {level}: {risk_counts.get(level, 0)}" for level in RISK_ORDER)
    lines.extend(["", "PQC status:"])
    lines.extend(f"- {status}: {pqc_counts.get(status, 0)}" for status in PQC_ORDER)
    lines.extend(["", f"Harvest-now-decrypt-later findings: {hndl_count}"])

    if critical:
        lines.extend(["", "Critical findings:"])
        for record in critical:
            location = f"{record.get('file')}:{record.get('line')}"
            detail = record.get("algorithm") or record.get("protocol") or record.get("api")
            lines.append(f"- {location} {detail} - {record.get('risk_reason')}")

    return "\n".join(lines) + "\n"


def convert_bqrs(args: argparse.Namespace) -> int:
    decoded = load_json_or_json_lines(args.input)
    records = [row_to_record(row) for row in find_tuples(decoded)]
    write_inventory(records, args.output)

    if args.summary:
        args.summary.write_text(build_summary(records), encoding="utf-8")

    if args.fail_on_critical and any(record["risk_level"] == "CRITICAL" for record in records):
        return 1
    return 0


def summarize(args: argparse.Namespace) -> int:
    records = load_inventory(args.inventory)
    summary = build_summary(records)
    if args.summary:
        args.summary.write_text(summary, encoding="utf-8")
    else:
        print(summary, end="")

    if args.fail_on_critical and any(record["risk_level"] == "CRITICAL" for record in records):
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    convert = subparsers.add_parser("from-bqrs-json", help="Convert decoded CodeQL BQRS JSON to inventory.json")
    convert.add_argument("input", type=Path, help="Decoded CodeQL JSON from `codeql bqrs decode --format=json`")
    convert.add_argument("--output", type=Path, default=Path("inventory.json"))
    convert.add_argument("--summary", type=Path, default=Path("summary.txt"))
    convert.add_argument("--fail-on-critical", action="store_true")
    convert.set_defaults(func=convert_bqrs)

    summary = subparsers.add_parser("summarize", help="Generate summary.txt from inventory.json")
    summary.add_argument("inventory", type=Path)
    summary.add_argument("--summary", type=Path)
    summary.add_argument("--fail-on-critical", action="store_true")
    summary.set_defaults(func=summarize)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
