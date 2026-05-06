#!/usr/bin/env python3
"""Scan text configuration files for TLS crypto inventory signals."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Iterable


CONFIG_SUFFIXES = {".conf", ".cnf", ".cfg", ".ini", ".properties", ".yaml", ".yml", ".toml"}
SKIP_DIRS = {".git", "build", "db-java", "db-python", "out", "__pycache__"}

TLS_PATTERN = re.compile(r"\b(?:SSLv2|SSLv3|TLSv1(?:\.0|\.1|\.2|\.3)?)\b", re.IGNORECASE)
CIPHER_PATTERN = re.compile(r"\b(?:RC4|3DES|DES|ECDHE-RSA|RSA|AES(?:128|256)?-GCM|TLS_AES_\d+_GCM_SHA\d+)\b", re.IGNORECASE)


def normalize_protocol(value: str) -> str:
    upper = value.upper()
    if upper == "TLSV1":
        return "TLSv1.0"
    if upper.startswith("TLSV"):
        return "TLSv" + value[4:]
    if upper.startswith("SSLV"):
        return "SSLv" + value[4:]
    return value


def protocol_risk(protocol: str) -> tuple[str, str]:
    upper = protocol.upper()
    if upper in {"SSLV2", "SSLV3"}:
        return "CRITICAL", "Obsolete protocol"
    if upper in {"TLSV1.0", "TLSV1.1"}:
        return "HIGH", "Deprecated protocol"
    if upper == "TLSV1.2":
        return "MEDIUM", "Legacy protocol"
    return "LOW", "Modern protocol"


def cipher_record_value(value: str) -> tuple[str | None, str | None, str, str, str, str]:
    upper = value.upper()
    if "RC4" in upper:
        return "RC4", None, "HIGH", "Deprecated cipher", "UNKNOWN", "HIGH"
    if "3DES" in upper or "DES" in upper and "ECDHE" not in upper:
        return "3DES" if "3DES" in upper else "DES", None, "HIGH", "Deprecated cipher", "UNKNOWN", "HIGH"
    if "ECDHE" in upper:
        return "EC", None, "MEDIUM", "PQC vulnerable asymmetric crypto", "NOT_SAFE", "MEDIUM"
    if "RSA" in upper:
        return "RSA", None, "MEDIUM", "PQC vulnerable asymmetric crypto", "NOT_SAFE", "MEDIUM"
    if "AES" in upper and "GCM" in upper:
        return "AES", "GCM", "LOW", "Modern secure mode", "SAFE", "HIGH"
    return value, None, "LOW", "No known weak pattern", "UNKNOWN", "LOW"


def iter_config_files(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        if not path.exists():
            continue
        if path.is_file() and path.suffix.lower() in CONFIG_SUFFIXES:
            yield path
        elif path.is_dir():
            for child in path.rglob("*"):
                if any(part in SKIP_DIRS for part in child.parts):
                    continue
                if child.is_file() and child.suffix.lower() in CONFIG_SUFFIXES:
                    yield child


def make_record(
    path: Path,
    line_number: int,
    api: str,
    algorithm: str | None,
    mode: str | None,
    protocol: str | None,
    risk_level: str,
    risk_reason: str,
    pqc_status: str,
    evidence: str,
    confidence: str = "HIGH",
) -> dict[str, object]:
    return {
        "file": str(path).replace("\\", "/"),
        "line": line_number,
        "api": api,
        "algorithm": algorithm,
        "mode": mode,
        "key_size": None,
        "protocol": protocol,
        "risk_level": risk_level,
        "risk_reason": risk_reason,
        "pqc_status": pqc_status,
        "harvest_now_decrypt_later_risk": protocol is not None or pqc_status == "NOT_SAFE",
        "source_type": "config",
        "language": None,
        "runtime_observed": False,
        "confidence": confidence,
        "evidence": evidence.strip(),
    }


def scan_file(path: Path) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return findings

    for index, line in enumerate(lines, start=1):
        for match in TLS_PATTERN.finditer(line):
            protocol = normalize_protocol(match.group(0))
            risk_level, risk_reason = protocol_risk(protocol)
            findings.append(
                make_record(
                    path,
                    index,
                    "tls.config.protocol",
                    None,
                    None,
                    protocol,
                    risk_level,
                    risk_reason,
                    "UNKNOWN",
                    line,
                )
            )

        for match in CIPHER_PATTERN.finditer(line):
            algorithm, mode, risk_level, risk_reason, pqc_status, confidence = cipher_record_value(match.group(0))
            findings.append(
                make_record(
                    path,
                    index,
                    "tls.config.cipher",
                    algorithm,
                    mode,
                    None,
                    risk_level,
                    risk_reason,
                    pqc_status,
                    line,
                    confidence,
                )
            )

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, default=[Path(".")])
    parser.add_argument("--output", type=Path, default=Path("inventory-config.json"))
    args = parser.parse_args()

    findings: list[dict[str, object]] = []
    for path in iter_config_files(args.paths):
        findings.extend(scan_file(path))

    args.output.write_text(json.dumps(findings, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(findings)} TLS config findings to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
