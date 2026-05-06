#!/usr/bin/env python3
"""Ingest TLS observations exported from PCAP tooling into CBOM JSON."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Iterable


def normalize_protocol(value: str | None) -> str | None:
    if not value:
        return None
    upper = str(value).upper()
    if upper in {"0X0301", "0X301", "TLS 1.0", "TLSV1"}:
        return "TLSv1.0"
    if upper in {"0X0302", "0X302", "TLS 1.1", "TLSV1.1"}:
        return "TLSv1.1"
    if upper in {"0X0303", "0X303", "TLS 1.2", "TLSV1.2"}:
        return "TLSv1.2"
    if upper in {"0X0304", "0X304", "TLS 1.3", "TLSV1.3"}:
        return "TLSv1.3"
    return str(value)


def protocol_risk(protocol: str | None) -> tuple[str, str]:
    if protocol in {"TLSv1.0", "TLSv1.1"}:
        return "HIGH", "Deprecated protocol"
    if protocol == "TLSv1.2":
        return "MEDIUM", "Legacy protocol"
    return "LOW", "Modern protocol"


def cipher_algorithm(cipher: str | None) -> tuple[str | None, str | None, str, str, str]:
    upper = (cipher or "").upper()
    if "RC4" in upper:
        return "RC4", None, "HIGH", "Deprecated cipher", "UNKNOWN"
    if "3DES" in upper or "DES" in upper and "ECDHE" not in upper:
        return "3DES" if "3DES" in upper else "DES", None, "HIGH", "Deprecated cipher", "UNKNOWN"
    if "RSA" in upper:
        return "RSA", None, "MEDIUM", "PQC vulnerable asymmetric crypto", "NOT_SAFE"
    if "ECDHE" in upper or "ECDSA" in upper:
        return "EC", None, "MEDIUM", "PQC vulnerable asymmetric crypto", "NOT_SAFE"
    if "AES" in upper and "GCM" in upper:
        return "AES", "GCM", "LOW", "Modern secure mode", "SAFE"
    return None, None, "LOW", "No known weak pattern", "UNKNOWN"


def load_json_records(path: Path) -> Iterable[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    if not text.strip():
        return []
    if path.suffix.lower() == ".jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    data = json.loads(text)
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("records"), list):
        return data["records"]
    return [data]


def load_csv_records(path: Path) -> Iterable[dict[str, Any]]:
    with path.open(newline="", encoding="utf-8", errors="ignore") as handle:
        return list(csv.DictReader(handle))


def iter_observations(paths: Iterable[Path]) -> Iterable[dict[str, Any]]:
    for path in paths:
        if not path.exists():
            continue
        if path.is_dir():
            yield from iter_observations(child for child in path.rglob("*") if child.is_file())
        elif path.suffix.lower() in {".json", ".jsonl"}:
            yield from load_json_records(path)
        elif path.suffix.lower() in {".csv", ".log", ".tsv"}:
            yield from load_csv_records(path)


def first(record: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if record.get(key) not in (None, ""):
            return record[key]
    return None


def make_records(record: dict[str, Any]) -> list[dict[str, object]]:
    source_file = str(first(record, "file", "pcap", "source") or "pcap").replace("\\", "/")
    frame = first(record, "frame", "frame_number", "number")
    line = int(frame) if str(frame or "").isdigit() else None
    protocol = normalize_protocol(first(record, "tls_version", "version", "tls.handshake.version"))
    cipher = first(record, "cipher", "cipher_suite", "tls.cipher")
    cert_alg = first(record, "cert_public_key_algorithm", "cert_algorithm", "x509_public_key_algorithm")
    cert_key_size = first(record, "cert_key_size", "key_size", "x509_key_size")
    sni = first(record, "sni", "server_name", "tls.handshake.extensions_server_name")

    evidence_parts = [part for part in [f"frame={frame}" if frame else None, f"sni={sni}" if sni else None, protocol, cipher] if part]
    evidence = " ".join(str(part) for part in evidence_parts)

    findings: list[dict[str, object]] = []
    if protocol:
        risk_level, risk_reason = protocol_risk(protocol)
        findings.append(
            {
                "file": source_file,
                "line": line,
                "api": "pcap.tls.protocol",
                "algorithm": None,
                "mode": None,
                "key_size": None,
                "protocol": protocol,
                "risk_level": risk_level,
                "risk_reason": risk_reason,
                "pqc_status": "UNKNOWN",
                "harvest_now_decrypt_later_risk": True,
                "source_type": "pcap",
                "language": None,
                "runtime_observed": True,
                "confidence": "HIGH",
                "evidence": evidence,
            }
        )

    algorithm, mode, risk_level, risk_reason, pqc_status = cipher_algorithm(str(cipher or ""))
    if cipher and algorithm:
        findings.append(
            {
                "file": source_file,
                "line": line,
                "api": "pcap.tls.cipher",
                "algorithm": algorithm,
                "mode": mode,
                "key_size": None,
                "protocol": protocol,
                "risk_level": risk_level,
                "risk_reason": risk_reason,
                "pqc_status": pqc_status,
                "harvest_now_decrypt_later_risk": pqc_status == "NOT_SAFE",
                "source_type": "pcap",
                "language": None,
                "runtime_observed": True,
                "confidence": "HIGH",
                "evidence": evidence,
            }
        )

    if cert_alg:
        alg = "RSA" if "RSA" in str(cert_alg).upper() else "EC" if "EC" in str(cert_alg).upper() else str(cert_alg)
        key_size = int(cert_key_size) if str(cert_key_size or "").isdigit() else None
        risk_level = "CRITICAL" if alg == "RSA" and key_size is not None and key_size < 2048 else "MEDIUM"
        risk_reason = "Weak key size" if risk_level == "CRITICAL" else "PQC vulnerable asymmetric crypto"
        findings.append(
            {
                "file": source_file,
                "line": line,
                "api": "pcap.tls.certificate",
                "algorithm": alg,
                "mode": None,
                "key_size": key_size,
                "protocol": protocol,
                "risk_level": risk_level,
                "risk_reason": risk_reason,
                "pqc_status": "NOT_SAFE" if alg in {"RSA", "EC"} else "UNKNOWN",
                "harvest_now_decrypt_later_risk": True,
                "source_type": "pcap",
                "language": None,
                "runtime_observed": True,
                "confidence": "HIGH",
                "evidence": evidence,
            }
        )

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, default=[Path("demo/pcap")])
    parser.add_argument("--output", type=Path, default=Path("inventory-pcap.json"))
    args = parser.parse_args()

    findings: list[dict[str, object]] = []
    for observation in iter_observations(args.paths):
        findings.extend(make_records(observation))

    args.output.write_text(json.dumps(findings, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(findings)} PCAP/runtime TLS findings to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
