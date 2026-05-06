#!/usr/bin/env python3
"""Assert the demo CBOM contains the expected crypto findings."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from cbom import load_inventory


EXPECTED_FINDINGS: list[dict[str, Any]] = [
    {
        "source_type": "code",
        "language": "java",
        "api": "java.security.MessageDigest",
        "algorithm": "MD5",
        "risk_level": "HIGH",
        "risk_reason": "Broken hash",
    },
    {
        "source_type": "code",
        "language": "java",
        "api": "java.security.MessageDigest",
        "algorithm": "SHA-256",
        "risk_level": "LOW",
        "pqc_status": "SAFE",
    },
    {
        "source_type": "code",
        "language": "java",
        "api": "java.security.Signature",
        "algorithm": "SHA1withRSA",
        "risk_level": "HIGH",
        "pqc_status": "NOT_SAFE",
    },
    {"source_type": "code", "language": "java", "api": "javax.crypto.Cipher", "algorithm": "AES", "mode": "ECB"},
    {"source_type": "code", "language": "java", "api": "javax.crypto.Cipher", "algorithm": "AES", "mode": "GCM"},
    {
        "source_type": "code",
        "language": "java",
        "api": "java.security.KeyPairGenerator",
        "algorithm": "RSA",
        "key_size": 3072,
        "risk_level": "MEDIUM",
        "pqc_status": "NOT_SAFE",
        "harvest_now_decrypt_later_risk": True,
    },
    {"source_type": "code", "language": "java", "api": "javax.net.ssl.SSLContext", "protocol": "TLSv1.2"},
    {"source_type": "code", "language": "python", "api": "hashlib.md5", "algorithm": "MD5", "risk_level": "HIGH"},
    {"source_type": "code", "language": "python", "api": "hashlib.sha256", "algorithm": "SHA-256", "risk_level": "LOW"},
    {"source_type": "code", "language": "python", "api": "hashlib.new", "algorithm": "sha1", "risk_level": "HIGH"},
    {"source_type": "code", "language": "python", "api": "hmac.new", "algorithm": "sha256", "risk_level": "LOW"},
    {
        "source_type": "code",
        "language": "python",
        "api": "cryptography.rsa.generate_private_key",
        "algorithm": "RSA",
        "key_size": 3072,
        "pqc_status": "NOT_SAFE",
    },
    {"source_type": "code", "language": "python", "api": "ssl.SSLContext", "protocol": "TLSv1.2"},
    {"source_type": "code", "language": "python", "api": "requests.get", "risk_level": "HIGH"},
    {"source_type": "config", "api": "tls.config.protocol", "protocol": "TLSv1.2"},
    {"source_type": "config", "api": "tls.config.protocol", "protocol": "TLSv1.3"},
    {"source_type": "pcap", "api": "pcap.tls.protocol", "protocol": "TLSv1.2", "runtime_observed": True},
    {"source_type": "pcap", "api": "pcap.tls.certificate", "algorithm": "RSA", "key_size": 3072},
]


def matches(record: dict[str, Any], expected: dict[str, Any]) -> bool:
    return all(record.get(key) == value for key, value in expected.items())


def describe(expected: dict[str, Any]) -> str:
    return ", ".join(f"{key}={value!r}" for key, value in expected.items())


def assert_inventory(path: Path) -> list[str]:
    records = load_inventory(path)
    failures: list[str] = []

    critical = [record for record in records if record.get("risk_level") == "CRITICAL"]
    if critical:
        failures.append(f"Expected no CRITICAL findings, got {len(critical)}")

    for expected in EXPECTED_FINDINGS:
        if not any(matches(record, expected) for record in records):
            failures.append(f"Missing finding: {describe(expected)}")

    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=Path, help="Path to inventory.json")
    args = parser.parse_args(argv)

    failures = assert_inventory(args.inventory)
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1

    print(f"Inventory assertions passed for {args.inventory}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
